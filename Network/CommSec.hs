{-# LANGUAGE RecordWildCards, RankNTypes #-}
module Network.CommSec
    (
    -- * Types
      Connection(..)
    , CommSecError(..)
    -- * Send and receive operations
    , send, recv
    , sendPtr, recvPtr
    -- * Establishing a connection from a shared secret
    , accept
    , connect
    , close
    -- * Establishing a connection from a public identity (PKI)
    -- , acceptId
    -- , connectId
    -- * Utility
    , expandSecret
    ) where

import Crypto.Classes (buildKey)
import Crypto.Cipher.AES128.Internal (encryptCTR)
import Crypto.Cipher.AES128 (AESKey)
import Network.CommSec.Package
import Network.CommSec.Types
import Network.Socket ( Socket, SocketType(..), SockAddr, AddrInfo(..)
                      , defaultHints , getAddrInfo, sendBuf, addrAddress
                      , recvBuf, HostName, PortNumber)
import qualified Network.Socket as Net
import Control.Concurrent.MVar
import Control.Exception (throw)
import Control.Monad
import qualified Data.ByteString as B
import qualified Data.ByteString.Unsafe as B
import qualified Data.ByteString.Internal as B
import Foreign.Ptr
import Foreign.Marshal.Alloc
import Data.Word
import Data.Maybe (isJust, listToMaybe)

-- | A connection is a secure bidirectional communication channel.
data Connection
            = Conn { inCtx        :: MVar InContext
                   , outCtx       :: MVar OutContext
                   , socket       :: Socket
                   }

pMVar :: MVar v -> v -> IO ()
pMVar m v = v `seq` putMVar m v

-- |Send a datagram, first encrypting it, using the given secure
-- connection.
send :: Connection -> B.ByteString -> IO ()
send conn msg = B.useAsCStringLen msg $ \(ptPtr, ptLen) ->
  sendPtr conn (castPtr ptPtr) ptLen

data RecvRes = Good | Err deriving (Eq)

recv :: Connection -> IO B.ByteString
recv conn@(Conn {..}) =
  allocaBytes sizeTagLen $ \tmpPtr ->
  modifyMVar inCtx       $ \iCtx   ->
  go tmpPtr iCtx

  where

  go :: Ptr Word8 -> InContext -> IO (InContext, B.ByteString)
  go tmpPtr iCtx = do
    recvBytesPtr socket tmpPtr sizeTagLen -- XXX This is unacceptable for datagrams
    sz <- fromIntegral `fmap` peekBE32 tmpPtr
    when (sz > 2^28)
      (fail "recv: A message is over 256MB! Probably corrupt data or the stream is unsyncronized.")
    (b, (iCtx,res)) <- B.createAndTrim' sz $ \ptPtr -> -- second time iCtx shadowed
        do (iCtx,resSz) <- recvPtrOfSz socket iCtx ptPtr sz -- first time iCtx shadowed
           case resSz of
             Left err
               | err `elem` retryOn -> return (0,0,(iCtx,Err))
               | otherwise          -> throw err
             Right s                -> return (0,s,(iCtx,Good))
    case res of
            Good   -> return (iCtx,b)
            Err    -> go tmpPtr iCtx

retryOn :: [CommSecError]
retryOn = [DuplicateSeq, InvalidICV, BadPadding]

-- |Sends a message over the connection.
sendPtr :: Connection -> Ptr Word8 -> Int -> IO ()
sendPtr c@(Conn {..}) ptPtr ptLen = do
    let ctLen  = encBytes ptLen
        pktLen = sizeTagLen + ctLen
    allocaBytes pktLen $ \pktPtr -> do
        let ctPtr = pktPtr `plusPtr` sizeTagLen
        pokeBE32 pktPtr (fromIntegral ctLen)
        modifyMVar_ outCtx $ \oCtx -> encodePtr oCtx ptPtr ctPtr ptLen
        sendBytesPtr socket pktPtr pktLen

-- |Blocks till it receives a valid message, placing the resulting plaintext
-- in the provided buffer.  If the incoming message is larger that the
-- provided buffer then the message is truncated.  This process also incurs
-- an additional copy.
recvPtr :: Connection -> Ptr Word8 -> Int -> IO Int
recvPtr c@(Conn{..}) ptPtr maxLen =
  allocaBytes sizeTagLen $ \szPtr ->
  modifyMVar inCtx       $ \iCtx -> do
  go szPtr iCtx

  where

  go szPtr iCtx = do
    recvBytesPtr socket szPtr sizeTagLen
    len <- fromIntegral `fmap` peekBE32 szPtr
    let ptMaxSize = decBytes (len - sizeTagLen)
    (iCtx, mbOutLen) <- allocaBytes len $ \ctPtr -> do -- shadow iCtx
      recvBytesPtr socket ctPtr len
      let finish pointer = do
              dRes <- decodePtr iCtx ctPtr pointer len
              case dRes of
                Left err
                  | err `elem` retryOn -> return (iCtx, Nothing) -- preserve old context
                  | otherwise          -> throw err
                Right (resLen,i2) -> return (i2, Just resLen)
      if ptMaxSize > maxLen -- shadow iCtx
        then allocaBytes ptMaxSize $ \tmp ->
               do res <- finish tmp
                  when (isJust (snd res)) -- don't bother copying in the retry case
                       (B.memcpy ptPtr tmp maxLen)
                  return res
        else finish ptPtr
    case mbOutLen of
      Nothing     -> go szPtr iCtx -- retry
      Just outLen -> return (iCtx, outLen)

-- Receive sz bytes and decode it into ptPtr, helper for recvWith
recvPtrOfSz :: Socket -> InContext -> Ptr Word8 -> Int -> IO (InContext, Either CommSecError Int)
recvPtrOfSz socket iCtx ptPtr sz =
    allocaBytes sz $ \ct -> do
        recvBytesPtr socket ct sz
        dRes <- decodePtr iCtx ct ptPtr sz
        return $ case dRes of
          Left err          -> (iCtx, Left err) -- restore old context
          Right (resLen,i2) -> (i2  , Right resLen)

-- Retry until we have received exactly the specified number of bytes
recvBytesPtr :: Socket -> Ptr Word8 -> Int -> IO ()
recvBytesPtr s p 0 = return ()
recvBytesPtr s p l = do
        nr <- recvBuf s p l
        recvBytesPtr s (p `plusPtr` nr) (l - nr)

-- Retry until we have sent exactly the specified number of bytes
sendBytesPtr :: Socket -> Ptr Word8 -> Int -> IO ()
sendBytesPtr s p 0 = return ()
sendBytesPtr s p l = do
        nr <- sendBuf s p l
        sendBytesPtr s (p `plusPtr` nr) (l - nr)

-- Use counter mode to expand input entropy that is at least 16 bytes long
expandSecret :: B.ByteString -> Int -> B.ByteString
expandSecret entropy sz =
    let k = buildKey entropy
    in case k of
           Nothing  -> error "Build key failed"
           Just key ->
              let iv = B.replicate 16 0
              in enc key iv input
 where
  input = B.replicate sz 0
  enc :: AESKey -> B.ByteString -> B.ByteString -> B.ByteString
  enc k i pt = B.unsafeCreate sz $ \ctPtr ->
                B.useAsCString pt $ \ptPtr ->
                 B.useAsCString i $ \iv ->
                   encryptCTR k (castPtr iv) nullPtr (castPtr ctPtr) (castPtr ptPtr) sz

-- |Expands the provided 128 (or more) bit secret into two
-- keys to create a connection.
--
-- ex: accept ent 3134
accept  :: B.ByteString -> PortNumber -> IO Connection
accept = doAccept newMVar

doAccept  :: (forall x. x -> IO (MVar x)) -> B.ByteString -> PortNumber -> IO Connection
doAccept create s p
  | B.length s < 16 = error "Invalid input entropy"
  | otherwise = do
    let ent   = expandSecret s 64
        k1    = B.take 32 ent
        k2    = B.drop 32 ent
        iCtx  = newInContext k1 Sequential
        oCtx  = newOutContext k2
        sockaddr = Net.SockAddrInet p Net.iNADDR_ANY
    sock <- Net.socket Net.AF_INET Net.Stream Net.defaultProtocol
    Net.setSocketOption sock Net.ReuseAddr 1
    Net.bind sock sockaddr
    Net.listen sock 10
    socket <- fst `fmap` Net.accept sock
    Net.setSocketOption socket Net.NoDelay 1
    Net.close sock
    inCtx  <- create iCtx
    outCtx <- create oCtx
    return (Conn {..})

doConnect  :: (forall x. x -> IO (MVar x)) -> B.ByteString -> HostName -> PortNumber -> IO Connection
doConnect create s hn p
  | B.length s < 16 = error "Invalid input entropy"
  | otherwise = do
    sockaddr <- resolve hn p
    let ent  = expandSecret s 64
        k2   = B.take 32 ent
        k1   = B.drop 32 ent
        iCtx = newInContext k1 Sequential
        oCtx = newOutContext k2
    socket <- Net.socket Net.AF_INET Net.Stream Net.defaultProtocol
    Net.connect socket sockaddr
    Net.setSocketOption socket Net.NoDelay 1
    Net.setSocketOption socket Net.ReuseAddr 1
    inCtx  <- create iCtx
    outCtx <- create oCtx
    return (Conn {..})
  where
      resolve :: HostName -> PortNumber -> IO SockAddr
      resolve h port = do
        ai <- getAddrInfo (Just $ defaultHints { addrFamily = Net.AF_INET, addrSocketType = Stream } ) (Just h) (Just (show port))
        return (maybe (error $ "Could not resolve host " ++ h) addrAddress (listToMaybe ai))

-- |Expands the provided 128 (or more) bit secret into two
-- keys to create a connection.
connect :: B.ByteString
        -> HostName
        -> PortNumber
        -> IO Connection
connect = doConnect newMVar

-- |Close a connection
close :: Connection -> IO ()
close c = Net.close (socket c)

-- |We use a word32 to indicate the size of a datagram
sizeTagLen :: Int
sizeTagLen = 4
