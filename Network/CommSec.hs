{-# LANGUAGE RecordWildCards, RankNTypes #-}
module Network.CommSec
    (
    -- * Types
      Connection(..)
    -- * Send and receive operations
    , send, recv
    , sendPtr, recvPtr
    -- * Establishing a connection from a shared secret
    , accept
    , connect
    -- * Establishing a connection from a public identity (PKI)
    -- , acceptId
    -- , connectId
    ) where

import Crypto.Classes (buildKey)
import Crypto.Cipher.AES128.Internal (encryptCTR)
import Crypto.Cipher.AES128 (AESKey)
import Network.CommSec.Package
import Network.Socket ( Socket, SocketType(..), SockAddr, AddrInfo(..)
                      , defaultHints , getAddrInfo, sendBuf, addrAddress
                      , recvBuf, HostName, PortNumber)
import qualified Network.Socket as Net
import Data.IORef
import Control.Concurrent.MVar
import Control.Exception (throw)
import Control.Monad
import qualified Data.ByteString as B
import qualified Data.ByteString.Unsafe as B
import qualified Data.ByteString.Internal as B
import Foreign.Ptr
import Foreign.Marshal.Alloc
import Data.Word
import Data.Maybe (listToMaybe)

-- | A connection is a secure bidirectional communication channel.
data Connection
            = Conn { inCtx        :: c InContext
                   , outCtx       :: c OutContext
                   , socket       :: Socket
                   }

pMVar :: MVar v -> v -> IO ()
pMVar m v = v `seq` putMVar m v

send :: Connection -> B.ByteString -> IO ()
send = sendWith takeMVar pMVar

recv :: Connection -> IO B.ByteString
recv = recvWith takeMVar pMVar

-- |Sends a message over the connection.
sendPtr :: Connection -> Ptr Word8 -> Int -> IO ()
sendPtr = sendPtrWith takeMVar pMVar

-- |Blocks till it receives a valid message, placing the resulting plaintext
-- in the provided buffer.  If the incoming message is larger that the
-- provided buffer then the message is truncated.  This process also incurs
-- an additional copy.
recvPtr :: Connection -> Ptr Word8 -> Int -> IO Int
recvPtr = recvPtrWith takeMVar pMVar

wIORef :: IORef v -> v -> IO ()
wIORef ref val = val `seq` writeIORef ref val

-- helper for send
sendWith :: (c OutContext -> IO OutContext) -> (c OutContext -> OutContext -> IO ()) -> Connection c -> B.ByteString -> IO ()
sendWith get put conn msg = B.useAsCStringLen msg $ \(ptPtr, ptLen) ->
  sendPtrWith get put conn (castPtr ptPtr) ptLen
{-# INLINE sendWith #-}

data RecvRes = Good | Small | Err deriving (Eq)

-- helper for recv
recvWith :: (c InContext -> IO InContext) -> (c InContext -> InContext -> IO ()) -> Connection c -> IO B.ByteString
recvWith get put conn@(Conn {..}) = allocGo baseSize
 where
    baseSize = 2048
    allocGo :: Int -> IO B.ByteString
    allocGo n = allocaBytes sizeTagLen (go n)

    --

    go :: Int -> Ptr Word8 -> IO B.ByteString
    go sz tmpPtr
      | sz > 2^28 = error "recvWith: A message is over 256MB! Probably corrupt data or the stream is unsyncronized."
      | otherwise = do
          recvBytesPtr socket tmpPtr sizeTagLen
          sz <- fromIntegral `fmap` peekBE32 tmpPtr
          (b, res) <- B.createAndTrim' sz $ \ptPtr -> do
            resSz <- recvPtrOfSz get put conn ptPtr sz
            case resSz of
                Left err -> if err `elem` retryOn then return (0,0,Err)
                                                  else throw err
                Right s  ->
                    if s > sz
                        then return (0,0,Small)
                        else return (0,s,Good)
          case res of
              Good   -> return b
              Small  -> go (sz * 2) tmpPtr
              Err    -> go sz tmpPtr
{-# INLINE recvWith #-}

retryOn :: [CommSecError]
retryOn = [DuplicateSeq, InvalidICV, BadPadding]

-- helper for sendPtr
sendPtrWith :: (c OutContext -> IO OutContext) -> (c OutContext -> OutContext -> IO ()) -> Connection c -> Ptr Word8 -> Int -> IO ()
sendPtrWith get put c@(Conn {..}) ptPtr ptLen = do
    let ctLen  = encBytes ptLen
        pktLen = sizeTagLen + ctLen
    allocaBytes pktLen $ \pktPtr -> do
        let ctPtr = pktPtr `plusPtr` sizeTagLen
        pokeBE32 pktPtr (fromIntegral ctLen)
        o  <- get outCtx
        o2 <- encodePtr o ptPtr ctPtr ptLen
        put outCtx o2
        sendBytesPtr socket pktPtr pktLen
        return ()

-- helper for recvPtr
recvPtrWith :: (c InContext -> IO InContext) -> (c InContext -> InContext -> IO ()) -> Connection c -> Ptr Word8 -> Int -> IO Int
recvPtrWith get put c@(Conn{..}) ptPtr maxLen = do
    r <- go
    case r of
        Nothing  -> recvPtrWith get put c ptPtr maxLen
        Just res -> return res
 where
  go :: IO (Maybe Int)
  go = allocaBytes sizeTagLen $ \szPtr -> do
    recvBytesPtr socket szPtr sizeTagLen
    len <- fromIntegral `fmap` peekBE32 szPtr
    let ptMaxSize = decBytes (len - sizeTagLen)
    allocaBytes len $ \ctPtr -> do
      recvBytesPtr socket ctPtr len
      i <- get inCtx
      let finish pointer = do
              dRes <- decodePtr i ctPtr pointer len
              case dRes of
                Left err -> if err `elem` retryOn then return Nothing
                                                  else throw err
                Right (resLen,i2) -> put inCtx i2 >> return (Just resLen)
      if ptMaxSize > maxLen
          then allocaBytes ptMaxSize (\tmp -> do
                        res <- finish tmp
                        B.memcpy ptPtr tmp maxLen
                        return res)
          else finish ptPtr

-- Receive sz bytes and decode it into ptPtr, helper for recvWith
recvPtrOfSz :: (c InContext -> IO InContext) -> (c InContext -> InContext -> IO ()) -> Connection c -> Ptr Word8 -> Int -> IO (Either CommSecError Int)
recvPtrOfSz get put (Conn {..}) ptPtr sz =
    allocaBytes sz $ \ct -> do
        recvBytesPtr socket ct sz
        i <- get inCtx
        dRes <- decodePtr i ct ptPtr sz
        case dRes of
                Left err -> return (Left err)
                Right (resLen,i2) -> put inCtx i2 >> return (Right resLen)

-- Retry until we have received exactly the specified number of bytes
recvBytesPtr :: Socket -> Ptr Word8 -> Int -> IO ()
recvBytesPtr s p 0 = return ()
recvBytesPtr s p l = do
        nr <- recvBuf s l p
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
                   encryptCTR k (castPtr iv) (castPtr ctPtr) (castPtr ptPtr) sz

-- |Expands the provided 128 (or more) bit secret into two
-- keys to create a connection.
--
-- ex: accept ent 3134
accept  :: B.ByteString -> PortNumber -> IO Connection
accept = doAccept newMVar

doAccept  :: (forall x. x -> IO (c x)) -> B.ByteString -> PortNumber -> IO (Connection c)
doAccept create s p
  | B.length s < 16 = error "Invalid input entropy"
  | otherwise = do
    let ent   = expandSecret s 64
        k1    = B.take 32 ent
        k2    = B.drop 32 ent
        iCtx  = newInContext k1
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

doConnect  :: (forall x. x -> IO (c x)) -> B.ByteString -> HostName -> PortNumber -> IO (Connection c)
doConnect create s hn p
  | B.length s < 16 = error "Invalid input entropy"
  | otherwise = do
    sockaddr <- resolve hn p
    let ent  = expandSecret s 64
        k2   = B.take 32 ent
        k1   = B.drop 32 ent
        iCtx = newInContext k1
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

-- |We use a word32 to indicate the size of a datagram
sizeTagLen :: Int
sizeTagLen = 4
