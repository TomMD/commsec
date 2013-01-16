{-# LANGUAGE CPP, BangPatterns, RecordWildCards, DeriveDataTypeable #-}
-- | CommSec is a package that provides communication security for
-- a datagram (vs streaming) style of communications.  Using an ephemeral shared
-- secret you can build contexts for sending to or receiving from with one or more
-- peers.
--
-- Do not reuse the shared secret!  Key agreement mechanisms that leverage
-- PKI might be added later.
module Network.CommSec.Package
    ( -- * Types
      OutContext(..)
    , InContext(..)
    , CommSecError(..)
    -- , Secret, Socket
      -- * Build contexts for use sending and receiving
    , newInContext, newOutContext -- , newSecret
      -- * Pure / ByteString based encryption and decryption routines
    , decode
    , encode
     -- * IO / Pointer based encryption and decryption routines
    , decodePtr
    , encodePtr
    -- * Utility functions
    , encBytes, decBytes
     -- * Wrappers for network sending and receiving
    -- , send, recv
    -- , sendPtr, recvPtr
    -- , connect, unsafeConnect
    -- , listen, unsafeListen
    -- * Utilities
    , peekBE32
    , pokeBE32
    , peekBE
    , pokeBE
    ) where

import Prelude hiding (seq)
import qualified Crypto.Cipher.AES128.Internal as AES
import Crypto.Cipher.AES128.Internal (AESKey)
import Crypto.Cipher.AES128 ()
import qualified Data.ByteString.Internal as B
import qualified Data.ByteString as B
import qualified Data.ByteString.Unsafe as B
import Crypto.Classes (buildKey)
import Data.ByteString (ByteString)
import Data.Bits
import Data.Maybe (fromMaybe)
import Data.Word
import Data.List
import Foreign.Ptr
import Foreign.ForeignPtr
import Foreign.Storable
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Marshal.Utils (copyBytes)
import System.IO.Unsafe
import Data.Data
import Data.Typeable
import Control.Exception

gPadMax,gBlockLen,gTagLen,gCtrSize :: Int
gPadMax   = 16
gBlockLen = 16
gTagLen   = 16
gCtrSize  = 8

-- IPSec inspired packet format:
--
--      [CNT (used for both the IV and seq) | CT of Payload + Pad | ICV]

-- | A context useful for sending data.
data OutContext =
    Out { aesCtr     :: {-# UNPACK #-} !Word64
        , saltOut    :: {-# UNPACK #-} !Word32
        , outKey     :: AESKey
        }

-- | A context useful for receiving data.
data InContext =
    In  { base      :: {-# UNPACK #-} !Word64
        , mask      :: {-# UNPACK #-} !Word64
        , saltIn    :: {-# UNPACK #-} !Word32
        , inKey     :: AESKey
        }

-- |Errors that can be returned by the decoding/receicing operations.
data CommSecError
        = OldContext    -- The context is too old (sequence number rollover)
        | DuplicateSeq  -- The sequence number we previously seen (possible replay attack)
        | InvalidICV    -- The integrity check value is invalid
        | BadPadding    -- The padding was invalid (corrupt sender?)
    deriving (Eq,Ord,Show,Enum,Data,Typeable)

instance Exception CommSecError

-- | Given at least 24 bytes of entropy, produce an out context that can
-- communicate with an identically initialized in context.
newOutContext :: ByteString -> OutContext
newOutContext bs
    | B.length bs < 24 = error $ "Not enough entropy: " ++ show (B.length bs)
    | otherwise =
        let aesCtr  = 0
            saltOut = unsafePerformIO $ B.unsafeUseAsCString bs $ peekBE32 . castPtr
            outKey  = fromMaybe (error "Could not build a key") $ buildKey $ B.drop (sizeOf saltOut) bs
        in Out {..}

-- | Given at least 24 bytes of entropy, produce an in context that can
-- communicate with an identically initialized out context.
newInContext  :: ByteString -> InContext
newInContext bs
    | B.length bs < 24 = error $ "Not enough entropy: " ++ show (B.length bs)
    | otherwise =
        let base   = 0
            mask   = 0
            saltIn = unsafePerformIO $ B.unsafeUseAsCString bs $ peekBE32 . castPtr
            inKey  = fromMaybe (error "Could not build a key") $ buildKey $ B.drop (sizeOf saltIn) bs
        in In {..}

-- Encrypts multiple-of-block-sized input, returing a bytestring of the
-- [ctr, ct, tag].
encryptGCM :: AESKey
           -> Word64 -- ^ AES GCM Counter (IV)
           -> Word32 -- ^ Salt
           -> ByteString -- ^ Plaintext
           -> ByteString
encryptGCM key ctr salt pt = unsafePerformIO $ do
    let ivLen  = sizeOf ctr + sizeOf salt
        tagLen = gTagLen
        paddedLen = B.length pt
    allocaBytes ivLen $ \ptrIV -> do
      -- Build the IV
      pokeBE32 ptrIV salt
      pokeBE (ptrIV `plusPtr` sizeOf salt) ctr
      B.unsafeUseAsCString pt $ \ptrPT -> do
        B.create (paddedLen + sizeOf ctr + tagLen) $ \ctPtr -> do
        pokeBE ctPtr ctr
        let tagPtr = ctPtr' `plusPtr` paddedLen
            ctPtr' = ctPtr `plusPtr` sizeOf ctr
        AES.encryptGCM key ptrIV ivLen nullPtr 0 (castPtr ptrPT) (B.length pt) (castPtr ctPtr') tagPtr


-- Encrypts multiple-of-block-sized input, filling a pointer with the
-- result of [ctr, ct, tag].
encryptGCMPtr :: AESKey
           -> Word64 -- ^ AES GCM Counter (IV)
           -> Word32 -- ^ Salt
           -> Ptr Word8 -- ^ Plaintext buffer
           -> Int       -- ^ Plaintext length
           -> Ptr Word8 -- ^ ciphertext buffer (at least encBytes large)
           -> IO ()
encryptGCMPtr key ctr salt ptPtr ptLen ctPtr = do
    let ivLen  = sizeOf ctr + sizeOf salt
        tagLen = gTagLen
        paddedLen = ptLen
    allocaBytes ivLen $ \ptrIV -> do
      -- Build the IV
      pokeBE32 ptrIV salt
      pokeBE (ptrIV `plusPtr` sizeOf salt) ctr
      pokeBE ctPtr ctr
      let tagPtr = ctPtr' `plusPtr` paddedLen
          ctPtr' = ctPtr `plusPtr` sizeOf ctr
      AES.encryptGCM key ptrIV ivLen nullPtr 0 (castPtr ptPtr) ptLen (castPtr ctPtr') tagPtr

-- | GCM decrypt and verify ICV.
decryptGCMPtr :: AESKey
              -> Word64 -- ^ AES GCM Counter (IV)
              -> Word32 -- ^ Salt
              -> Ptr Word8 -- ^ Ciphertext
              -> Int       -- ^ Ciphertext length
              -> Ptr Word8 -- ^ Tag
              -> Int       -- ^ Tag length
              -> Ptr Word8 -- ^ Plaintext result ptr (at least 'decBytes' large)
              -> IO (Either CommSecError ())
decryptGCMPtr key ctr salt ctPtr ctLen tagPtr tagLen ptPtr
  | tagLen /= gTagLen = return $ Left InvalidICV
  | otherwise = do
    let ivLen     = sizeOf ctr + sizeOf salt
        paddedLen = ctLen
    allocaBytes ivLen $ \ptrIV -> allocaBytes tagLen $ \ctagPtr -> do
      -- Build the IV
      pokeBE32 ptrIV salt
      pokeBE (ptrIV `plusPtr` sizeOf salt) ctr
      AES.decryptGCM key ptrIV ivLen nullPtr 0 (castPtr ctPtr) paddedLen (castPtr ptPtr) ctagPtr
      w1 <- peekBE ctagPtr
      w2 <- peekBE (ctagPtr `plusPtr` sizeOf w1)
      y1 <- peekBE (castPtr tagPtr)
      y2 <- peekBE (castPtr tagPtr `plusPtr` sizeOf y1)
      if (w1 /= y1 || w2 /= y2)
            then return (Left InvalidICV)
            else return (Right ())

-- Decrypts multiple-of-block-sized input, returing a bytestring of the
-- [ctr, ct, tag].
decryptGCM :: AESKey
           -> Word64 -- ^ AES GCM Counter (IV)
           -> Word32 -- ^ Salt
           -> ByteString -- ^ Ciphertext
           -> ByteString -- ^ Tag
           -> Either CommSecError ByteString -- Plaintext (or an exception due to bad tag)
decryptGCM key ctr salt ct tag
  | B.length tag < gTagLen = Left InvalidICV
  | otherwise = unsafePerformIO $ do
    let ivLen  = sizeOf ctr + sizeOf salt
        tagLen = gTagLen
        paddedLen = B.length ct
    allocaBytes ivLen $ \ptrIV -> allocaBytes tagLen $ \ctagPtr -> do
      -- Build the IV
      pokeBE32 ptrIV salt
      pokeBE (ptrIV `plusPtr` sizeOf salt) ctr
      B.unsafeUseAsCString tag $ \tagPtr -> do
       B.unsafeUseAsCString ct $ \ptrCT -> do
        pt <- B.create paddedLen $ \ptrPT -> do
                     AES.decryptGCM key ptrIV ivLen nullPtr 0 (castPtr ptrCT) (B.length ct) (castPtr ptrPT) ctagPtr
        w1 <- peekBE ctagPtr
        w2 <- peekBE (ctagPtr `plusPtr` sizeOf w1)
        y1 <- peekBE (castPtr tagPtr)
        y2 <- peekBE (castPtr tagPtr `plusPtr` sizeOf y1)
        if (w1 /= y1 || w2 /= y2)
            then return (Left InvalidICV)
            else return (Right pt)

-- |Use an 'OutContext' to protect a message for transport.
-- Message format: [ctr, ct, padding, tag].
--
-- This routine can throw an exception of 'OldContext' if the context being
-- used has expired.
encode :: OutContext -> ByteString -> (ByteString, OutContext)
encode ctx@(Out {..}) pt 
  | aesCtr == maxBound = throw OldContext
  | otherwise =
    let !iv_ct_tag = encryptGCM outKey aesCtr saltOut (pad pt)
    in (iv_ct_tag, ctx { aesCtr = 1 + aesCtr })

-- |Given a message length, returns the number of bytes an encoded message
-- will consume.
encBytes :: Int -> Int
encBytes lenMsg =
     let lenBlock = gBlockLen
         tagLen = lenBlock
         ctrLen = gCtrSize
         r = lenBlock - (lenMsg `rem` lenBlock)
         pdLen = if r == 0 then lenBlock else r
    in ctrLen + lenMsg + pdLen + tagLen

-- |Given a package length, returns the maximum number of bytes the
-- underlying message could be (including padding).
decBytes :: Int -> Int
decBytes lenPkg =
    let tagLen = gTagLen
        ctrLen = gCtrSize
    in lenPkg - tagLen - ctrLen

-- |@encodePtr outCtx msg result msgLen@ will encode @msgLen@ bytes at
-- location @msg@, placing the result at location @result@.  The buffer
-- pointed to by @result@ must be at least @encBytes msgLen@ bytes large,
-- the actual package will be exactly @encBytes msgLen@ in size.
encodePtr :: OutContext -> Ptr Word8 -> Ptr Word8 -> Int -> IO OutContext
encodePtr ctx@(Out {..}) ptPtr pkgPtr ptLen
  | aesCtr == maxBound = throw OldContext
  | otherwise = do
    let !totalLen = padding + ptLen
        !padding  = padLen ptLen
    allocaBytes totalLen $ \ptPaddedPtr -> do
      copyBytes ptPaddedPtr ptPtr ptLen
      memset (ptPaddedPtr `plusPtr` ptLen) padding (fromIntegral padding)
      encryptGCMPtr outKey aesCtr saltOut ptPaddedPtr totalLen pkgPtr
      return (ctx { aesCtr = 1 + aesCtr })
  where
    memset :: Ptr Word8 -> Int -> Word8 -> IO ()
    memset ptr1 len val = mapM_ (\o -> pokeElemOff ptr1 o val) [0..len-1]

-- |@decodePtr inCtx pkg msg pkgLen@ decrypts and verifies a package at
-- location @pkg@ of size @pkgLen@.  The resulting message is placed at
-- location @msg@ and its size is returned along with a new context (or
-- error).
decodePtr :: InContext -> Ptr Word8 -> Ptr Word8 -> Int -> IO (Either CommSecError (Int,InContext))
decodePtr (In {..}) pkgPtr msgPtr pkgLen
  | base >= maxBound - 64 = return $ Left OldContext
  | otherwise = do
    cnt <- peekBE pkgPtr
    let !ctPtr  = pkgPtr `plusPtr` sizeOf cnt
        !ctLen  = pkgLen - tagLen - sizeOf cnt
        !tagPtr = pkgPtr `plusPtr` (pkgLen - tagLen)
        tagLen  = gTagLen
        paddedLen = ctLen
    r <- decryptGCMPtr inKey cnt saltIn ctPtr ctLen tagPtr tagLen msgPtr
    case r of
        Left err  -> return (Left err)
        Right  () -> do
            case updateBaseMask base mask cnt of
                Nothing -> return (Left DuplicateSeq)
                Just (base',mask') -> do
                    pdLen <- padLenPtr msgPtr paddedLen
                    case pdLen of
                        Nothing -> return $ Left BadPadding
                        Just l  -> return $ Right (paddedLen - l, In base' mask' saltIn inKey)

-- |Use an 'InContext' to decrypt a message, verifying the ICV and sequence
-- number.  Unlike sending, receiving is more likely to result in an
-- exceptional condition and thus it returns an 'Either' value.
--
-- Message format: [ctr, ct, padding, tag].
decode :: InContext -> ByteString -> Either CommSecError (ByteString, InContext)
decode (In {..}) pkg
  | base >= maxBound - 64 = Left OldContext
  | otherwise =
    let cnt    = unsafePerformIO $ B.unsafeUseAsCString pkg (peekBE . castPtr)
        cntLen = sizeOf cnt
        tagLen = gTagLen
        tag    = B.drop (B.length pkg - tagLen) pkg
        ct     = let st = (B.drop cntLen pkg) in B.take (B.length st - tagLen) st
        ptpd   = decryptGCM inKey cnt saltIn ct tag
    in case updateBaseMask base mask cnt of
              Nothing -> Left DuplicateSeq
              Just (base',mask') ->
                  case ptpd of
                      Left err    -> Left err
                      Right ptPad ->
                        case unpad ptPad of
                            Nothing -> Left BadPadding
                            Just pt -> Right (pt, In base' mask' saltIn inKey)

-- |Pad a bytestring to block size
pad :: ByteString -> ByteString
pad bs =
        let pd = B.replicate pdLen pdValue
            pdLen = padLen (B.length bs)
            pdValue = fromIntegral pdLen
        in B.concat [bs,pd]

-- |Given length of a plaintext message, return the length of the padding
-- needed.
padLen :: Int -> Int
padLen ptLen =
    let blkLen = gBlockLen
        r      = blkLen - (ptLen `rem` blkLen)
    in if r == 0 then blkLen else r
{-# INLINE padLen #-}

-- |Remove padding from a padded bytestring.  This is a varient of PCKS5 padding that does not check the pad values.
unpad :: ByteString -> Maybe ByteString
unpad bs
    | len > 0 = Just $ B.take (len - fromIntegral (B.last bs)) bs
    | otherwise = Nothing
  where
      len = B.length bs

-- |Given a pointer to padded data and the length of the data, determine the length of the padding.
-- Perhaps this should be called 'unpadPtr'
padLenPtr :: Ptr Word8 -> Int -> IO (Maybe Int)
padLenPtr ptr len
    | len <= gPadMax = return Nothing
    | otherwise = do
        r <- fromIntegral `fmap` (peekElemOff ptr (len-1) :: IO Word8)
        if r <= gPadMax then return (Just r) else return Nothing

updateBaseMask :: Word64 -> Word64 -> Word64 -> Maybe (Word64,Word64)
updateBaseMask !base !mask !seq
  | base <= seq && base >= seqBase =
      let pos = fromIntegral $ seq - base
      in if testBit mask pos
          then Nothing
          else Just (base, setBit mask pos)
#ifdef SEQ_WINDOW_JUMPS
  -- If all packets are received iun order, you will hit this case on every
  -- 64th packet and perform a single shiftR operation.  If packets are
  -- received out of order then this method is more likely to incorrectly
  -- mark packets as duplicate.
  | base < seqBase = updateBaseMask seq (mask `shiftR` fromIntegral (seq - base)) seq
#else
  -- If all packets are received in order, you will theoretically hit this
  -- case on every 64th packet, perform 64 shiftRight operations (due to lack of
  -- a msnzb operation), and
  -- proceed with the next 63 packets incurring only a bitSet operation.
  | base < seqBase =
      let newBase = seqBase
          newMask = mask `shiftR` fromIntegral (seqBase - base)
          shiftIt !b !m
            | testBit m 0 = shiftIt (b+1) (shiftR m 1)
            | otherwise   = (b,m)
          (finalBase, finalMask) = shiftIt newBase newMask
      in updateBaseMask finalBase finalMask seq
#endif
  | base > seq     = Nothing
  where
   !seqBase | seq < 64  = 0
            | otherwise = seq-63
{-# INLINE updateBaseMask #-}


peekBE :: Ptr Word8 -> IO Word64
peekBE p = do
    let op n = fromIntegral `fmap` peekElemOff p n
    as <- mapM op [0..7]
    return (foldl1' (\r a -> (r `shiftL` 8) .|. a) as)
{-# INLINE peekBE #-}

pokeBE :: Ptr Word8 -> Word64 -> IO ()
pokeBE p w = do
    let op n = pokeElemOff p n (fromIntegral (w `shiftR` (56-(8*n) :: Int)))
    mapM_ op [0..7]
{-# INLINE pokeBE #-}

pokeBE32 :: Ptr Word8 -> Word32 -> IO ()
pokeBE32 p w = do
    let op n = pokeElemOff p n (fromIntegral (w `shiftR` (24 - (8*n) :: Int)))
    mapM_ op [0..3]
{-# INLINE pokeBE32 #-}

peekBE32 :: Ptr Word8 -> IO Word32
peekBE32 p = do
    let op n = fromIntegral `fmap` peekElemOff p n
    as <- mapM op [0..3]
    return (foldl1' (\r a -> (r `shiftL` 8) .|. a) as)
{-# INLINE peekBE32 #-}
