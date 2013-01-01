{-# LANGUAGE BangPatterns, RecordWildCards #-}
-- | CommSec, for communications security.
module Network.CommSec
    ( -- * Types
      OutContext(..)
    , InContext(..)
      -- * Build contexts for use sending and receiving
    , newInContext, newOutContext
      -- Encryption and decryption routines
    , recv
    , send
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
import System.IO.Unsafe

-- IPSec inspired packet format:
--
--      [CNT (IV and seq) | Payload | Pad | ICV]

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

-- | Given at least 24 bytes of entropy, produce an out context that can
-- communicate with an identically initialized in context.
newOutContext :: ByteString -> OutContext
newOutContext bs
    | B.length bs < 24 = error "Not enough entropy"
    | otherwise =
        let aesCtr  = 0
            saltOut = unsafePerformIO $ B.unsafeUseAsCString bs $ peekBE32 . castPtr
            outKey  = fromMaybe (error "Could not build a key") $ buildKey $ B.drop (sizeOf saltOut) bs
        in Out {..}

-- | Given at least 24 bytes of entropy, produce an in context that can
-- communicate with an identically initialized out context.
newInContext  :: ByteString -> InContext
newInContext bs
    | B.length bs < 24 = error "Not enough entropy"
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
        tagLen = 16
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

-- Decrypts multiple-of-block-sized input, returing a bytestring of the
-- [ctr, ct, tag].
decryptGCM :: AESKey
           -> Word64 -- ^ AES GCM Counter (IV)
           -> Word32 -- ^ Salt
           -> ByteString -- ^ Ciphertext
           -> ByteString -- ^ Tag
           -> Either String ByteString -- Plaintext (or an exception due to bad tag)
decryptGCM key ctr salt ct tag
  | B.length tag < 16 = Left "Tag too small"
  | otherwise = unsafePerformIO $ do
    let ivLen  = sizeOf ctr + sizeOf salt
        tagLen = 16
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
            then return (Left $ "Tags do not match: " ++ show (w1,w2,y1,y2))
            else return (Right pt)

-- |Use an 'OutContext' to protect a message for transport.
-- Message format: [ctr, ct, padding, tag].
send :: OutContext -> ByteString -> (ByteString, OutContext)
send ctx@(Out {..}) pt =
    let !iv_ct_tag = encryptGCM outKey aesCtr saltOut (pad pt)
    in (iv_ct_tag, ctx { aesCtr = 1 + aesCtr })

-- |Use an 'InContext' to decrypt a message, verifying the ICV and sequence
-- number.
-- Message format: [ctr, ct, padding, tag].
recv :: InContext -> ByteString -> Either String (ByteString, InContext)
recv (In {..}) pkg
  | base >= maxBound - 64 = Left "This cipher context has been used too long."
  | otherwise =
    let cnt    = unsafePerformIO $ B.unsafeUseAsCString pkg (peekBE . castPtr)
        cntLen = sizeOf cnt
        tagLen = 16
        tag    = B.drop (B.length pkg - tagLen) pkg
        ct     = let st = (B.drop cntLen pkg) in B.take (B.length st - tagLen) st
        ptpd   = decryptGCM inKey cnt saltIn ct tag
    in case updateBaseMask base mask cnt of
              Nothing -> Left "Dup!"
              Just (base',mask') ->
                  case ptpd of
                      Left err    -> Left err
                      Right ptPad ->
                        case unpad ptPad of
                            Nothing -> Left "Bad padding"
                            Just pt -> Right (pt, In base' mask' saltIn inKey)

pad :: ByteString -> ByteString
pad bs =
        let pd = B.replicate pdLen pdValue
            len = 16
            r = len - (B.length bs `rem` len)
            pdLen = if r == 0 then len else r
            pdValue = fromIntegral pdLen
        in B.concat [bs,pd]

-- Unsafe varient of PCKS5 padding
unpad :: ByteString -> Maybe ByteString
unpad bs
    | len > 0 = Just $ B.take (len - fromIntegral (B.last bs)) bs
    | otherwise = Nothing
  where
      len = B.length bs

updateBaseMask :: Word64 -> Word64 -> Word64 -> Maybe (Word64,Word64)
updateBaseMask !base !mask !seq
  | base <= seq && base >= seqBase =
      let pos = fromIntegral $ seq - base
      in if testBit mask pos
          then Nothing
          else Just (base, setBit mask pos)
  | base < seqBase = updateBaseMask seq (mask `shiftR` fromIntegral (seq - base)) seq
  | base > seq      = Nothing
  where
   !seqBase | seq < 64  = 0
            | otherwise = seq-63

peekBE :: Ptr Word8 -> IO Word64
peekBE p = do
    let op n = fromIntegral `fmap` peekElemOff p n
    as <- mapM op [0..7]
    return (foldl1' (\r a -> (r `shiftL` 8) .|. a) as)

pokeBE :: Ptr Word8 -> Word64 -> IO ()
pokeBE p w = do
    let op n = pokeElemOff p n (fromIntegral (w `shiftR` (56-(8*n) :: Int)))
    mapM_ op [0..7]

pokeBE32 :: Ptr Word8 -> Word32 -> IO ()
pokeBE32 p w = do
    let op n = pokeElemOff p n (fromIntegral (w `shiftR` (24 - (8*n) :: Int)))
    mapM_ op [0..3]

peekBE32 :: Ptr Word8 -> IO Word32
peekBE32 p = do
    let op n = fromIntegral `fmap` peekElemOff p n
    as <- mapM op [0..3]
    return (foldl1' (\r a -> (r `shiftL` 8) .|. a) as)
