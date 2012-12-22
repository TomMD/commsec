{-# LANGUAGE BangPatterns, RecordWildCards #-}
module Network.CommSec
    ( OutContext(..)
    , InContext(..)
    , recv
    , send
    ) where

import Prelude hiding (seq)
import Crypto.Cipher.AES as AES
import qualified Data.ByteString.Internal as B
import qualified Data.ByteString as B
import qualified Data.ByteString.Unsafe as B
import Data.ByteString (ByteString)
import Data.Bits
import Data.Word
import Data.List
import Foreign.Ptr
import Foreign.Storable
import System.IO.Unsafe

-- Packet format:
--
--      [CNT | IV | Payload | Pad | ICV]
--           ^-------------------------^
--               encrypted/random
--      ^------------------------------^
--           authenticated

data OutContext =
    Out { seq        :: {-# UNPACK #-} !Word64
        , outKey     :: AES.Key
        , aesCtr     :: AES.IV
        }

data InContext =
    In  { base      :: {-# UNPACK #-} !Word64
        , mask      :: {-# UNPACK #-} !Word64
        , inKey     :: AES.Key
        }

-- |Use an 'OutContext' to protect a message for transport.
send :: OutContext -> ByteString -> (ByteString, OutContext)
send ctx@(Out {..}) pt =
    let (ct,tag) = AES.encryptGCM outKey aesCtr cnt (pad pt)
        cnt = B.unsafeCreate (B.length pt + sizeOf seq) $ \ptr -> pokeBE ptr seq
    in (B.concat [cnt,aesCtr,ct,tag], ctx { seq = seq + 1, aesCtr = AES.incIV aesCtr })

-- |Use an 'InContext' to decrypt a message, verifying the ICV and sequence
-- number.
recv :: InContext -> ByteString -> Either String (ByteString, InContext)
recv (In {..}) pkg 
  | base >= maxBound - 64 = Left "This cipher context has been used too long."
  | otherwise =
    let cnt = unsafePerformIO $ B.unsafeUseAsCString pkg peekBE
        iv  = B.take 16 (B.drop 8 pkg)
        tag = B.drop (B.length pkg - 16)
        ct  = let st = (B.drop 24 pkg) in B.take (B.length st - 16) st
        (ptpd,compTag) = AES.decryptGCM inKey aesCtr aesCtr cnt ct
        ptM            = unpad ptpd
        valid          = compTag == tag -- constTimeEq compTag tag
    in if not valid
           then Left "invalid message"
           else case updateBaseMask base mask cnt of
                      Nothing -> Left "Dup"
                      Just (base',mask') ->
                          case ptM of
                              Just pt -> Right (pt, In base' mask' inKey)
                              Nothing -> Left "Bad padding"

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
    | len > 0 = Just $ B.take (len - fromIntegral (B.last bs))
    | otherwise = Nothing
  where
      len = B.length bs

updateBaseMask :: Word64 -> Word64 -> Word64 -> Maybe (Word64,Word64)
updateBaseMask !base !mask !seq
  | base <= seq && base >= seqBase =
      let pos = seq - base
      in if testBit mask pos
          then Nothing
          else Just (base, setBit mask pos)
  | base < seqBase = updateBaseMask seq (mask `shiftR` seq - base) seq
  | base > seq      = Nothing
  where
   !seqBase = seq-63

peekBE :: Ptr Word8 -> IO Word64
peekBE p = do
    let op n = fromIntegral `fmap` peekElemOff p n
    as <- mapM op [0..7]
    return (foldl1' (\r a -> (r `shiftL` 8) .|. a)) as

pokeBE :: Ptr Word8 -> Word64 -> IO ()
pokeBE p w = do
    let op n = pokeBE p n (fromIntegral $ w `shiftR` 56-(8*n))
    mapM_ op [0..7]

