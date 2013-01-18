{-# LANGUAGE BangPatterns, UnboxedTuples #-}
module Network.CommSec.BitWindow
    ( BitWindow
    , zeroWindow
    , updateBitWindow
    ) where

import Data.Bits
import Network.CommSec.Types
import Data.Word (Word64)

-- | A Bit Window is just an unpacked tuple of base and mask
type BitWindow = (Word64,Word64)

zeroWindow :: BitWindow
zeroWindow = (0,0)

updateBitWindow :: BitWindow -> Word64 -> Either CommSecError BitWindow
updateBitWindow !(!base,!mask) !sqn
  | base >= maxBound - 63 && mask == maxBound = Left OldContext
  | base <= sqn && base >= seqBase =
        let pos = fromIntegral $ sqn - base
        in if testBit mask pos
            then Left DuplicateSeq
            else let new = setBit mask pos
                 in new `seq` Right (base, new)
  | base < seqBase =
        let newBase = seqBase
            newMask
                | seqBase - base > 63 = 0
                | otherwise           =  mask `shiftR` fromIntegral (seqBase - base)
            shiftIt !b !m
                | testBit m 0 = shiftIt (b+1) (shiftR m 1)
                | otherwise   = (b,m)
            (finalBase, finalMask) = shiftIt newBase newMask
        in updateBitWindow (finalBase,finalMask) sqn
  | base > sqn = Left DuplicateSeq
  where
   !seqBase | sqn < 64 = 0
            | otherwise = sqn - 63
{-# INLINE updateBitWindow #-}

