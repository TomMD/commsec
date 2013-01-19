{-# LANGUAGE ExistentialQuantification #-}
import Network.CommSec
import Network.CommSec.Package
import Network.CommSec.BitWindow
import qualified Data.ByteString as B
import Data.Either
import Test.QuickCheck
import Test.QuickCheck.Monadic
import Control.Concurrent.Async
import Data.Bits
import Foreign.Marshal.Alloc
import Foreign.Storable

instance Arbitrary B.ByteString where
    arbitrary = B.pack `fmap` arbitrary

isRight (Right _) = True
isRight _ = False

isLeft = not . isRight

entropy = B.replicate 64 0

prop_package_encDecId x = either (error . show) fst (decode inCtx $ fst (encode outCtx x)) == x
 where
    inCtx = newInContext entropy
    outCtx = newOutContext entropy

prop_bitwindow_rejects_low bw cnt = cnt < (fst bw) ==> isLeft (updateBitWindow bw cnt)

prop_bitwindow_rejects_match bw cnt = testBit (snd bw) (fromIntegral $ cnt - fst bw) ==> isLeft (updateBitWindow bw cnt)

prop_bitwindow_accepts_high bw cnt = cnt > (fst bw + 63) ==> isRight (updateBitWindow bw cnt)

prop_bitwindow_accepts_nonmatch bw cnt = cnt > (fst bw) && cnt < (fst bw + 64) && not (testBit (snd bw) (fromIntegral $ cnt - fst bw)) ==> isRight (updateBitWindow bw cnt)

prop_bitwindow_rejects_dup bw cs =
        let bwFinal = foldl (\b' c -> either (const b') id (updateBitWindow b' c)) bw cs
            rs      = map (updateBitWindow bwFinal) cs
        in all isLeft rs

prop_send_recv_valid cIn cOut bs = monadicIO t
  where t = do
        run $ send cOut bs
        bs' <- run $ recv cIn
        assert (bs ==  bs')

prop_peek_poke_BE val = monadicIO t
  where t = do
         r <- run $ allocaBytes (sizeOf val) $ \ptr -> do
                    pokeBE ptr val
                    v <- peekBE ptr
                    return (v == val)
         assert r

prop_peek_poke_BE32 val = monadicIO t
  where t = do
         r <- run $ allocaBytes (sizeOf val) $ \ptr -> do
                    pokeBE32 ptr val
                    v <- peekBE32 ptr
                    return (v == val)
         assert r

data Test = forall a. Testable a => T String a

tests :: Connection Safe -> Connection Safe -> [Test]
tests cIn cOut =
        [
          T "prop_send_recv_valid" (prop_send_recv_valid cIn cOut)
        , T "prop_peek_poke_BE" (prop_peek_poke_BE)
        , T "prop_peek_poke_BE32" (prop_peek_poke_BE32)
        , T "prop_bitwindow_rejects_dup" (prop_bitwindow_rejects_dup)
        , T "prop_bitwindow_rejects_low" prop_bitwindow_rejects_low
        , T "prop_bitwindow_rejects_match" prop_bitwindow_rejects_match
        , T "prop_bitwindow_accepts_high" prop_bitwindow_accepts_high
        , T "prop_bitwindow_accepts_nonmatch" prop_bitwindow_accepts_nonmatch
        , T "prop_package_encDecId" prop_package_encDecId
        ]

runTest :: Test -> IO ()
runTest (T s a) = putStrLn s >> quickCheckWith (stdArgs { maxSuccess = 10000 }) a

runTests :: Connection Safe -> Connection Safe -> IO ()
runTests i o = mapM_ runTest (tests i o)

main = do
    iW <- async $ accept entropy 3245
    o <- connect entropy "127.0.0.1" 3245
    i <- wait iW
    runTests i o
