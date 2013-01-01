import Criterion
import Criterion.Main
import qualified Data.ByteString as B
import Data.Maybe (fromMaybe)
import Network.CommSec

ctxIn :: InContext
ctxIn  = newInContext (B.replicate 24 0)

ctxOut :: OutContext
ctxOut = newOutContext (B.replicate 24 0)

x16   = B.replicate 16 0
x32   = B.replicate 32 0
x64   = B.replicate 64 0
x128  = B.replicate 128 0
x256  = B.replicate 256 0
x512  = B.replicate 512 0
x1024 = B.replicate 1024 0
x2048 = B.replicate 2048 0

pkg16 = fst $ send ctxOut x16
pkg32 = fst $ send ctxOut x32
pkg64 = fst $ send ctxOut x64
pkg128 = fst $ send ctxOut x128
pkg256 = fst $ send ctxOut x256
pkg512 = fst $ send ctxOut x512
pkg1024 = fst $ send ctxOut x1024
pkg2048 = fst $ send ctxOut x2048

main = do
  defaultMain [ bench "send 16b" $   nf (fst . send ctxOut) x16
              , bench "send 32b" $   nf (fst . send ctxOut) x32
              , bench "send 64b" $   nf (fst . send ctxOut) x64
              , bench "send 128b" $  nf (fst . send ctxOut) x128
              , bench "send 256b" $  nf (fst . send ctxOut) x256
              , bench "send 512b" $  nf (fst . send ctxOut) x512
              , bench "send 1024b" $ nf (fst . send ctxOut) x1024
              , bench "send 2048b" $ nf (fst . send ctxOut) x2048
              , bench "recv 16b" $   nf (either error fst . recv ctxIn) pkg16
              , bench "recv 32b" $   nf (either error fst . recv ctxIn) pkg32
              , bench "recv 64b" $   nf (either error fst . recv ctxIn) pkg64
              , bench "recv 128b" $  nf (either error fst . recv ctxIn) pkg128
              , bench "recv 256b" $  nf (either error fst . recv ctxIn) pkg256
              , bench "recv 512b" $  nf (either error fst . recv ctxIn) pkg512
              , bench "recv 1024b" $ nf (either error fst . recv ctxIn) pkg1024
              , bench "recv 2048b" $ nf (either error fst . recv ctxIn) pkg2048
              ]
