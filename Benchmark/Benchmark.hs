import Criterion
import Criterion.Main
import qualified Data.ByteString as B
import Data.Maybe (fromMaybe)
import Network.CommSec
import Network.CommSec.Package
import Control.Concurrent.Async
import Control.Concurrent
import Control.Monad
import Control.Exception (throw)

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

pkg16 = fst $ encode ctxOut x16
pkg32 = fst $ encode ctxOut x32
pkg64 = fst $ encode ctxOut x64
pkg128 = fst $ encode ctxOut x128
pkg256 = fst $ encode ctxOut x256
pkg512 = fst $ encode ctxOut x512
pkg1024 = fst $ encode ctxOut x1024
pkg2048 = fst $ encode ctxOut x2048

main = do
  let secret = B.replicate 32 0
      port1 = 1982
      port2 = 9843
      port3 = 2982
      port4 = 3843

  aw1 <- async $ accept secret port1 Stream
  threadDelay 10000
  c1 <- connect secret "127.0.0.1" port1 Stream
  a1 <- wait aw1
  forkIO (forever $ recv a1)

  aw2 <- async $ accept secret port2 Stream
  threadDelay 10000
  c2 <- connect secret "127.0.0.1" port2 Stream
  a2 <- wait aw2

  aw3 <- async $ acceptUnsafe secret port3 Stream
  threadDelay 10000
  c3 <- connectUnsafe secret "127.0.0.1" port3 Stream
  a3 <- wait aw3
  forkIO (forever $ recvUnsafe a3)

  aw4 <- async $ acceptUnsafe secret port4 Stream
  threadDelay 10000
  c4 <- connectUnsafe secret "127.0.0.1" port4 Stream
  a4 <- wait aw4

  defaultMain [ bench "encode 16b" $   nf (fst . encode ctxOut) x16
              , bench "encode 32b" $   nf (fst . encode ctxOut) x32
              , bench "encode 64b" $   nf (fst . encode ctxOut) x64
              , bench "encode 128b" $  nf (fst . encode ctxOut) x128
              , bench "encode 256b" $  nf (fst . encode ctxOut) x256
              , bench "encode 512b" $  nf (fst . encode ctxOut) x512
              , bench "encode 1024b" $ nf (fst . encode ctxOut) x1024
              , bench "encode 2048b" $ nf (fst . encode ctxOut) x2048
              , bench "decode 16b" $   nf (either throw fst . decode ctxIn) pkg16
              , bench "decode 32b" $   nf (either throw fst . decode ctxIn) pkg32
              , bench "decode 64b" $   nf (either throw fst . decode ctxIn) pkg64
              , bench "decode 128b" $  nf (either throw fst . decode ctxIn) pkg128
              , bench "decode 256b" $  nf (either throw fst . decode ctxIn) pkg256
              , bench "decode 512b" $  nf (either throw fst . decode ctxIn) pkg512
              , bench "decode 1024b" $ nf (either throw fst . decode ctxIn) pkg1024
              , bench "decode 2048b" $ nf (either throw fst . decode ctxIn) pkg2048
              , bench "send stream 16b" $ send c1 x16
              , bench "send stream 2048b" $ send c1 x2048
              , bench "send/recv stream 2048b" $ (send c2 x2048 >> recv a2)
              , bench "sendU stream 16b" $ sendUnsafe c3 x16
              , bench "sendU stream 2048b" $ sendUnsafe c3 x2048
              , bench "sendU/recvU stream 2048b" $ (sendUnsafe c4 x2048 >> recvUnsafe a4)
              -- , bench "send dgram"  $ send c2 x16
              -- , bench "recv stream" $ recv a2
              -- , bench "recv dgram" $ recv a2
              ]
