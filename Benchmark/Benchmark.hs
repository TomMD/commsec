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
import qualified Network.Secure as S
import OpenSSL
import Foreign.Marshal.Alloc

ctxIn :: InContext
ctxIn  = newInContext (B.replicate 24 0) Sequential

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

main = withOpenSSL $ allocaBytes 2048 $ \ptr -> do
  let secret = B.replicate 32 0
      port1 = 1982
      port2 = 9843
      port3 = 2982
      port4 = 3843
      port5 = 4843
      port6 = 5843

  id <- S.newLocalIdentity "localhost" 365
  S.writeIdentity (S.toPeerIdentity id) >>= B.writeFile "blah.pub"
  let me = id
  you <- B.readFile "blah.pub" >>= S.readIdentity
  server <- S.newServer (Nothing, "4242")
  aw0   <- async $ S.accept me [you] server
  c0 <- S.connect me [you] ("localhost", "4242")
  a0 <- wait aw0

  aw1 <- async $ accept secret port1
  threadDelay 10000
  c1 <- connect secret "127.0.0.1" port1
  a1 <- wait aw1
  forkIO (forever $ recv a1)

  aw2 <- async $ accept secret port2
  threadDelay 10000
  c2 <- connect secret "127.0.0.1" port2
  a2 <- wait aw2


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
              , bench "send/recv stream 16b (ptr)" $ (sendPtr c2 ptr 16 >> recvPtr a2 ptr 2048)
              , bench "send/recv stream 16b" $ (send c2 x16 >> recv a2)
              , bench "secure-sockets 16b" $ (S.write c0 x16 >> S.read a0 16)
              , bench "send/recv stream 2048b (ptr)" $ (sendPtr c2 ptr 2048 >> recvPtr a2 ptr 2048)
              , bench "send/recv stream 2048b" $ (send c2 x2048 >> recv a2)
              , bench "secure-sockets 2048b" $ (S.write c0 x2048 >> S.read a0 2048)
              ]
