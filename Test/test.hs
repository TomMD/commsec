import Crypto.Classes (buildKey)
import Network.CommSec
import Data.ByteString as B
import System.Entropy

main = do
    pt <- getEntropy 41
    bs <- getEntropy 24
    let i1  = newInContext bs
        o1  = newOutContext bs
        (pkt1,o2) = send o1 pt
        pt1 = recv i1 pkt1
    print (B.take 8 pkt1, B.drop 8 pkt1, B.drop (B.length pkt1 - 16) pkt1)
    case pt1 of
        Left s -> print s
        Right (x,_) -> print x
    print pt
