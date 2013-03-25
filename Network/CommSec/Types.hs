{-# LANGUAGE DeriveDataTypeable #-}

module Network.CommSec.Types where

import Control.Exception
import Data.Data
import Data.Typeable
import Control.Concurrent.MVar

-- |Errors that can be returned by the decoding/receicing operations.
data CommSecError
        = OldContext    -- The context is too old (sequence number rollover)
        | DuplicateSeq  -- The sequence number we previously seen (possible replay attack)
        | InvalidICV    -- The integrity check value is invalid
        | BadPadding    -- The padding was invalid (corrupt sender?)
    deriving (Eq,Ord,Show,Enum,Data,Typeable)

-- |Policy for misordered packets.  Notice StrictOrdering does not mean
-- every sequence numbered packet will be received, only that the sequence
-- number will always increase.
data SequenceMode
        = AllowOutOfOrder -- In IPSec style, allow for datagrams to be recieved out of order
        | StrictOrdering  -- Allow messages with newer sequence numbers than previously observed, but drop any with older.
        | Sequential      -- Allows messages only if the sequence number matches the expected value
    deriving (Eq,Ord,Show,Enum,Data,Typeable)

instance Exception CommSecError
