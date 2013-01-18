{-# LANGUAGE DeriveDataTypeable #-}

module Network.CommSec.Types where

import Control.Exception
import Data.Data
import Data.Typeable

-- |Errors that can be returned by the decoding/receicing operations.
data CommSecError
        = OldContext    -- The context is too old (sequence number rollover)
        | DuplicateSeq  -- The sequence number we previously seen (possible replay attack)
        | InvalidICV    -- The integrity check value is invalid
        | BadPadding    -- The padding was invalid (corrupt sender?)
    deriving (Eq,Ord,Show,Enum,Data,Typeable)

instance Exception CommSecError
