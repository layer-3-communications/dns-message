{-# language BangPatterns #-}
{-# language DuplicateRecordFields #-}
{-# language PatternSynonyms #-}
{-# language RankNTypes #-}
{-# language NamedFieldPuns #-}

module Dns.Message
  ( -- * Functions
    encode
  , decode
    -- * Types
  , Message(..)
  , ResourceRecord(..)
  , Question(..)
  , Type(..)
  , Class(..)
    -- * Opcode Patterns
  , pattern Query
  , pattern IQuery
  , pattern Status
  , pattern Notify
  , pattern Update
    -- * ResponseCode Patterns
  , pattern NoErr
  , pattern FormatErr
  , pattern ServFail
  , pattern NameErr
  , pattern NotImpl
  , pattern Refused
  , pattern YXDomain
  , pattern YXRRSet
  , pattern NXRRSet
  , pattern NotAuth
  , pattern NotZone
    -- * Bitfields
  , query
  , authoritativeAnswer
  , truncation
  ) where

import Control.Monad (when)
import Data.Bits (testBit,setBit,clearBit)
import Data.Bytes (Bytes, toByteArray)
import Data.Bytes.Parser (Parser)
import Data.Coerce (coerce)
import Data.Primitive (SmallArray,ByteArray,sizeofByteArray)
import Data.Word (Word32,Word16,Word8)
import qualified Data.Bytes as Bytes
import qualified Data.Bytes.Builder as BB
import qualified Data.Bytes.Chunks as Chunks
import qualified Data.Bytes.Parser as P
import qualified Data.Bytes.Parser.BigEndian as P
import qualified Data.Primitive.Contiguous as Contiguous

encode :: Message -> ByteArray
encode m = Chunks.concatU $ BB.run len (builderMessage m)
  where
  len = lenIdentifier + lenBitfields + 2 + 2 + 2 + 2 + lenQuestion + lenAnswer + lenAuthority + lenAdditional
  lenIdentifier = 2
  lenBitfields = 2
  lenQuestion = 
    let qlen :: Question -> Int
        qlen Question{name} = 2 + sizeofByteArray name + 2 + 2
     in Contiguous.foldl' (\acc q -> acc + qlen q) 0 (question m)
  lenAnswer     = Contiguous.foldl' (\acc x -> lenResourceRecord x + acc) 0 (answer m)
  lenAuthority  = Contiguous.foldl' (\acc x -> lenResourceRecord x + acc) 0 (authority m)
  lenAdditional = Contiguous.foldl' (\acc x -> lenResourceRecord x + acc) 0 (additional m)
  lenResourceRecord :: ResourceRecord -> Int
  lenResourceRecord ResourceRecord{name,rdata} = 2 + sizeofByteArray name + 2 + 2 + 4 + 2 + sizeofByteArray rdata

builderMessage :: Message -> BB.Builder
builderMessage Message{ 
    identifier, bitfields, question, answer, authority, additional
  } =  BB.word16BE identifier
    <> BB.word16BE (getBitfields bitfields)
    <> BB.word16BE questionCount
    <> BB.word16BE answerCount
    <> BB.word16BE authorityCount
    <> BB.word16BE additionalCount
    <> Contiguous.foldMap builderQuestion question
    <> Contiguous.foldMap builderResourceRecord answer
    <> Contiguous.foldMap builderResourceRecord authority
    <> Contiguous.foldMap builderResourceRecord additional
  where
  questionCount = fromIntegral $ Contiguous.size question
  answerCount = fromIntegral $ Contiguous.size answer
  authorityCount = fromIntegral $ Contiguous.size authority
  additionalCount = fromIntegral $ Contiguous.size additional

builderQuestion :: Question -> BB.Builder
builderQuestion Question{
    name, type_, class_
  } =  BB.word16BE (fromIntegral $ sizeofByteArray name)
    <> BB.byteArray name
    <> BB.word16BE (coerce type_)
    <> BB.word16BE (coerce class_)

builderResourceRecord :: ResourceRecord -> BB.Builder
builderResourceRecord ResourceRecord{
    name, type_, class_, ttl, rdata
  } = BB.word16BE (fromIntegral $ sizeofByteArray name)
   <> BB.byteArray name
   <> BB.word16BE (coerce type_)
   <> BB.word16BE (coerce class_)
   <> BB.word32BE ttl
   <> BB.word16BE (fromIntegral $ sizeofByteArray rdata)
   <> BB.byteArray rdata

decode :: Bytes -> Maybe Message
decode b = P.parseBytesMaybe parser b

parser :: Parser () s Message
parser = do
  identifier' <- P.word16 ()
  bitfields' <- Bitfields <$> P.word16 ()
  questionCount <- P.word16 ()
  answerCount <- P.word16 ()
  authorityCount <- P.word16 ()
  additionalCount <- P.word16 ()
  question' <- P.replicate (fromIntegral questionCount) parseQuestion
  answer' <- P.replicate (fromIntegral answerCount) parseResourceRecord
  authority' <- P.replicate (fromIntegral authorityCount) parseResourceRecord
  additional' <- P.replicate (fromIntegral additionalCount) parseResourceRecord
  pure $ Message
    { identifier = identifier'
    , bitfields = bitfields'
    , question = question'
    , answer = answer'
    , authority = authority'
    , additional = additional'
    }

-- QNAME
-- Single octet defining the number of characters in the label which follows. 
-- The top two bits of this number must be 00 (indicates the label format is being used) 
-- which gives a maximum domain name length of 63 bytes (octets). 
-- A value of zero indicates the end of the name field.
--
-- the upper two bits being 11 indicates 
-- compression with a pointer to a previous domain name

parseQuestion :: Parser () s Question
parseQuestion = do
  len <- P.any ()
  name' <- P.take () (fromIntegral len)
  when (Bytes.all (\b -> testBit b 7) name') $ P.fail () -- QNAME compression encountered (RFC 1035 section 4.1.4)"
  type_' <- Type <$> P.word16 ()
  class_' <- Class <$> P.word16 ()
  pure $ Question
    { name = toByteArray name'
    , type_ = type_'
    , class_ = class_'
    }

parseResourceRecord :: Parser () s ResourceRecord
parseResourceRecord = do
  namelen <- P.any ()
  name' <- P.take () (fromIntegral namelen)
  when (Bytes.all (\b -> testBit b 7) name') $ P.fail () -- NAME compression encountered (RFC 1035 section 4.1.4)"
  type_' <- Type <$> P.word16 ()
  class_' <- Class <$> P.word16 ()
  ttl' <- P.word32 ()
  rdataLen <- P.word16 ()
  rdata' <- P.take () (fromIntegral rdataLen)
  pure $ ResourceRecord
    { name = toByteArray name'
    , type_ = type_'
    , class_ = class_'
    , ttl = ttl'
    , rdata = toByteArray rdata'
    }

data Message = Message
  { identifier :: !Word16 -- ^ Query or reply identifier
  , bitfields :: !Bitfields -- ^ Sub-byte-sized fields
  , question :: !(SmallArray Question) -- ^ The question for the name server
  , answer :: !(SmallArray ResourceRecord) -- ^ RRs answering the question
  , authority :: !(SmallArray ResourceRecord) -- ^ RRs pointing toward an authority
  , additional :: !(SmallArray ResourceRecord) -- ^ RRs holding additional information
  } deriving (Eq, Show)

data Question = Question
  { name :: !ByteArray -- ^ Name
  , type_ :: !Type -- ^ Question type
  , class_ :: !Class  -- ^ Question class
  } deriving (Eq,Show)

data ResourceRecord = ResourceRecord
  { name :: !ByteArray -- ^ Name
  , type_ :: !Type -- ^ Resource record type
  , class_ :: !Class  -- ^ Resource record class
  , ttl :: !Word32 -- ^ Time to live
  , rdata :: !ByteArray -- ^ Resource data
  } deriving (Eq,Show)

-- | Raw data format for the header of DNS Query and Response.
data Bitfields = Bitfields { getBitfields :: !Word16 }
  deriving (Eq,Show)

newtype ResponseCode = ResponseCode Word8
  deriving (Eq,Show)

-- | No error condition.
pattern NoErr     :: ResponseCode
pattern NoErr      = ResponseCode  0

-- | Format error - The name server was
--   unable to interpret the query.
pattern FormatErr :: ResponseCode
pattern FormatErr  = ResponseCode  1

-- | Server failure - The name server was
--   unable to process this query due to a
--   problem with the name server.
pattern ServFail  :: ResponseCode
pattern ServFail   = ResponseCode  2

-- | Name Error - Meaningful only for
--   responses from an authoritative name
--   server, this code signifies that the
--   domain name referenced in the query does
--   not exist.
pattern NameErr   :: ResponseCode
pattern NameErr    = ResponseCode  3

-- | Not Implemented - The name server does
--   not support the requested kind of query.
pattern NotImpl   :: ResponseCode
pattern NotImpl    = ResponseCode  4

-- | Refused - The name server refuses to perform the specified operation for
-- policy reasons.  For example, a name server may not wish to provide the
-- information to the particular requester, or a name server may not wish to
-- perform a particular operation (e.g., zone transfer) for particular data.
pattern Refused   :: ResponseCode
pattern Refused    = ResponseCode  5

-- | YXDomain - Dynamic update response, a pre-requisite domain that should not
-- exist, does exist.
pattern YXDomain :: ResponseCode
pattern YXDomain  = ResponseCode 6

-- | YXRRSet - Dynamic update response, a pre-requisite RRSet that should not
-- exist, does exist.
pattern YXRRSet  :: ResponseCode
pattern YXRRSet   = ResponseCode 7

-- | NXRRSet - Dynamic update response, a pre-requisite RRSet that should
-- exist, does not exist.
pattern NXRRSet  :: ResponseCode
pattern NXRRSet   = ResponseCode 8

-- | NotAuth - Dynamic update response, the server is not authoritative for the
-- zone named in the Zone Section.
pattern NotAuth  :: ResponseCode
pattern NotAuth   = ResponseCode 9

-- | NotZone - Dynamic update response, a name used in the Prerequisite or
-- Update Section is not within the zone denoted by the Zone Section.
pattern NotZone  :: ResponseCode
pattern NotZone   = ResponseCode 10

newtype Opcode = Opcode Word8
  deriving (Eq,Show)

pattern Query :: Opcode
pattern Query = Opcode 0

pattern IQuery :: Opcode
pattern IQuery = Opcode 1

pattern Status :: Opcode
pattern Status = Opcode 2

pattern Notify :: Opcode
pattern Notify = Opcode 4

pattern Update :: Opcode
pattern Update = Opcode 5

newtype Type = Type Word16
  deriving (Eq,Show)

newtype Class = Class Word16
  deriving (Eq,Show)

type Lens' a b = forall f. Functor f => (b -> f b) -> (a -> f a)

assignBit :: Word16 -> Int -> Bool -> Word16
{-# inline assignBit #-}
assignBit !w !ix !b = case b of
  True -> setBit w ix
  False -> clearBit w ix

-- | True means query, False means response
query :: Lens' Bitfields Bool
{-# inline query #-}
query k (Bitfields x) = fmap (\b -> Bitfields (assignBit x 15 b)) (k (testBit x 15))

-- | AA (Authoritative Answer) bit - this bit is valid in responses,
-- and specifies that the responding name server is an
-- authority for the domain name in question section.
authoritativeAnswer :: Lens' Bitfields Bool
{-# inline authoritativeAnswer #-}
authoritativeAnswer k (Bitfields x) = fmap (\b -> Bitfields (assignBit x 10 b)) (k (testBit x 10))

-- | TC (Truncated Response) bit - specifies that this message was truncated
-- due to length greater than that permitted on the
-- transmission channel.
truncation :: Lens' Bitfields Bool
{-# inline truncation #-}
truncation k (Bitfields x) = fmap (\b -> Bitfields (assignBit x 9 b)) (k (testBit x 9))

-- TODO: Add these other lenses. Opcode and response code are a little tricky.
--
-- opcode :: !Opcode -- ^ Kind of query.
-- recursionDesired :: !Bool
-- -- ^ RD (Recursion Desired) bit - this bit may be set in a query and
-- -- is copied into the response.  If RD is set, it directs the name server
-- -- to pursue the query recursively. Recursive query support is optional.
-- recursionAvailable :: !Bool
-- -- ^ RA (Recursion Available) bit - this be is set or cleared in a response,
-- -- and denotes whether recursive query support is available in the name server.
-- responseCode :: !ResponseCode
-- -- ^ RCODE (Response Code). Only 4 bits.
-- authenticatedData :: !Bool
-- -- ^ AD (Authenticated Data) bit - (RFC4035, Section 3.2.3).
-- checkingDisabled :: !Bool
-- -- ^ CD (Checking Disabled) bit - (RFC4035, Section 3.2.2).
-- deriving (Eq, Show)

