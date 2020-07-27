{-# language BangPatterns #-}
{-# language DuplicateRecordFields #-}
{-# language PatternSynonyms #-}
{-# language RankNTypes #-}
{-# language NamedFieldPuns #-}
{-# language BinaryLiterals #-}

module Dns.Message
  ( -- * Functions
    encode
  , decode
  , parser
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

import Data.Bits (testBit,setBit,clearBit)
import Data.Bytes (Bytes, toByteArray)
import Data.Bytes.Parser (Parser)
import Data.Coerce (coerce)
import Data.Primitive (SmallArray,ByteArray,sizeofByteArray)
import Data.Word (Word32,Word16,Word8)

import qualified Data.Bytes.Builder as BB
import qualified Data.Bytes.Chunks as Chunks
import qualified Data.Bytes.Parser as P
import qualified Data.Bytes.Parser.BigEndian as P
import qualified Data.Primitive.Contiguous as Contiguous

encode :: Message -> ByteArray
encode m = Chunks.concatU $ BB.run 4080 (builderMessage m)

builderMessage :: Message -> BB.Builder
builderMessage Message{ 
    identifier, bitfields, question, answer, authority, additional
  } =  BB.word16BE identifier
    <> BB.word16BE (getBitfields bitfields)
    <> BB.word16BE questionCount
    <> BB.word16BE answerCount
    <> BB.word16BE authorityCount
    <> BB.word16BE additionalCount
    <> Contiguous.foldMap' builderQuestion question
    <> Contiguous.foldMap' builderResourceRecord answer
    <> Contiguous.foldMap' builderResourceRecord authority
    <> Contiguous.foldMap' builderResourceRecord additional
  where
  questionCount = fromIntegral $ Contiguous.size question
  answerCount = fromIntegral $ Contiguous.size answer
  authorityCount = fromIntegral $ Contiguous.size authority
  additionalCount = fromIntegral $ Contiguous.size additional

builderQuestion :: Question -> BB.Builder
builderQuestion Question{
    name, type_, class_
  } =  builderDnsName name
    <> BB.word16BE (coerce type_)
    <> BB.word16BE (coerce class_)

builderResourceRecord :: ResourceRecord -> BB.Builder
builderResourceRecord ResourceRecord{
    name, type_, class_, ttl, rdata
  } = builderDnsName name
   <> BB.word16BE (coerce type_)
   <> BB.word16BE (coerce class_)
   <> BB.word32BE ttl
   <> BB.word16BE (fromIntegral $ sizeofByteArray rdata)
   <> BB.byteArray rdata

builderDnsName :: SmallArray DnsName -> BB.Builder
builderDnsName name = 
  flip Contiguous.foldMap' name $ \(DnsName len n) ->
    BB.word8 len <> BB.byteArray n

decode :: Bytes -> Maybe Message
decode b = P.parseBytesMaybe parser b

parser :: Parser Int s Message
parser = do
  identifier' <- P.word16 1
  bitfields' <- Bitfields <$> P.word16 2
  questionCount <- P.word16 3
  answerCount <- P.word16 4
  authorityCount <- P.word16 5
  additionalCount <- P.word16 6
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

parseQuestion :: Parser Int s Question
parseQuestion = do
  name' <- parseDnsName
  type_' <- Type <$> P.word16 10
  class_' <- Class <$> P.word16 11
  pure $ Question
    { name = name'
    , type_ = type_'
    , class_ = class_'
    }

parseResourceRecord :: Parser Int s ResourceRecord
parseResourceRecord = do
  name' <- parseDnsName
  type_' <- Type <$> P.word16 15
  class_' <- Class <$> P.word16 16
  ttl' <- P.word32 17
  rdataLen <- P.word16 18
  rdata' <- P.take 19 (fromIntegral rdataLen)
  pure $ ResourceRecord
    { name = name'
    , type_ = type_'
    , class_ = class_'
    , ttl = ttl'
    , rdata = toByteArray rdata'
    }

-- The compression scheme allows a domain name in a message to be
-- represented as either:
--   - a sequence of labels ending in a zero octet
--   - a pointer
--   - a sequence of labels ending with a pointer
parseDnsName :: Parser Int s (SmallArray DnsName)
parseDnsName = do
  (len, labels) <- go 0 []
  pure $ Contiguous.unsafeFromListReverseN len labels
  where
  go len xs = do
    labelLen <- P.word8 12
    case labelLen of
      0 -> pure (len, xs)
      _ -> do
        case (testBit labelLen 7 && testBit labelLen 6) of
          True -> do -- compressed
            ptr <- P.take 99 1 -- second octet of pointer
            let !ptr' = toByteArray $! ptr
            pure $ ((len+1), (DnsName labelLen ptr' : xs))
          False -> do -- uncompressed
            !label <- P.take 13 (fromIntegral labelLen)
            let !label' = toByteArray $! label
            go (len+1) (DnsName labelLen label' : xs)

data Message = Message
  { identifier :: !Word16 -- ^ Query or reply identifier
  , bitfields :: !Bitfields -- ^ Sub-byte-sized fields
  , question :: !(SmallArray Question) -- ^ The question for the name server
  , answer :: !(SmallArray ResourceRecord) -- ^ RRs answering the question
  , authority :: !(SmallArray ResourceRecord) -- ^ RRs pointing toward an authority
  , additional :: !(SmallArray ResourceRecord) -- ^ RRs holding additional information
  } deriving (Eq, Show)

data DnsName = DnsName 
  !Word8 -- length including upper 2 bits which specify encoding
  !ByteArray -- offset or label
  deriving (Eq, Show)

data Question = Question
  { name :: !(SmallArray DnsName) -- ^ Name
  , type_ :: !Type -- ^ Question type
  , class_ :: !Class  -- ^ Question class
  } deriving (Eq,Show)

data ResourceRecord = ResourceRecord
  { name :: !(SmallArray DnsName) -- ^ Name
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

-- showBits :: (Integral a, Show a) => a -> String
-- showBits x = 
--   let y = showIntAtBase 2 intToDigit x ""
--   in pad y <> y
--   where
--   pad z = "0b" <> (replicate (8 - (length z)) '0')

