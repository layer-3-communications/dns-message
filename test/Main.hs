
{-# LANGUAGE 
    MagicHash 
  , TemplateHaskell
#-}

module Main where

import Test.Tasty
import Test.Tasty.HUnit
import System.IO
import qualified Data.Bytes as Bytes
import qualified Dns.Message as Dns
import qualified Data.Bytes.Parser as P

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "Tests" [unitTests]

unitTests :: TestTree
unitTests = testGroup "Unit tests"
  [ testCase "encode/decode round trip" $ do
      dnsMsg <- readFileBytes "test/dns-msg.bin"
      dnsMsg2 <- readFileBytes "test/dns-msg2.bin"
      let dnsMsg' = either (\x -> error $ "ERROR INDEX: " <> show x) id $ P.parseBytesEither Dns.parser dnsMsg
      let dnsMsg2' = either (\x -> error $ "ERROR INDEX: " <> show x) id $ P.parseBytesEither Dns.parser dnsMsg2
      Dns.encode dnsMsg' @?= Bytes.toByteArray dnsMsg
      Dns.encode dnsMsg2' @?= Bytes.toByteArray dnsMsg2
  ]

unwrap :: Either a b -> b
unwrap = either (error "unwrap") id

readFileBytes :: FilePath -> IO Bytes.Bytes
readFileBytes fp = withBinaryFile fp ReadMode $ \h -> do
  sz <- hFileSize h
  Bytes.hGet h (fromIntegral sz)
