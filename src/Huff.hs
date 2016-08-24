{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE DeriveFunctor #-}
module Huff where

import GHC.Generics
import Data.Bits

import Data.Either.Unwrap

import Data.ASN1.BinaryEncoding
import Data.ASN1.Types
import qualified Data.ByteString.Lazy.Char8 as LBS
import qualified Data.ByteString.Char8 as BS

import Data.Text.Encoding (encodeUtf8)
import Data.Aeson ((.:), (.:?), decode, FromJSON(..),
  ToJSON(..), Value(..), genericParseJSON, defaultOptions)
import Data.Binary.Get
import Data.Aeson.Types
import Control.Applicative ((<$>), (<*>))
import Data.ASN1.BitArray
import Data.ASN1.Encoding
import Data.ByteString (pack)
import Data.ByteString.Base64.URL (encode, decodeLenient)
import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8, decodeUtf8)

import qualified Crypto.Hash.SHA256 as SHA256

-- Cryptonite stuff
import Crypto.Error
import Crypto.PubKey.ECC.Types
import qualified Crypto.PubKey.ECC.P256 as P256
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import Crypto.Hash.Algorithms

-- Curve
ourCurve = getCurveByName SEC_p256r1

-- Errors
data HuffError =
  RegistrationParseError |
  RegistrationDataParseError |
  RegistrationCertificateParseError |
  PubKeyParsingError |
  SignatureParseError |
  ChallengeMismatchError |
  FailedVerificationError |
  SigninParseError |
  ClientDataParseError |
  RequestParseError
  deriving (Show, Eq)

data Request = Request {
  appId :: T.Text,
  version :: T.Text,
  challenge :: T.Text,
  keyHandle :: Maybe T.Text
} deriving (Show, Generic, Eq)
instance FromJSON Request
instance ToJSON Request

-- Registration Flow --
data Registration = Registration {
  registration_registrationData :: T.Text,
  registration_challenge :: T.Text,
  registration_version :: Maybe T.Text,
  registration_appId :: T.Text,
  registration_clientData :: T.Text,
  registration_sessionID :: Maybe T.Text
} deriving (Show, Generic)
instance ToJSON Registration where
  toJSON = genericToJSON defaultOptions {
                fieldLabelModifier = Prelude.drop 13 }

instance FromJSON Registration where
  parseJSON = genericParseJSON defaultOptions {
                fieldLabelModifier = Prelude.drop 13 }


data RegistrationData = RegistrationData {
  registrationData_reserved :: BS.ByteString,
  registrationData_publicKey :: BS.ByteString,
  registrationData_keyHandle :: BS.ByteString,
  registrationData_certificate :: BS.ByteString,
  registrationData_signature :: BS.ByteString
} deriving (Show, Generic)

parseRequest :: String -> Either HuffError Request
parseRequest x = case (Data.Aeson.decode (LBS.pack x) :: Maybe Request) of
  Just request -> Right request
  Nothing -> Left RequestParseError

parseRegistration :: String -> Either HuffError Registration
parseRegistration x = case (Data.Aeson.decode (LBS.pack x) :: Maybe Registration) of
  Just registration -> Right registration
  Nothing -> Left RegistrationParseError

parseRegistrationData :: BS.ByteString -> Either HuffError RegistrationData
parseRegistrationData r = Right $ runGet unpackRegistrationData ( LBS.fromStrict $ decodeLenient r)

getPubKeyFromCertificate :: BS.ByteString -> Either HuffError ECDSA.PublicKey
getPubKeyFromCertificate cert = case (decodeASN1' DER cert) of
  Right certParse -> case (parsePublicKey $ BS.tail $ fromBitString $ certParse !! 34) of
    Just key -> Right key
    Nothing -> Left PubKeyParsingError
  Left _ -> Left RegistrationCertificateParseError

getSignatureBase :: BS.ByteString -> BS.ByteString -> BS.ByteString -> BS.ByteString -> BS.ByteString
getSignatureBase appId clientData keyHandle publicKey = sigBase
  where sigBase = BS.concat([BS.pack "\NUL", SHA256.hash(appId), SHA256.hash(decodeLenient clientData), keyHandle, publicKey])

getSignatureBaseFromRegistration :: Registration -> RegistrationData -> Either HuffError BS.ByteString
getSignatureBaseFromRegistration registration registrationData = do
  appId <- pure $ BS.pack $ T.unpack $ registration_appId registration
  clientData <- pure $ BS.pack $ T.unpack $ registration_clientData registration
  keyHandle <- pure $ registrationData_keyHandle registrationData
  publicKey <- pure $ registrationData_publicKey registrationData
  pure $ getSignatureBase appId clientData keyHandle publicKey

verifyRegistration :: Request -> Registration -> Either HuffError Request
verifyRegistration request registration = do
  challengesEqual <- huffComparator (challenge request) (registration_challenge registration) ChallengeMismatchError
  registrationData <- parseRegistrationData $ encodeUtf8 $ registration_registrationData registration
  pkey <- getPubKeyFromCertificate $ registrationData_certificate registrationData
  signature <- parseSignature $ registrationData_signature registrationData
  signatureBase <- getSignatureBaseFromRegistration registration registrationData
  case (verifySignature signatureBase pkey signature) of
    True -> Right (request {keyHandle = Just $ formatOutputBase64 $ registrationData_keyHandle registrationData})
    False -> Left FailedVerificationError

-- Signin Flow --
data Signin = Signin {
  signin_keyHandle :: T.Text,
  signin_clientData :: T.Text,
  signin_signatureData :: T.Text
} deriving (Show, Generic, Eq)

instance FromJSON Signin where
  parseJSON = genericParseJSON defaultOptions {
                fieldLabelModifier = Prelude.drop 7 }

data ClientData = ClientData {
  clientData_typ :: T.Text,
  clientData_challenge :: T.Text,
  clientData_origin :: T.Text,
  clientData_cid_pubkey :: T.Text
  } deriving (Show, Generic, Eq)

instance FromJSON ClientData where
  parseJSON = genericParseJSON defaultOptions {
                fieldLabelModifier = Prelude.drop 11 }

data SignatureData = SignatureData {
  signatureData_userPresenceFlag :: BS.ByteString,
  signatureData_counter :: BS.ByteString,
  signatureData_signature :: BS.ByteString
} deriving (Show, Generic)

parseSignin :: String -> Either HuffError Signin
parseSignin x = case (Data.Aeson.decode (LBS.pack x) :: Maybe Signin) of
  Just signin -> Right signin
  Nothing -> Left SigninParseError

parseClientData :: BS.ByteString -> Either HuffError ClientData
parseClientData x = case (Data.Aeson.decode (LBS.fromStrict $ decodeLenient x) :: Maybe ClientData) of
  Just clientData -> Right clientData
  Nothing -> Left ClientDataParseError

verifySignin :: BS.ByteString -> Request -> Signin -> Either HuffError Bool
verifySignin savedPubkey request signin = do
  clientData <- parseClientData $ encodeUtf8 $ signin_clientData signin
  challengesEqual <- huffComparator (challenge request) (clientData_challenge clientData) ChallengeMismatchError
  signatureData <- parseSignatureData $ encodeUtf8 $ signin_signatureData signin
  signature <- parseSignature $ signatureData_signature signatureData
  signatureBase <- getSigninSignatureBase request signin signatureData
  -- So Gross. TODO: write function that checks first byte for compression state, parses each pubkey format
  publicKey <- case (parsePublicKey $ BS.tail $ savedPubkey) of
    Just key -> Right key
    Nothing -> Left PubKeyParsingError
  case (verifySignature signatureBase publicKey signature) of
    True -> Right True
    False -> Left FailedVerificationError

-- Other stuff

parseSignatureData :: BS.ByteString -> Either HuffError SignatureData
parseSignatureData s = Right $ runGet unpackSignatureData ( LBS.fromStrict $ decodeLenient s)

parseSignature :: BS.ByteString -> Either HuffError ECDSA.Signature
parseSignature possibleSig = case (decodeASN1' DER (possibleSig)) of
  Right sigParse -> Right $ ECDSA.Signature (fromIntVal $ sigParse !! 1) (fromIntVal $ sigParse !! 2)
  Left _ -> Left SignatureParseError

--getSigninSignatureBase appId userPresenceFlag counter clientData = sigBase
--  where sigBase = BS.concat([SHA256.hash(BS.pack appId), userPresenceFlag, counter, SHA256.hash(decodeLenient $ BS.pack clientData)])

getSigninSignatureBase :: Request -> Signin -> SignatureData -> Either HuffError BS.ByteString
getSigninSignatureBase request signin signatureData = do
  appId <- pure $ encodeUtf8 $ appId request
  userPresenceFlag <- pure $ signatureData_userPresenceFlag signatureData
  counter <- pure $ signatureData_counter signatureData
  clientData <- pure $ encodeUtf8 $ signin_clientData signin
  Right $ BS.concat([SHA256.hash(appId), userPresenceFlag, counter, SHA256.hash(decodeLenient clientData)])

parsePublicKey keyByteString = case P256.pointFromBinary keyByteString of
  CryptoPassed key -> Just $ ECDSA.PublicKey ourCurve $ Point (fst $ P256.pointToIntegers key) (snd $ P256.pointToIntegers key)
  CryptoFailed err -> Nothing

-- URL-friendly base64 encoding may or may not contain padding. Delete it here
-- https://tools.ietf.org/html/rfc4648#section-3.2
formatOutputBase64 :: BS.ByteString -> T.Text
formatOutputBase64 byteString = T.replace "=" "" (decodeUtf8 $ encode byteString)

verifySignature :: BS.ByteString -> ECDSA.PublicKey -> ECDSA.Signature -> Bool
verifySignature sigBase pubKey signature = ECDSA.verify Crypto.Hash.Algorithms.SHA256 pubKey signature sigBase

huffComparator :: (Eq a) => a -> a -> HuffError -> Either HuffError Bool
huffComparator firstThing secondThing theError = case (firstThing == secondThing) of
    True -> Right True
    False -> Left theError

unpackRegistrationData = do
  reserved <- getByteString 1
  publicKey <- getByteString 65
  keyHandleLen <- getWord8
  keyHandle <- getByteString $ fromIntegral keyHandleLen
  cert <- unpackASN1
  sign <- unpackASN1
  return $ RegistrationData reserved publicKey keyHandle cert sign

unpackSignatureData = do
  userPresenceFlag <- getByteString 1
  counter <- getByteString 4
  signature <- unpackASN1
  return $ SignatureData userPresenceFlag counter signature

unpackASN1 = do
  asnPadding <- getWord8
  asnLen <- getWord8
  if ((.&.) asnLen 128) /= 0
    then do
      firstByte <- getWord8
      secondByte <- getWord8
      let firstLen = (fromIntegral firstByte :: Int)
      let secondLen = (fromIntegral secondByte :: Int)
      let asnLength = (firstLen * 256) + secondLen
      asnBody <- getByteString asnLength
      return $ BS.concat([pack([asnPadding, asnLen, firstByte, secondByte]), asnBody])
    else do
      asnBody <- getByteString (fromIntegral asnLen)
      return $ BS.concat([pack([asnPadding, asnLen]), asnBody])

fromIntVal (IntVal x) = x
fromBitString (BitString (BitArray len x)) = x
