{-# LANGUAGE DeriveGeneric #-}

module U2F where

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
import Data.List

import qualified Crypto.Hash.SHA256 as SHA256

-- Cryptonite stuff
import Crypto.Error
import Crypto.PubKey.ECC.Types
import qualified Crypto.PubKey.ECC.P256 as P256
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import Crypto.Hash.Algorithms

{-
  HOW TO USE
  ==========
  To Register
    - Generate yourself a Request, consisting of your site/service uri, u2f version number, etc, send it to the client.
    - Assuming the client returned a registration response (Registration), parse it with parseRegistration.
    - Use verifyRegistration Request Registration to verify that the Registration is valid. (Challenge bytes match, were signed by key described in cert)
    - Stash the publicKey and keyHandle somewhere, so you can use them for signin. verifyRegistration returns a Request, with added keyHandle, for convenience.
  To Signin
    - Make a Request.
    - Parse whatever signin json you have with parseSignin.
    - Dig out the publicKey for the relevant keyHandle.
    - Verify signin with verifySignin publicKey Request Signin
-}

-- Curve
ourCurve = getCurveByName SEC_p256r1

-- Errors
data U2FError =
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

parseRequest :: String -> Either U2FError Request
parseRequest x = case (Data.Aeson.decode (LBS.pack x) :: Maybe Request) of
  Just request -> Right request
  Nothing -> Left RequestParseError

parseRegistration :: String -> Either U2FError Registration
parseRegistration x = case (Data.Aeson.decode (LBS.pack x) :: Maybe Registration) of
  Just registration -> Right registration
  Nothing -> Left RegistrationParseError

parseRegistrationData :: BS.ByteString -> Either U2FError RegistrationData
parseRegistrationData r = Right $ runGet unpackRegistrationData ( LBS.fromStrict $ decodeLenient r)

getPubKeyFromCertificate :: BS.ByteString -> Either U2FError ECDSA.PublicKey
getPubKeyFromCertificate cert = case (decodeASN1' DER cert) of
  Right certParse -> case (findPubKey certParse) of
    Just key -> Right key
    Nothing -> Left PubKeyParsingError
  Left _ -> Left RegistrationCertificateParseError

findPubKey :: Foldable t => t ASN1 -> Maybe ECDSA.PublicKey
findPubKey parsedCert = case (find pubKeyShape parsedCert) of
  Just (BitString (BitArray len x)) -> parsePublicKey $ BS.tail x
  _ -> Nothing

pubKeyShape :: ASN1 -> Bool
pubKeyShape (BitString (BitArray len _)) = len == 520
pubKeyShape _ = False

getSignatureBase :: BS.ByteString -> BS.ByteString -> BS.ByteString -> BS.ByteString -> BS.ByteString
getSignatureBase appId clientData keyHandle publicKey = sigBase
  where sigBase = BS.concat([BS.pack "\NUL", SHA256.hash(appId), SHA256.hash(decodeLenient clientData), keyHandle, publicKey])

getSignatureBaseFromRegistration :: Registration -> RegistrationData -> Either U2FError BS.ByteString
getSignatureBaseFromRegistration registration registrationData = do
  appId <- pure $ BS.pack $ T.unpack $ registration_appId registration
  clientData <- pure $ BS.pack $ T.unpack $ registration_clientData registration
  keyHandle <- pure $ registrationData_keyHandle registrationData
  publicKey <- pure $ registrationData_publicKey registrationData
  pure $ getSignatureBase appId clientData keyHandle publicKey

verifyRegistration :: Request -> Registration -> Either U2FError Request
verifyRegistration request registration = do
  challengesEqual <- u2fComparator (challenge request) (registration_challenge registration) ChallengeMismatchError
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

parseSignin :: String -> Either U2FError Signin
parseSignin x = case (Data.Aeson.decode (LBS.pack x) :: Maybe Signin) of
  Just signin -> Right signin
  Nothing -> Left SigninParseError

parseClientData :: BS.ByteString -> Either U2FError ClientData
parseClientData x = case (Data.Aeson.decode (LBS.fromStrict $ decodeLenient x) :: Maybe ClientData) of
  Just clientData -> Right clientData
  Nothing -> Left ClientDataParseError

verifySignin :: BS.ByteString -> Request -> Signin -> Either U2FError Bool
verifySignin savedPubkey request signin = do
  clientData <- parseClientData $ encodeUtf8 $ signin_clientData signin
  challengesEqual <- u2fComparator (challenge request) (clientData_challenge clientData) ChallengeMismatchError
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

parseSignatureData :: BS.ByteString -> Either U2FError SignatureData
parseSignatureData s = Right $ runGet unpackSignatureData ( LBS.fromStrict $ decodeLenient s)

parseSignature :: BS.ByteString -> Either U2FError ECDSA.Signature
parseSignature possibleSig = case (decodeASN1' DER possibleSig) of
  Right ([_, IntVal r, IntVal s, _]) -> Right $ ECDSA.Signature r s
  _ -> Left SignatureParseError

getSigninSignatureBase :: Request -> Signin -> SignatureData -> Either U2FError BS.ByteString
getSigninSignatureBase request signin signatureData = do
  appId <- pure $ encodeUtf8 $ appId request
  userPresenceFlag <- pure $ signatureData_userPresenceFlag signatureData
  counter <- pure $ signatureData_counter signatureData
  clientData <- pure $ encodeUtf8 $ signin_clientData signin
  Right $ BS.concat([SHA256.hash(appId), userPresenceFlag, counter, SHA256.hash(decodeLenient clientData)])

parsePublicKey :: BS.ByteString -> Maybe ECDSA.PublicKey
parsePublicKey keyByteString = case P256.pointFromBinary keyByteString of
  CryptoPassed key -> Just $ ECDSA.PublicKey ourCurve $ Point (fst $ P256.pointToIntegers key) (snd $ P256.pointToIntegers key)
  CryptoFailed err -> Nothing

-- URL-friendly base64 encoding may or may not contain padding. Delete it here
-- https://tools.ietf.org/html/rfc4648#section-3.2
formatOutputBase64 :: BS.ByteString -> T.Text
formatOutputBase64 byteString = T.replace (T.pack "=") (T.pack "") (decodeUtf8 $ encode byteString)

verifySignature :: BS.ByteString -> ECDSA.PublicKey -> ECDSA.Signature -> Bool
verifySignature sigBase pubKey signature = ECDSA.verify Crypto.Hash.Algorithms.SHA256 pubKey signature sigBase

u2fComparator :: (Eq a) => a -> a -> U2FError -> Either U2FError Bool
u2fComparator firstThing secondThing theError = case (firstThing == secondThing) of
    True -> Right True
    False -> Left theError

unpackRegistrationData :: Get RegistrationData
unpackRegistrationData = do
  reserved <- getByteString 1
  publicKey <- getByteString 65
  keyHandleLen <- getWord8
  keyHandle <- getByteString $ fromIntegral keyHandleLen
  cert <- unpackASN1
  sign <- unpackASN1
  return $ RegistrationData reserved publicKey keyHandle cert sign

unpackSignatureData :: Get SignatureData
unpackSignatureData = do
  userPresenceFlag <- getByteString 1
  counter <- getByteString 4
  signature <- unpackASN1
  return $ SignatureData userPresenceFlag counter signature

unpackASN1 :: Get BS.ByteString
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
