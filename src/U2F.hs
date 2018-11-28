{-# LANGUAGE DeriveGeneric #-}

{- |
  __HOW TO USE__

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
module U2F
  (
    parseRequest,
    parseRegistration,
    parseRegistrationData,
    verifyRegistration,
    parseSignin,
    parseClientData,
    verifySignin,
    formatOutputBase64
  )where
import U2F.Types

import Data.Bits

import Data.ASN1.BitArray
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ASN1.Types

import qualified Data.ByteString.Lazy.Char8 as LBS
import qualified Data.ByteString.Char8 as BS

import Data.Aeson (decode)
import Data.Binary.Get

import Data.ByteString (pack)
import Data.ByteString.Base64.URL (encode, decodeLenient)

import Data.List

import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8, decodeUtf8)

import qualified Crypto.Hash.SHA256 as SHA256

-- Cryptonite stuff
import Crypto.Error
import Crypto.PubKey.ECC.Types
import qualified Crypto.PubKey.ECC.P256 as P256
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import Crypto.Hash.Algorithms

-- | The U2F Spec (currently) exclusively supports use of the SEC p256r Curve
ourCurve :: Curve
ourCurve = getCurveByName SEC_p256r1

-- | Parses Registration or Signin Request JSON
parseRequest :: String -> Either U2FError Request
parseRequest x = case (Data.Aeson.decode (LBS.pack x) :: Maybe Request) of
  Just request -> Right request
  Nothing -> Left RequestParseError

-- | Parses Registration response JSON
parseRegistration :: String -> Either U2FError Registration
parseRegistration x = case (Data.Aeson.decode (LBS.pack x) :: Maybe Registration) of
  Just registration -> Right registration
  Nothing -> Left RegistrationParseError

-- | Parses base64-encoded bytestring in Registration response
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
  -- Eventually check to make sure this is not compressed, in right format
  Just (BitString (BitArray _ x)) -> parsePublicKey $ BS.tail x
  _ -> Nothing

pubKeyShape :: ASN1 -> Bool
pubKeyShape (BitString (BitArray len _)) = len == 520
pubKeyShape _ = False

formatSignatureBase :: BS.ByteString -> BS.ByteString -> BS.ByteString -> BS.ByteString -> BS.ByteString
formatSignatureBase _appId clientData _keyHandle publicKey = sigBase
  where sigBase = BS.concat([BS.pack "\NUL", SHA256.hash(_appId), SHA256.hash(decodeLenient clientData), _keyHandle, publicKey])

getSignatureBaseFromRegistration :: Registration -> RegistrationData -> BS.ByteString
getSignatureBaseFromRegistration registration registrationData = formatSignatureBase aId clientData kH publicKey
  where aId = encodeUtf8 $ registration_appId registration
        clientData = encodeUtf8 $ registration_clientData registration
        kH = registrationData_keyHandle registrationData
        publicKey = registrationData_publicKey registrationData

-- | Verifies that Registration is a valid response to the Request
verifyRegistration :: Request -> Registration -> Either U2FError Request
verifyRegistration request registration = do
  _ <- u2fComparator (challenge request) (registration_challenge registration) ChallengeMismatchError
  registrationData <- parseRegistrationData $ encodeUtf8 $ registration_registrationData registration
  pkey <- getPubKeyFromCertificate $ registrationData_certificate registrationData
  signature <- parseSignature $ registrationData_signature registrationData
  let signatureBase = getSignatureBaseFromRegistration registration registrationData
  case (verifySignature signatureBase pkey signature) of
    True -> Right (request {keyHandle = Just $ formatOutputBase64 $ registrationData_keyHandle registrationData})
    False -> Left FailedVerificationError

-- | Parses Signin response JSON
parseSignin :: String -> Either U2FError Signin
parseSignin x = case (Data.Aeson.decode (LBS.pack x) :: Maybe Signin) of
  Just signin -> Right signin
  Nothing -> Left SigninParseError

-- | Parses base64-encoded client data bytestring inside Signin response
parseClientData :: BS.ByteString -> Either U2FError ClientData
parseClientData x = case (Data.Aeson.decode (LBS.fromStrict $ decodeLenient x) :: Maybe ClientData) of
  Just clientData -> Right clientData
  Nothing -> Left ClientDataParseError

-- | Verifies that Signin response is valid given saved pubkey bytestring, request
verifySignin :: BS.ByteString -> Request -> Signin -> Either U2FError Bool
verifySignin savedPubkey request signin = do
  clientData <- parseClientData $ encodeUtf8 $ signin_clientData signin
  _ <- u2fComparator (challenge request) (clientData_challenge clientData) ChallengeMismatchError
  signatureData <- parseSignatureData $ encodeUtf8 $ signin_signatureData signin
  signature <- parseSignature $ signatureData_signature signatureData
  let signatureBase = getSigninSignatureBase request signin signatureData
  -- So Gross. TODO: write function that checks first byte for compression state, parses each pubkey format
  publicKey <- case (parsePublicKey $ BS.tail $ savedPubkey) of
    Just key -> Right key
    Nothing -> Left PubKeyParsingError
  case (verifySignature signatureBase publicKey signature) of
    True -> Right True
    False -> Left FailedVerificationError

parseSignatureData :: BS.ByteString -> Either U2FError SignatureData
parseSignatureData s = Right $ runGet unpackSignatureData ( LBS.fromStrict $ decodeLenient s)

parseSignature :: BS.ByteString -> Either U2FError ECDSA.Signature
parseSignature possibleSig = case (decodeASN1' DER possibleSig) of
  Right ([_, IntVal r, IntVal s, _]) -> Right $ ECDSA.Signature r s
  _ -> Left SignatureParseError

getSigninSignatureBase :: Request -> Signin -> SignatureData -> BS.ByteString
getSigninSignatureBase request signin signatureData = BS.concat([SHA256.hash(aId), userPresenceFlag, counter, SHA256.hash(decodeLenient clientData)])
  where aId = encodeUtf8 $ appId request
        userPresenceFlag = signatureData_userPresenceFlag signatureData
        counter = signatureData_counter signatureData
        clientData = encodeUtf8 $ signin_clientData signin

parsePublicKey :: BS.ByteString -> Maybe ECDSA.PublicKey
parsePublicKey keyByteString = case P256.pointFromBinary keyByteString of
  CryptoPassed key -> Just $ ECDSA.PublicKey ourCurve $ Point (fst $ P256.pointToIntegers key) (snd $ P256.pointToIntegers key)
  CryptoFailed _ -> Nothing

-- | URL-friendly base64 encoding may or may not contain padding. (https://tools.ietf.org/html/rfc4648#section-3.2).
--   We remove it here.
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
  kH <- getByteString $ fromIntegral keyHandleLen
  cert <- unpackASN1
  sign <- unpackASN1
  return $ RegistrationData reserved publicKey kH cert sign

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
