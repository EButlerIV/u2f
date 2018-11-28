{-# LANGUAGE DeriveGeneric #-}

module U2F.Types where

import GHC.Generics
import qualified Data.Text as T
import qualified Data.ByteString.Char8 as BS
import Data.Aeson (FromJSON(..),
  ToJSON(..), genericParseJSON, genericToJSON,  defaultOptions)
import Data.Aeson.Types (fieldLabelModifier)

data U2FError =
  RegistrationParseError            |
  RegistrationDataParseError        |
  RegistrationCertificateParseError |
  PubKeyParsingError                |
  SignatureParseError               |
  ChallengeMismatchError            |
  FailedVerificationError           |
  SigninParseError                  |
  ClientDataParseError              |
  RequestParseError                 |
  RegisterRequestParseError
  deriving (Show, Eq)

data Transport =  BT  | -- ^ Bluetooth Classic (Bluetooth BR/EDR)
                  BLE | -- ^ Bluetooth Low Energy (Bluetooth Smart)
                  NFC | -- ^ Near-Field Communications
                  USB   -- ^ USB HID (Human Interface Device)
  deriving (Show, Eq)

-- | Generic request for old version of protocol. Probably want to remove
data Request = Request {
  appId :: T.Text,
  version :: T.Text,
  challenge :: T.Text,
  keyHandle :: Maybe T.Text
} deriving (Show, Generic, Eq)
instance FromJSON Request
instance ToJSON Request

data RegisterRequest = RegisterRequest {
  registerRequest_version :: T.Text, -- Will probably be 'U2F_V2'
  registerRequest_challenge :: T.Text
} deriving (Show, Generic)
instance ToJSON RegisterRequest where
  toJSON = genericToJSON defaultOptions {
                fieldLabelModifier = Prelude.drop 16 }
instance FromJSON RegisterRequest where
  parseJSON = genericParseJSON defaultOptions {
                fieldLabelModifier = Prelude.drop 16 }

data RegisteredKey = RegisteredKey {
  registeredKey_version :: T.Text,
  registeredKey_keyHandle :: T.Text,
  registeredKey_transports :: Maybe [Transport],
  registeredKey_appId :: Maybe T.Text
} deriving (Show, Generic, Eq)

-- Register Flow --

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
