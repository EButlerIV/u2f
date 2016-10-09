import Test.Hspec
import U2F
import U2F.Types
import Data.Either.Unwrap (fromRight)
import qualified Data.ByteString.Char8 as BS
import qualified Data.Text as T

rawRegRequest :: String
rawRegRequest = "{\"appId\":\"https://localhost:4000\",\"version\":\"U2F_V2\",\"challenge\":\"7uy5uxqHXeCGg7K1cWmO3bVlr_KY1U5dQkPP_wOvlWg\",\"keyHandle\":\"9Hgjem2ZlnKKuKVnHepmuSzMHnoyCX0idccYCwztgtpXllNSr-xv_oSuQnyVCN8HYa5JgIsawOxhtp0CIIcBGQ\"}"
registrationRequest :: Request
registrationRequest = Request (T.pack "https://localhost:4000") (T.pack "U2F_V2") (T.pack "7uy5uxqHXeCGg7K1cWmO3bVlr_KY1U5dQkPP_wOvlWg") Nothing
registrationResponse :: Registration
registrationResponse = fromRight $ parseRegistration "{\"registrationData\":\"BQQ65jfw5zT6MqdV81UYQ6btGV-dK8wRyxAGuYcFAKvFp1HubXnyI9wG5Vw8zdmE8sjBNK58GNrJ3woQ-e_nnV9kQPR4I3ptmZZyirilZx3qZrkszB56Mgl9InXHGAsM7YLaV5ZTUq_sb_6ErkJ8lQjfB2GuSYCLGsDsYbadAiCHARkwggJEMIIBLqADAgECAgR4wN8OMAsGCSqGSIb3DQEBCzAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowKjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMjAyNTkwNTkzNDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLW4cVyD_f4OoVxFd6yFjfSMF2_eh53K9Lg9QNMg8m-t5iX89_XIr9g1GPjbniHsCDsYRYDHF-xKRwuWim-6P2-jOzA5MCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4xMBMGCysGAQQBguUcAgEBBAQDAgUgMAsGCSqGSIb3DQEBCwOCAQEAPvar9kqRawv5lJON3JU04FRAAmhWeKcsQ6er5l2QZf9h9FHOijru2GaJ0ZC5UK8AelTRMe7wb-JrTqe7PjK3kgWl36dgBDRT40r4RMN81KhfjFwthw4KKLK37UQCQf2zeSsgdrDhivqbQy7u_CZYugkFxBskqTxuyLum1W8z6NZT189r1QFUVaJll0D33MUcwDFgnNA-ps3pOZ7KCHYykHY_tMjQD1aQaaElSQBq67BqIaIU5JmYN7Qp6B1-VtM6VJLdOhYcgpOVQIGqfu90nDpWPb3X26OVzEc-RGltQZGFwkN6yDrAZMHL5HIn_3obd8fV6gw2fUX2ML2ZjVmybjBEAiBGwwt4P70-8E1KmmKQBtVQkvi-w16gSYLECB68b8nDNgIgCiRB1ATDXuWQ7m2DfNnsEq3bs3haITTa4ssHWB8PG-0\",\"challenge\":\"7uy5uxqHXeCGg7K1cWmO3bVlr_KY1U5dQkPP_wOvlWg\",\"version\":\"U2F_V2\",\"appId\":\"https://localhost:4000\",\"sessionId\":\"444\",\"clientData\":\"eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6Ijd1eTV1eHFIWGVDR2c3SzFjV21PM2JWbHJfS1kxVTVkUWtQUF93T3ZsV2ciLCJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdDo0MDAwIiwiY2lkX3B1YmtleSI6InVudXNlZCJ9\"}"

signinRequest :: Request
signinRequest = Request (T.pack "https://localhost:4000") (T.pack "U2F_V2") (T.pack "7uy5uxqHXeCGg7K1cWmO3bVlr_KY1U5dQkPP_wOvlWg") (Just $ T.pack "9Hgjem2ZlnKKuKVnHepmuSzMHnoyCX0idccYCwztgtpXllNSr-xv_oSuQnyVCN8HYa5JgIsawOxhtp0CIIcBGQ")
signinResponse :: Signin
signinResponse = fromRight $ parseSignin "{\"keyHandle\":\"9Hgjem2ZlnKKuKVnHepmuSzMHnoyCX0idccYCwztgtpXllNSr-xv_oSuQnyVCN8HYa5JgIsawOxhtp0CIIcBGQ\",\"clientData\":\"eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiwiY2hhbGxlbmdlIjoiN3V5NXV4cUhYZUNHZzdLMWNXbU8zYlZscl9LWTFVNWRRa1BQX3dPdmxXZyIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0OjQwMDAiLCJjaWRfcHVia2V5IjoidW51c2VkIn0\",\"signatureData\":\"AQAAAAAwRgIhAI4jLgLewiaFzuyyuaxlToF1OHmkItaOeASUtIStic5HAiEA8X16pOe_Sugk8O8AAh2iQdlx_98cR9UwwCwDmr_bbXo\"}"
signinSavedPubkey :: BS.ByteString
signinSavedPubkey = BS.pack "\EOT:\230\&7\240\231\&4\250\&2\167U\243U\CANC\166\237\EM_\157+\204\DC1\203\DLE\ACK\185\135\ENQ\NUL\171\197\167Q\238my\242#\220\ACK\229\\<\205\217\132\242\200\193\&4\174|\CAN\218\201\223\n\DLE\249\239\231\157_d"

main :: IO ()
main = hspec $ do
  describe "Request/Response Parsing" $ do
    it "should work for registration requests" $ do
      regRequest <- pure $ fromRight $ parseRequest rawRegRequest
      (appId regRequest) `shouldBe` (T.pack "https://localhost:4000")

  describe "Registration Flow" $ do
    it "should check that request and response challenges are equivalent" $ do
      registrationVerificationFail <- return $ do
            registration <- pure $ registrationResponse {registration_challenge = (T.pack "")}
            verifyRegistration registrationRequest registration
      registrationVerificationFail `shouldBe` (Left ChallengeMismatchError)

    it "should validate properly formed request and response" $ do
      registrationVerificationSuccess <- return $ do
            verifyRegistration registrationRequest registrationResponse
      --TODO: Find a better way to test for this
      (registrationVerificationSuccess) `shouldBe` (Right $ fromRight registrationVerificationSuccess)

  describe "Signin Flow" $ do
    it "should check that request and response challenges are equivalent" $ do
      signinVerificationFail <- return $ do
            signinRequest <- pure $ signinRequest {challenge = (T.pack "")}
            verifySignin signinSavedPubkey signinRequest signinResponse
      signinVerificationFail `shouldBe` (Left ChallengeMismatchError)

    it "should validate properly formed request and response" $ do
      signinVerificationSuccess <- return $ verifySignin signinSavedPubkey signinRequest signinResponse
      --TODO: Find a better way to test for this
      (signinVerificationSuccess) `shouldBe` (Right $ fromRight signinVerificationSuccess)
