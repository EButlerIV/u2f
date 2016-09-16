import Test.Hspec
import Control.Exception (evaluate)
import U2F
import Data.Maybe
import qualified Data.ByteString.Char8 as BS
import qualified Data.Text as T

rawRegRequest = "{\"appId\":\"https://localhost:4000\",\"version\":\"U2F_V2\",\"challenge\":\"7uy5uxqHXeCGg7K1cWmO3bVlr_KY1U5dQkPP_wOvlWg\",\"keyHandle\":\"9Hgjem2ZlnKKuKVnHepmuSzMHnoyCX0idccYCwztgtpXllNSr-xv_oSuQnyVCN8HYa5JgIsawOxhtp0CIIcBGQ\"}"
registrationRequest = Request (T.pack "https://localhost:4000") (T.pack "U2F_V2") (T.pack "7uy5uxqHXeCGg7K1cWmO3bVlr_KY1U5dQkPP_wOvlWg") Nothing
registrationResponse = justRight $ parseRegistration "{\"registrationData\":\"BQQ65jfw5zT6MqdV81UYQ6btGV-dK8wRyxAGuYcFAKvFp1HubXnyI9wG5Vw8zdmE8sjBNK58GNrJ3woQ-e_nnV9kQPR4I3ptmZZyirilZx3qZrkszB56Mgl9InXHGAsM7YLaV5ZTUq_sb_6ErkJ8lQjfB2GuSYCLGsDsYbadAiCHARkwggJEMIIBLqADAgECAgR4wN8OMAsGCSqGSIb3DQEBCzAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowKjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMjAyNTkwNTkzNDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLW4cVyD_f4OoVxFd6yFjfSMF2_eh53K9Lg9QNMg8m-t5iX89_XIr9g1GPjbniHsCDsYRYDHF-xKRwuWim-6P2-jOzA5MCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4xMBMGCysGAQQBguUcAgEBBAQDAgUgMAsGCSqGSIb3DQEBCwOCAQEAPvar9kqRawv5lJON3JU04FRAAmhWeKcsQ6er5l2QZf9h9FHOijru2GaJ0ZC5UK8AelTRMe7wb-JrTqe7PjK3kgWl36dgBDRT40r4RMN81KhfjFwthw4KKLK37UQCQf2zeSsgdrDhivqbQy7u_CZYugkFxBskqTxuyLum1W8z6NZT189r1QFUVaJll0D33MUcwDFgnNA-ps3pOZ7KCHYykHY_tMjQD1aQaaElSQBq67BqIaIU5JmYN7Qp6B1-VtM6VJLdOhYcgpOVQIGqfu90nDpWPb3X26OVzEc-RGltQZGFwkN6yDrAZMHL5HIn_3obd8fV6gw2fUX2ML2ZjVmybjBEAiBGwwt4P70-8E1KmmKQBtVQkvi-w16gSYLECB68b8nDNgIgCiRB1ATDXuWQ7m2DfNnsEq3bs3haITTa4ssHWB8PG-0\",\"challenge\":\"7uy5uxqHXeCGg7K1cWmO3bVlr_KY1U5dQkPP_wOvlWg\",\"version\":\"U2F_V2\",\"appId\":\"https://localhost:4000\",\"sessionId\":\"444\",\"clientData\":\"eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6Ijd1eTV1eHFIWGVDR2c3SzFjV21PM2JWbHJfS1kxVTVkUWtQUF93T3ZsV2ciLCJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdDo0MDAwIiwiY2lkX3B1YmtleSI6InVudXNlZCJ9\"}"
registrationGoodSig = BS.pack "0D\STX F\195\vx?\189>\240MJ\154b\144\ACK\213P\146\248\190\195^\160I\130\196\b\RS\188o\201\195\&6\STX \n$A\212\EOT\195^\229\144\238m\131|\217\236\DC2\173\219\179xZ!4\218\226\203\aX\US\SI\ESC\237"
registrationGoodSigBase = BS.pack "\NUL\219\214S\135\176*\251\174\&8J\132g\177\209\ETX\192y\136s/L\136si\RSA\255\140\184/%\129Q\208\243\CAN!\204\&1\202\144j\153\246\&4\171\SOH\251@\165\244%\202=\ETB>\217\160\a\STX!\158\246W\244x#zm\153\150r\138\184\165g\GS\234f\185,\204\RSz2\t}\"u\199\CAN\v\f\237\130\218W\150SR\175\236o\254\132\174B|\149\b\223\aa\174I\128\139\SUB\192\236a\182\157\STX \135\SOH\EM\EOT:\230\&7\240\231\&4\250\&2\167U\243U\CANC\166\237\EM_\157+\204\DC1\203\DLE\ACK\185\135\ENQ\NUL\171\197\167Q\238my\242#\220\ACK\229\\<\205\217\132\242\200\193\&4\174|\CAN\218\201\223\n\DLE\249\239\231\157_d"

signinRequest = Request (T.pack "https://localhost:4000") (T.pack "U2F_V2") (T.pack "7uy5uxqHXeCGg7K1cWmO3bVlr_KY1U5dQkPP_wOvlWg") (Just $ T.pack "9Hgjem2ZlnKKuKVnHepmuSzMHnoyCX0idccYCwztgtpXllNSr-xv_oSuQnyVCN8HYa5JgIsawOxhtp0CIIcBGQ")
signinResponse = justRight $ parseSignin "{\"keyHandle\":\"9Hgjem2ZlnKKuKVnHepmuSzMHnoyCX0idccYCwztgtpXllNSr-xv_oSuQnyVCN8HYa5JgIsawOxhtp0CIIcBGQ\",\"clientData\":\"eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiwiY2hhbGxlbmdlIjoiN3V5NXV4cUhYZUNHZzdLMWNXbU8zYlZscl9LWTFVNWRRa1BQX3dPdmxXZyIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0OjQwMDAiLCJjaWRfcHVia2V5IjoidW51c2VkIn0\",\"signatureData\":\"AQAAAAAwRgIhAI4jLgLewiaFzuyyuaxlToF1OHmkItaOeASUtIStic5HAiEA8X16pOe_Sugk8O8AAh2iQdlx_98cR9UwwCwDmr_bbXo\"}"
signinSavedPubkey = BS.pack "\EOT:\230\&7\240\231\&4\250\&2\167U\243U\CANC\166\237\EM_\157+\204\DC1\203\DLE\ACK\185\135\ENQ\NUL\171\197\167Q\238my\242#\220\ACK\229\\<\205\217\132\242\200\193\&4\174|\CAN\218\201\223\n\DLE\249\239\231\157_d"
justRight (Right x) = x

main :: IO ()
main = hspec $ do
  describe "Request/Response Parsing" $ do
    it "should work for registration requests" $ do
      regRequest <- pure $ justRight $ parseRequest rawRegRequest
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
      (registrationVerificationSuccess) `shouldBe` (Right $ justRight registrationVerificationSuccess)

  describe "Signin Flow" $ do
    it "should check that request and response challenges are equivalent" $ do
      signinVerificationFail <- return $ do
            signinRequest <- pure $ signinRequest {challenge = (T.pack "")}
            verifySignin signinSavedPubkey signinRequest signinResponse
      signinVerificationFail `shouldBe` (Left ChallengeMismatchError)

    it "should validate properly formed request and response" $ do
      signinVerificationSuccess <- return $ do
            verifySignin signinSavedPubkey signinRequest signinResponse
      --TODO: Find a better way to test for this
      (signinVerificationSuccess) `shouldBe` (Right $ justRight signinVerificationSuccess)
