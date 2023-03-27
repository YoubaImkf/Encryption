using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace EncryptFile
{
    /* LOGIC :
     * Encrypt a Aes key using RSA algorithm,
     * then encrypt the inputData using the encrypted Aes key using Aes algorithm
     */
    // SOURCES :
    // https://stackoverflow.com/questions/8417993/rsa-encryption-of-large-data-in-c-sharp
    // https://stackoverflow.com/questions/11533105/aes-gcm-manual-byte-concatenation-of-iv-and-tag-to-encrypted-information
    public class AesRsaEncrypt
    {
        #region -- KEYS ---

        private const string publicKey = "<RSAKeyValue><Modulus>ZJTqfYKHi4KOj2TGBhQ/SYifZC27fuYJjTtPr7DoKuyyv1eskGlEJ4+BLYZU9oXc5AZ+do90RdvltNF/VTxGRWJFQYYJoFkbEgeiR5tFmwDp23O5dwbWMEVrjk3hWkxoxVwj0GBfwgA62TA0MlszNM993CA4HC5al0PS8HkYiSi79gcILH93i701oPJAkH65F7IGSeyNM6JGsHcgtEdsheYN2BITuJEXPlJXhKeLVD/62G6qG4GPT9BQJdgLK43iyhwUOTPk1uK52Plb2p9ZwM1oAb6S2xLlw58OYh7lZPypLylm3gDk+pLKOEEDSCu+jFU1oZLBcexCI8BM9mJLrw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

        private const string privateKey = "<RSAKeyValue><Modulus>ZJTqfYKHi4KOj2TGBhQ/SYifZC27fuYJjTtPr7DoKuyyv1eskGlEJ4+BLYZU9oXc5AZ+do90RdvltNF/VTxGRWJFQYYJoFkbEgeiR5tFmwDp23O5dwbWMEVrjk3hWkxoxVwj0GBfwgA62TA0MlszNM993CA4HC5al0PS8HkYiSi79gcILH93i701oPJAkH65F7IGSeyNM6JGsHcgtEdsheYN2BITuJEXPlJXhKeLVD/62G6qG4GPT9BQJdgLK43iyhwUOTPk1uK52Plb2p9ZwM1oAb6S2xLlw58OYh7lZPypLylm3gDk+pLKOEEDSCu+jFU1oZLBcexCI8BM9mJLrw==</Modulus><Exponent>AQAB</Exponent><P>xi6E2q93syvU5iOWMbLCOxgvEwt7y8dA2bu6rDUH1XglaIN+1VkxVGONZUcZVtcQ9mQAIaVwUsgZghkozh/I4S0r1xAKmMPqPvZioP95t4cyTexE0uYuY9Q4hzmBiXcanNvCjTu8YE+MfLU74dB9Lwi67SpzxxIOAS7kumDj0TE=</P><Q>ge0AngE4U6HbjuxY47bkNlA9dSPdgqUX3Ul58kw1DMllpAiA51a/TrsROIOolClRKOLIOSKXIeQC7tGDKWqqSysHfD4QVfU1kmHSKOyGrLSoYi/9nn3eZs0Usc31QpQHBZ/FJMvmQtUCOgOQGgR6m63l2WHvl7OO0Rag0Qlrst8=</Q><DP>ZZlnpq0aEpK//JP15dic1qrZR0w11Qx7ZKRnWO1+7KNBmkj/duTY80huLqO6i9iJ66bsolMsOGQ5H4dCchm9ZCNCPGkO5a5aopixi5QtlDcNRQGBbxVuZuNfb4O9svmKfSv0m28qbb2aajyHTIcUBk7VdcyzujS5VUXzINGXOaE=</DP><DQ>GQRUiRf9C4Vv7D4wA3C00oxyuPp17XDyfmZmd7QaxuKEkqgcge7fGT7F2xbmv9iQywmXugCiDyGDOw7WbYQfVCft4gtlQ9faP9xcBgs9B0Yl4foRoJHl3+9/G5lnrzEnhPq1kBc+uAGh0x/agFf6b711M307D/+/8RylTHq+5Qs=</DQ><InverseQ>r0nq/kZaivNTbl0fUVg2mNH6bgQG9Q39nb3u2W/15+hCXMc9+FE7e2sUSEMqfqXYrdAmVF/ytOhE9dODy+h0pTWctxGMOIHXBPRgZpCOmdr8OFXPwSKWLx/hZEh6H/SH7GJsuo8MAGfD+3roYhSHR6b+5+5ll44f1ggD0HWn50o=</InverseQ><D>Tp8I3KrXgPnArd273Kye+7/Lt+b3lK4D8V3XYCIMmOEEqATEYu2l1Lab5xYF+92PWL6qw8pGvQSyfbD0s4+17i5urFU12R1Nx74n34lD03HXWy8OXjf93SWmeUnvSUJI81yeshdjQqYjWfoQEvyu/izi2NpmgcDKF0tw63/86djo+ngjzEfOfQBC1hd/95FAF4VemS9X9zdNEjWeyH8IrX3lea0sUxX5L36xQtp3hJb7NtKlVz8u65+CcyJ1BY1353pksmCEoablTyJYYAnpKM8BaGSrU/p141HMUFzt1AsdJfTVAmwTUlNFWnAELs0BYJ715b1wh/hgHXoYKIHVgQ==</D></RSAKeyValue>";

        private static readonly byte[] aesKey = Encoding.UTF8.GetBytes("Zy0B&E)s@McH:TjmnZq4t7w!z%C*P-Ja");
        #endregion
        private const int IvLength = 16; // to randomize the first block

        public static byte[] EncryptDataUsingAes(byte[] plainData)
        {

            using var aes = Aes.Create();
            aes.Key = aesKey;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            byte[] iv = GenerateRandomBytes(IvLength);
            aes.IV = iv;

            // Encrypt the AES key using RSA
            using var rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(publicKey);

            byte[] aesKeyEncrypted = rsa.Encrypt(aes.Key, RSAEncryptionPadding.Pkcs1);

            // Combine the encrypted AES key and the IV into a single array
            byte[] encryptedAesKeyAndIv = new byte[aesKeyEncrypted.Length + aes.IV.Length];
            aesKeyEncrypted.CopyTo(encryptedAesKeyAndIv, 0); // copied to the beginning
            aes.IV.CopyTo(encryptedAesKeyAndIv, aesKeyEncrypted.Length); // copied to the end of the array

            // Encrypt the data using AES
            using MemoryStream ms = new();
            using CryptoStream cs = new(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);
            cs.Write(plainData, 0, plainData.Length);
            cs.FlushFinalBlock();

            byte[] encryptedBytes = ms.ToArray();

            // Combine the encrypted AES key and IV with the encrypted data
            byte[] result = new byte[encryptedAesKeyAndIv.Length + encryptedBytes.Length];
            encryptedAesKeyAndIv.CopyTo(result, 0); // copy the contents of the encrypted AES key and IV array into the result 
            encryptedBytes.CopyTo(result, encryptedAesKeyAndIv.Length); // copy the contents of the encrypted data array into the result

            return result;
        }


        public static byte[] DecryptDataUsingAes(byte[] encryptedData)
        {
            using var rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(privateKey);

            byte[] aesKeyEncrypted = new byte[rsa.KeySize / 8]; // convert bits to byte
            Array.Copy(encryptedData, aesKeyEncrypted, aesKeyEncrypted.Length);

            byte[] aesKey = rsa.Decrypt(aesKeyEncrypted, RSAEncryptionPadding.Pkcs1);

            byte[] iv = new byte[16]; // extract IV
            Array.Copy(encryptedData, aesKeyEncrypted.Length, iv, 0, iv.Length);

            using Aes aes = Aes.Create();
            aes.Key = aesKey;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using MemoryStream ms = new();
            using CryptoStream cs = new(ms, aes.CreateDecryptor(), CryptoStreamMode.Write); // Decrypt the data using AES
            cs.Write(encryptedData, aesKeyEncrypted.Length + iv.Length, encryptedData.Length - aesKeyEncrypted.Length - iv.Length); // Extracts the encrypted data and write it
            cs.FlushFinalBlock();

            return ms.ToArray();
        }

        private static byte[] GenerateRandomBytes(int length)
        {
            using RandomNumberGenerator rng = RandomNumberGenerator.Create();
            byte[] bytes = new byte[length];
            rng.GetBytes(bytes);
            return bytes;
        }

    }
}
