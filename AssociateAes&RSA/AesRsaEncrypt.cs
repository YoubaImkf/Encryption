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
    // https://stackoverflow.com/questions/1220751/how-to-choose-an-aes-encryption-mode-cbc-ecb-ctr-ocb-cfb?rq=2
    public class AesRsaEncrypt
    {
        #region -- KEYS ---

        private const string publicKey = "-----BEGIN PUBLIC KEY-----\r\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAmPiPsQ1KsBWqa5pIQOMQ\r\noM/APrxaVn/1nnzp8/T2i6xvSQYPTgIVrToUJ263G+e4vPNMoDnnyAXBjfGdu0Oz\r\n50G8L64DfJm5S7XpgEqwJM5Jz/eDrUtGwkTN1IC7soNVfURPkgnrh1fk+WsZF6PX\r\nnuvOF1BmmeIAcg01fieF9DOsfhdwhq65xhLgdeHWldtDRJeNkIqG2nXPZvUbQ/5J\r\nhvnu4/BDl3t/RDYlfWKoteCki1wLZGR/NoFMRea+/8eyj4ZQYaZcTKXBIgUHaWWP\r\n+daKwuUf1rSQmX/wvSSmtESCIrhkiHI/smTrJDYXBTJtXM0rS43bkSUzsUGAnrRB\r\nBqXnbnW2qfnFxw0W6GlPi8Eiftpc7G4CfmymI7Vq04AyNA1pcH07M+7OBiTvlX4Q\r\nITWfXMH7CrAVBsn6YfzI6n5EAedlnHa8pkN8+mp+qewequr+Zt3lMNEisUau7doD\r\nu9+ZfWW4qWgJLTa9k6EFF1cPGGf8WotFmABTvWnUEXF+et/nWMro01xS3T6WKWNe\r\nqsgHPRMvn9QznKFhjhyWfAed3gFd/DR6b0FWmw4gcTkCZ3SvyTOmvzalTmdg0Rxw\r\nc6dIZ9nLKl/JXAbTTXcpYuWf+Td5EvUvHC0SIWidSvCVYEw0Vxuf1u36RoSu1AKl\r\nf6q4PRADR/dXuDe8TH1XuVUCAwEAAQ==\r\n-----END PUBLIC KEY-----";

        private const string privateKey = "-----BEGIN RSA PRIVATE KEY-----\r\nMIIJKAIBAAKCAgEAmPiPsQ1KsBWqa5pIQOMQoM/APrxaVn/1nnzp8/T2i6xvSQYP\r\nTgIVrToUJ263G+e4vPNMoDnnyAXBjfGdu0Oz50G8L64DfJm5S7XpgEqwJM5Jz/eD\r\nrUtGwkTN1IC7soNVfURPkgnrh1fk+WsZF6PXnuvOF1BmmeIAcg01fieF9DOsfhdw\r\nhq65xhLgdeHWldtDRJeNkIqG2nXPZvUbQ/5Jhvnu4/BDl3t/RDYlfWKoteCki1wL\r\nZGR/NoFMRea+/8eyj4ZQYaZcTKXBIgUHaWWP+daKwuUf1rSQmX/wvSSmtESCIrhk\r\niHI/smTrJDYXBTJtXM0rS43bkSUzsUGAnrRBBqXnbnW2qfnFxw0W6GlPi8Eiftpc\r\n7G4CfmymI7Vq04AyNA1pcH07M+7OBiTvlX4QITWfXMH7CrAVBsn6YfzI6n5EAedl\r\nnHa8pkN8+mp+qewequr+Zt3lMNEisUau7doDu9+ZfWW4qWgJLTa9k6EFF1cPGGf8\r\nWotFmABTvWnUEXF+et/nWMro01xS3T6WKWNeqsgHPRMvn9QznKFhjhyWfAed3gFd\r\n/DR6b0FWmw4gcTkCZ3SvyTOmvzalTmdg0Rxwc6dIZ9nLKl/JXAbTTXcpYuWf+Td5\r\nEvUvHC0SIWidSvCVYEw0Vxuf1u36RoSu1AKlf6q4PRADR/dXuDe8TH1XuVUCAwEA\r\nAQKCAgAY4k5VqejdbhjT+jwIuidJUaJfUjqL2bL1/jH8qnu0yu8rfN3efb5S+KCw\r\nrXUCCBboPdfYNLM8uZr74TMcdG3+j5XyV6dfjI40/7mlUgEHa7tcJlJ4TUeMcK7f\r\nA7YE2xJ8FzGuewiicqzf2gkx7Eg2JPvYlQ6rt7UE2Js8E2faCtHjjSKT9jZoP0fe\r\nRUeoBwwRS2oO+knnncSIZhTyYZpKZ7vxvnLwYHmaeghtNjBlrc52kRmVUjfTgQMM\r\nV/X4G98zM9E9oVdgbJJXW2QSRCBAryLRg35Dagofvk1GJ4Eqz/4vcbmA7Lzp4zrR\r\nIC9sfACIWSPS3Ze7K8cV7abjqkTtdItjgUbpz29STEWn4g2iLFhvan+UAkL/Tr8z\r\nFFUkJq4RWSclw2Qw/KWifkyCCZVlKAX3Rzn9lSrScdz8uTBx7nIBJMkHds7Rh1MA\r\nOgNjEFxoBmK1dbSKxQYiTEeZjVYgR8BoE0KsyOeR9rJj+jZDAjG61iSi7m1Buq1x\r\nPKmGX3Te+X2bXAe6wBXGvUnY4egFr1wCbirioZs0X3ZEajRkjgAL+a5AvtVoXUgi\r\nd2MkiFxnwTz8GMjSNIcVuC6gvbC5fOROEFl8TAjO4LrKZOvRLSdntSbcxr27RILY\r\nEocZgpkLDvsHnY1iTusJ7KiQeCV8ubfhWX8Hss9mSE0y9OqVQQKCAQEAxmgtE4Ze\r\nyGMg5W+sqXu8yOOxL0SdcotOliCAxtKyKDdPx0mLrkp/9KdKHcueMUV1Tyst0M6r\r\nsnks1WA0cguPiaya4pcmCd1N0nOuqFCLFCdRBNKX46VCmTsi/Y6EWHy16BYw7P2t\r\nLA08ALdQQ3+6HmLH8ve4f9F/D6iZ0pAOvhL2sanmYpoXPzWWEtu7SRIlZtaeZOIH\r\nDPfMfy8xhXC+w/jUUU+ugJPWN3ckFgC/ceHab3O/Ic0XfU/pgCasV/2gxUyn1TW+\r\nsXnq27nxlSGJ7tBhEC4NzwFBoHeErci3Hsyp1JA2/mP75zy3O1MLePR2n40/sHFY\r\n5hDsZTjjlZXmBQKCAQEAxV/9VuSB4rdlf5CoXbLn0st50UBZgPPMpb1sGR2U35Mn\r\n6Z2UHNCQnDj08JGHNMrk0wxw5od648Lny1yqycsKJ7dTQuY6r3ofpeAsQOF4TBSj\r\nMOe8bgPjIokU9pjjX0sAKKBh3/3DgJR/mas9FWGB/3siqvahuyZ8BLDndd6gurCj\r\ngjLcYmwbkaK4mwNml7hGrFVK2Rw7PJyoLzI+nHV3qnPurg6tcIRtzI5tfuSNjfRK\r\n5dsp8LDJJC7xnJAovvA89NB66uB4Dxpsi4SrQIQKBdpa+sih8B08lmYCoYpy+i8o\r\n0MY7twLy3R42/7lDDtG+aDPrvSmkS6xYCjxA+CUXEQKCAQBp6ejOOHfWjxxbfm70\r\nlqpjrzDB4+YM5JLSD43PFWCnmUdMQlV/eCOwTbGCEFVlRgfmeE1f30PG5WrqiQ3W\r\nJ5e7TdnsxfU3ZN0LUFfXYA+udYKJiYYtruXLeMcoBfFeb0yIFXiOuqi8EGCMnU8K\r\niV+oouDMMjNagFJM4JskzWQhUWxB0Um8LzfjtU5kyMnEqxwuNrmdbw+Ge62940qT\r\nSml7ohRtR5UG7GR5fW9VE5cfSwrZXjeU6q/0ZDlpALwVyL4PNOmPJr6ibUvTegKd\r\nsqa4RqLaCUuzyp7m84ZvYutmVKkAYPAKgwNRIJdL4vwH2LCOYc+y9/8V6cjYDDNp\r\ngfilAoIBAQCZGoW1IppSWHrmQjsoO8AyNt5u4CDNs9B6fH5e2SCDcW4TfMXIuEyE\r\nsnXmKq0b2Ys43zywxkUgai9OA7sDv3lIJ5/xlA/P0Ma98C/DwGKFebjBFfGH0YIe\r\nZwGY7C3r3Izp9scVbo55rjdw53EBpdqmaEkTHy+Dsi2foe5Z83DwgFbFh1iHDF8y\r\nUGws6q1pYWuJALyHv6t/r/GScsI4sbI6yaVK5V3Kmx9k/tKXDQl1JRv4Q1K8PxY3\r\n+CY5kWXZ/xb5vMKscaUP6ipq62XALOxtb90FDh732GYIMGc4EeJwiaZ6lFr78tCb\r\nj3WQVpBa7X5q7GOgH64veSfuAKFRG8xRAoIBAD4UJXP3b7d8flmmmh38eju5Y786\r\nBUJSYZoJteaqv8Yfnv9XVu1S8I5FU1WGivQW8/muqrP+J9w51uPEzCJAQnZNssw8\r\nwcGbYYABQXOF27yAAnB2duSf9On9HoptosoVnbYTCQs9ENb3/TbvR/7IXagrHGIG\r\nqx2BA07Az764hKUrINBb4ttIsWCzo4tdsqXnnjfZVzZ3WbqK2rO3YrJ5M10ZIfeZ\r\n1zIdve4KvoDJwSMe2IiavEgJbytJpPqBfS7QjDYyTziMd/GwJDleepE5qcEb42zN\r\nC9hZfptcr0QE9yevd+CdqydZb/KHX5i4dIappwRrm/+dMy+weXLg1wtxGuM=\r\n-----END RSA PRIVATE KEY-----";

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
            rsa.ImportFromPem(publicKey);

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
            rsa.ImportFromPem(privateKey);

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
