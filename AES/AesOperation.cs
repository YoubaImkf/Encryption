using System;
using System.Security.Cryptography;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;

// SOURCE :
// FileCrypt : https://stackoverflow.com/questions/53653510/c-sharp-aes-encryption-byte-array
// https://codereview.stackexchange.com/questions/196088/encrypt-a-byte-array
// https://code-maze.com/dotnet-cryptography-implementations/

namespace EncryptFile
{
    public class AesOperation
    {
/*        Encrypt - Execution Time: 172 ms
        decrypt - Execution Time: 92 ms*/
        private const int IvLength = 16; // to randomize the first block
        private static readonly byte[] Key = Encoding.UTF8.GetBytes("GyDWRe6*;hTb8n&bFvL<+o'-C&6&[X@:");

        public static byte[] Encrypt(byte[] plainData)
        {
            using Aes aes = Aes.Create();
            aes.Key = Key;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            byte[] iv = GenerateRandomBytes(IvLength);
            aes.IV = iv;

            using MemoryStream ms = new();
            ms.Write(iv, 0, iv.Length);
            using CryptoStream cs = new(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);
            cs.Write(plainData, 0, plainData.Length);
            cs.FlushFinalBlock();

            return ms.ToArray();
        }

        public static byte[] Decrypt(byte[] cipherData)
        {
            using Aes aes = Aes.Create();
            aes.Key = Key;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            byte[] iv = new byte[IvLength];
            Array.Copy(cipherData, iv, iv.Length);
            aes.IV = iv;

            using MemoryStream ms = new();
            using CryptoStream cs = new(ms, aes.CreateDecryptor(), CryptoStreamMode.Write);
            cs.Write(cipherData, iv.Length, cipherData.Length - iv.Length);
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
