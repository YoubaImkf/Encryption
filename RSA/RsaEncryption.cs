using System.Security.Cryptography;

public static class RsaEncryption
{

    #region --- KEYS ---
    private static readonly string publicKey = "<RSAKeyValue><Modulus>qIOwHddnqajm7gy+I6Okt6FrNpE3tyM1U9Hru0CZaEAsW7AMSWxbO1Tp3xf90URzyOjh/63f+AQfO+FZ1LG56HVrCPDpM5Y8kCcFOQQBZ33w7hI+sBBB0bynD59e8fqny3C83CT4V+uXQwAxE3zHm4VhrCI/uurp9vR8Lmr5igRazc25y1/Alav37fIdwDaRV4rRlISK7pBynH6frUP0vgcar3YEdD3KMEXEHPsUEVQ+nHIn1AbaV7WuTCvske0CaWYwRx+JKsAzDvvCTfdLszcrOmf/yOjLWmvRam41y8jGJE9O4zUs3D128mEJQd/zGMCtvxNzcvEGM3dA6N/Qzs4qQIMlU4VAKQyyTAHMhsAqEVVJ2oI5pOdERNRY9iUXsHMeSSfaF5TqG8sN6sbOl+T7lvW5ckoeYipTEzYWVaRXsDwD0ZxwASe3rdxMWRVf1F6yHKHRiDyVpqFfmzHmhROm837VRusyJtuPww0fJ3vvXVaZAt2l12G5GhI86KiVBkovB0mzafkvpR0+mfHwocWwlRI10b6vABZcUrFlVeADoEwUwn25GGH8++pTLsvf4r48imwOSniStWkhRjON69QYIp0N1xEiUmJyx9XfBJ+pwqg6jvPj7wRSXeNYg3wqIYw2sQvQPCNpmwv0Ez44c7uP3+PIF1rEDvS/VApQzPc=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

    private static readonly string privateKey = "<RSAKeyValue><Modulus>qIOwHddnqajm7gy+I6Okt6FrNpE3tyM1U9Hru0CZaEAsW7AMSWxbO1Tp3xf90URzyOjh/63f+AQfO+FZ1LG56HVrCPDpM5Y8kCcFOQQBZ33w7hI+sBBB0bynD59e8fqny3C83CT4V+uXQwAxE3zHm4VhrCI/uurp9vR8Lmr5igRazc25y1/Alav37fIdwDaRV4rRlISK7pBynH6frUP0vgcar3YEdD3KMEXEHPsUEVQ+nHIn1AbaV7WuTCvske0CaWYwRx+JKsAzDvvCTfdLszcrOmf/yOjLWmvRam41y8jGJE9O4zUs3D128mEJQd/zGMCtvxNzcvEGM3dA6N/Qzs4qQIMlU4VAKQyyTAHMhsAqEVVJ2oI5pOdERNRY9iUXsHMeSSfaF5TqG8sN6sbOl+T7lvW5ckoeYipTEzYWVaRXsDwD0ZxwASe3rdxMWRVf1F6yHKHRiDyVpqFfmzHmhROm837VRusyJtuPww0fJ3vvXVaZAt2l12G5GhI86KiVBkovB0mzafkvpR0+mfHwocWwlRI10b6vABZcUrFlVeADoEwUwn25GGH8++pTLsvf4r48imwOSniStWkhRjON69QYIp0N1xEiUmJyx9XfBJ+pwqg6jvPj7wRSXeNYg3wqIYw2sQvQPCNpmwv0Ez44c7uP3+PIF1rEDvS/VApQzPc=</Modulus><Exponent>AQAB</Exponent><P>9+6J0RJNVKGYFX5aWMa/nCi2Apme36YX80Mo20CGGlgBZwREoFLuP61r+WrjhhrKuraFdVT1sfY1WKZI4wMF/kFQiXEChMPXfVmE+enZFciji/g8QY6lvKhI4kXoQo4TKqQtQBvttqLa7q5AhqgY39sgrdtUlflIpqA0lnaJOklUbIH/FhvG78ro/6950NN1TRJVAsJVfrnOu9QbxY2eTGrpG+YUDT/XIflIgWsDwU0qEYdIlKiQ/PfGY3RxrTbP4wFATTSJN4+eS/n3xWwyuSHemSQ7QOsU71JnNHtNFhsqpG4qBVSMPCS1OExAbdMxmNjT++X+XKQRXLn6zgjhvQ==</P><Q>rf+Kv7ts1P6vA8BrKr+zj16WTLx5yOPk0VI98/M4fzIfAmaekTtGyZherhC4HGZLl1AIUYUjmtDwnkVcjHshU4JqAqac/KZrB48aKOx0Y7u455Sb1maU4d4lJA5WBI/PEgNQR4jQMPnBon9KdA80Zr4Q2l7e9JqOy5xXpSKVVTq5lcxAv0bKeDTa46mxIM03m4gTJTTOJ/aZtf5S4sHrHC96Gkx5jcv1+9QVix5k12NoYG542evETCrF56K8fdh+RM1X9ot0wxLf/hqUNru7vz0fIi4LLgDZbzwpTD42ejuq+DGpcdhQ+OWjMogH9ykmJLcKKkmsNqsPjlP7VZTiww==</Q><DP>42S4qjSrEFAVeMEmg/3lh4gfR0s2V9Gybb7PHiiT1l2ZC67yckkdkvGv8laCz2CLR6xXw0FlBw/V5bS9bNg9CvFEuIoZ0UL9xU3xlHVSUZRvy9SlD0uR3vJJxp5vY3uDQLzLc90prTS4r+jJ7bcG+Wm1Ez/y2IqGg6y0DrwxKHBRKiQgnVpkn1HvWXLLuyf2kfWaWql6WHx6i/MCdbJp2ZTEsH3ZLj27RsGoKmrISuZHC0SU4SOptxpZrqYCDOgUyxM+spDYuUjT2sMs6LlP3FSgIL0GS4hQ7x8Y4R2lmfzYo28Ww0TESfUw8K2e+huVhaZ45rQPE1C3S+CXk5i50Q==</DP><DQ>Fe4TSr8QpHfFDy/9UdH/i55cSyemIc+3UzqOXGTXRhDHH8JXUe6qqVXu+PlaexnZhSStJ7kkF6sl6IzNcVdDiAbz3YmqV52R983teiLzOG68i1OLoKYlNaKOA9FavhByBM8uGxX/R2zzHsv0UlRoQlrKPPugFiw0uyzlTwbg03EnWt33eyQs+KGQxQjqLjwvOgcYgqP5J8hI70synynZvB+vwAjLeTevtSGx5WrbQtpgmWbTDIROpVruvpcgMqxKndlTsNs6yCtk1935uDxJGX1WozQybIXm4cIvYlClBRroHYgE1zhwXC51NzU168zf5di8C0Bl2C4PM90Z3Ft7iQ==</DQ><InverseQ>NZPQByQ8SPhRMbvZ4ShvN1dr2sqGUv0tqA+QpBepqUTpO6rwB23NyGZtxNEd3OhnOPxeNzXzQvHftyAD7uWdFJ94Z+1BZj0j7qXoUQy8mcg54wCWaO08HiHoCJa7pFGon9iG3JSu6QZ/kKGAwjUJjp8HAQnO19FxpJLQGnJX/2nCgvBwwoMb9XRYD5wL3U6NdiASdM8IEwoMkVVLidCwC0BVWg3I1sBFyDMdW68BC68ivFH1RqtAvBHR8okiG8uaib9mb+U1QT608HpP0lhkIUHtCe/3Cs00iSq1z1l6qzxRGN2RE9ZYe5WNVs0xfR06M0wh9mmLjXsKu7PA1H0xeg==</InverseQ><D>Kby0GjAH1NWonL07OsiFO5YXX+SH0CxAQQp1QGO3m0KJugvYfzb/Qaq+YisnCnXR16kWkKUYG+2pbsNZ5HxAd3rdj9FbcRN83JdNi9maH2/qBI0wSZs9Mh1vo0bt1TEn7hN2M3BUsjH/vPCHNzRom/RlRKUW88zLNgdH2pdURwLdGqwhoGWO5YM6XQzioYDibrRLRGWvo3bTbD9QfTGfpJFN4rdwUvoa4enlsOffCIu9FjKP+svXuHGfQe5/IYV6W3Cb9IGzD4ubGdLxRS5C6Zh4dHbdu30tILAjpiC14ktQCB48g7nf6oyusUmnaVF2fGL8pZ7DsWxRBN48jXEh3i5g+OGFIM64wtXxfxY3dRITXoki3ph0EUjF1uefWCqQXWSJsm9WTD4Z7J7K1h8/syAa4LNjTj8xJA/3RhEyEAcT7n4sGhznR1g7wIHe4vEvYnwzNs6OagsD6hk8rz7Xgr2NeEJJGyZwG1hhC1JDtqAPP7pVcTQ5+RHv35GR77RVp6jl24DLpVgQa9BTKzMAmr1HiMhbzfLTc+uk234EkCfjQOXyqPabxVCWGpucJiL3TQQXZCCj3D5roUN3bIxuD89kR4fm6CXSc021yU0bM7l3o16qCYwlgMONw4jxqKFYLC6jRy5RaGnR3kbaAPvdD3HRvpye7BJau7pa288P+ME=</D></RSAKeyValue>";
    #endregion
    public static void EncryptFile(string inputFile, string outputFile)
    {
        using RSACryptoServiceProvider rsa = new();
        rsa.FromXmlString(publicKey);

        using FileStream inputStream = new(inputFile, FileMode.Open, FileAccess.Read);
        using FileStream outputStream = new(outputFile, FileMode.Create, FileAccess.Write);

        // Determine buffer size based on key size and block size
        int keySize = rsa.KeySize / 8; // Récupère la taille de la clé RSA en bits et la convertit en octets
        int blockSize = keySize - 11; // Calcule la taille maximale de bloc pouvant être encryptée à partir de la taille de la clé RSA
        int bufferSize = blockSize > 0 ? blockSize : 1; // Si la taille du bloc est supérieure à 0, alors la taille du tampon est égale à la taille du bloc, sinon elle est égale à 1 (pour éviter les tampons vides)
        byte[] buffer = new byte[bufferSize]; // Crée un tampon (buffer) de la taille calculée pour stocker les données à encrypter ou décrypter

        int bytesRead;
        while ((bytesRead = inputStream.Read(buffer, 0, buffer.Length)) > 0)
        {
            byte[] encryptedData = rsa.Encrypt(buffer, false);
            outputStream.Write(encryptedData, 0, encryptedData.Length);
        }
    }

    public static void DecryptFile(string inputFile, string outputFile)
    {
        using RSACryptoServiceProvider rsa = new();
        rsa.FromXmlString(privateKey);

        using FileStream inputStream = new(inputFile, FileMode.Open, FileAccess.Read);
        using FileStream outputStream = new(outputFile, FileMode.Create, FileAccess.Write);

        // Determine buffer size based on key size and block size
        int keySize = rsa.KeySize / 8;
        int blockSize = keySize;
        int bufferSize = blockSize > 0 ? blockSize : 1;
        byte[] buffer = new byte[bufferSize];

        int bytesRead;
        while ((bytesRead = inputStream.Read(buffer, 0, buffer.Length)) > 0)
        {
            byte[] decryptedData = rsa.Decrypt(buffer, false);
            outputStream.Write(decryptedData, 0, decryptedData.Length);
        }
    }

}