// See https://aka.ms/new-console-template for more information
// SOURCES :
// genererate key : https://dotnetcodr.com/2016/10/05/generate-truly-random-cryptographic-keys-using-a-random-number-generator-in-net/

using EncryptFile;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

Console.WriteLine("Hello, World!");


//string filePath = @"C:\Users\...\Desktop\DataPackage\Mp3\CA6e19a4f8939991e98be37b023503ad1f.mp3";
string filePath = @"C:\Users\...\Desktop\DataPackage\Mp3\MicrosoftActivisionPA.mp3";
string fileName = Path.GetFileName(filePath);

#region ---  AES Encrypt ---

/*var watch1 = new System.Diagnostics.Stopwatch();
watch1.Start();

// Read the file into a byte array
byte[] fileBytes = File.ReadAllBytes(filePath);

// Encrypt the file
byte[] encryptedBytes = AesOperation.Encrypt(fileBytes);

// Write the encrypted data to a new file
string encryptedFilePath = $@"C:\Users\...\Desktop\DataPackage\Mp3\Encrypt-AES\2AES_encrypted_file-{fileName}.enc";
File.WriteAllBytes(encryptedFilePath, encryptedBytes);

watch1.Stop();
Console.WriteLine($"Encrypt - Execution Time: {watch1.ElapsedMilliseconds} ms");*/

#endregion --

#region --- AES Decrypt --- 
/*var encryptedFilePath = @"C:\Users\...\Desktop\DataPackage\Mp3\Encrypt-AES\AES_encrypted_file-MicrosoftActivisionPA.mp3.enc";*//*

var watch2 = new System.Diagnostics.Stopwatch();
watch2.Start();

// Read the encrypted file into a byte array
byte[] encryptedFileBytes = File.ReadAllBytes(encryptedFilePath);

// Decrypt the file
byte[] decryptedBytes = AesOperation.Decrypt(encryptedFileBytes);

// Write the decrypted data to a new file
string decryptedFilePath = $@"C:\Users\...\Desktop\DataPackage\Mp3\Decrypt-AES\2AES_decrypted_file-{fileName}.mp3";
File.WriteAllBytes(decryptedFilePath, decryptedBytes);

watch2.Stop();
Console.WriteLine($"decrypt - Execution Time: {watch2.ElapsedMilliseconds} ms");*/


#endregion


#region RSA - Encrypt 

/*var watch3 = new System.Diagnostics.Stopwatch();
watch3.Start();
string encryptedFolder = $@"C:\Users\...\Desktop\DataPackage\Mp3\Encrypt-RSA\RSA_encrypted_file-{fileName}.enc";
RsaEncryption.EncryptFile(filePath, encryptedFolder);

watch3.Stop();

Console.WriteLine($"Encrypt(asymetric) - Execution Time: {watch3.ElapsedMilliseconds} ms");*/

#endregion

#region RSA - Decrypt 

/*var watch4 = new System.Diagnostics.Stopwatch();
watch4.Start();

string theEncFile = @"C:\Users\...\Desktop\DataPackage\Mp3\Encrypt-RSA\RSA_encrypted_file-MicrosoftActivisionPA.mp3.enc";

// string fileName2 = Path.GetFileName(theEncFile);
string decryptedFolder = $@"C:\Users\...\Desktop\DataPackage\Mp3\Decrypt-RSA\RSA_decrypted_file-pioupiou.mp3";

RsaEncryption.DecryptFile(theEncFile, decryptedFolder);

watch4.Stop();
Console.WriteLine($"Encrypt(asymetric) - Execution Time: {watch4.ElapsedMilliseconds} ms");*/

#endregion


#region Aes/RSA Encrypt //~300ms
/*var watch1 = new System.Diagnostics.Stopwatch();
watch1.Start();

// Read the file into a byte array
byte[] fileBytes = File.ReadAllBytes(filePath);

// Encrypt the file
byte[] encryptedBytes = AesRsaEncrypt.EncryptDataUsingAes(fileBytes);

// Write the encrypted data to a new file
string encryptedFilePath = $@"C:\Users\...\Desktop\DataPackage\Mp3\3Encrypt-AES_RSA\AES-RSA_encrypted_file-{fileName}.enc";
File.WriteAllBytes(encryptedFilePath, encryptedBytes);

watch1.Stop();
Console.WriteLine($"Encrypt - Execution Time: {watch1.ElapsedMilliseconds} ms");*/
#endregion

#region Aes/RSA Decrypt //~300ms
var encryptedFilePath = @"C:\Users\...\Desktop\DataPackage\Mp3\3Encrypt-AES_RSA\AES-RSA_encrypted_file-MicrosoftActivisionPA.mp3.enc";

var watch2 = new System.Diagnostics.Stopwatch();
watch2.Start();

// Read the encrypted file into a byte array
byte[] encryptedFileBytes = File.ReadAllBytes(encryptedFilePath);

// Decrypt the file
byte[] decryptedBytes = AesRsaEncrypt.DecryptDataUsingAes(encryptedFileBytes);

// Write the decrypted data to a new file
string decryptedFilePath = $@"C:\Users\...\Desktop\DataPackage\Mp3\3Decrypt-AES_RSA\AES-RSA_decrypted_file-{fileName}.mp3";
File.WriteAllBytes(decryptedFilePath, decryptedBytes);

watch2.Stop();
Console.WriteLine($"decrypt - Execution Time: {watch2.ElapsedMilliseconds} ms");
#endregion

Console.WriteLine("Done");

Console.ReadKey(); 