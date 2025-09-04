using System;
using System.IO;
using System.Security.Cryptography;

namespace UniversalSecureEncriptor.Helper.Services
{
    internal static class FileEncryptor
    {
        internal static string EncryptToBase64(string inputFile, string password)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] tag = new byte[16];
            byte[] key = KeyManager.DeriveKey(password, salt);

            byte[] plainBytes = File.ReadAllBytes(inputFile);
            byte[] cipherBytes = new byte[plainBytes.Length];

            using var aesGcm = new AesGcm(key, 16);
            aesGcm.Encrypt(nonce, plainBytes, cipherBytes, tag);

            byte[] combined = new byte[salt.Length + nonce.Length + tag.Length + cipherBytes.Length];
            Buffer.BlockCopy(salt, 0, combined, 0, salt.Length);
            Buffer.BlockCopy(nonce, 0, combined, salt.Length, nonce.Length);
            Buffer.BlockCopy(tag, 0, combined, salt.Length + nonce.Length, tag.Length);
            Buffer.BlockCopy(cipherBytes, 0, combined, salt.Length + nonce.Length + tag.Length, cipherBytes.Length);

            return Convert.ToBase64String(combined);
        }

        internal static byte[] EncryptToBytes(string inputFile, string password)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] tag = new byte[16];
            byte[] key = KeyManager.DeriveKey(password, salt);

            byte[] plainBytes = File.ReadAllBytes(inputFile);
            byte[] cipherBytes = new byte[plainBytes.Length];

            using var aesGcm = new AesGcm(key, 16);
            aesGcm.Encrypt(nonce, plainBytes, cipherBytes, tag);

            byte[] combined = new byte[salt.Length + nonce.Length + tag.Length + cipherBytes.Length];
            Buffer.BlockCopy(salt, 0, combined, 0, salt.Length);
            Buffer.BlockCopy(nonce, 0, combined, salt.Length, nonce.Length);
            Buffer.BlockCopy(tag, 0, combined, salt.Length + nonce.Length, tag.Length);
            Buffer.BlockCopy(cipherBytes, 0, combined, salt.Length + nonce.Length + tag.Length, cipherBytes.Length);

            return combined;
        }


        internal static void EncryptToBase64ToFile(string inputFile, string password)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] tag = new byte[16];
            byte[] key = KeyManager.DeriveKey(password, salt);

            byte[] plainBytes = File.ReadAllBytes(inputFile);
            byte[] cipherBytes = new byte[plainBytes.Length];

            using var aesGcm = new AesGcm(key, 16);
            aesGcm.Encrypt(nonce, plainBytes, cipherBytes, tag);

            byte[] combined = new byte[salt.Length + nonce.Length + tag.Length + cipherBytes.Length];
            Buffer.BlockCopy(salt, 0, combined, 0, salt.Length);
            Buffer.BlockCopy(nonce, 0, combined, salt.Length, nonce.Length);
            Buffer.BlockCopy(tag, 0, combined, salt.Length + nonce.Length, tag.Length);
            Buffer.BlockCopy(cipherBytes, 0, combined, salt.Length + nonce.Length + tag.Length, cipherBytes.Length);

            string base64 = Convert.ToBase64String(combined);

            // Create new filename with "_encrypted" appended
            string directory = Path.GetDirectoryName(inputFile);
            string filenameWithoutExt = Path.GetFileNameWithoutExtension(inputFile);
            string extension = Path.GetExtension(inputFile);
            string newFileName = Path.Combine(directory, $"{filenameWithoutExt}_encrypted{extension}");

            // Write Base64 string to the new file
            File.WriteAllText(newFileName, base64);
        }

        internal static void EncryptToBytesToFile(string inputFile, string password)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] tag = new byte[16];
            byte[] key = KeyManager.DeriveKey(password, salt);

            byte[] plainBytes = File.ReadAllBytes(inputFile);
            byte[] cipherBytes = new byte[plainBytes.Length];

            using var aesGcm = new AesGcm(key, 16);
            aesGcm.Encrypt(nonce, plainBytes, cipherBytes, tag);

            byte[] combined = new byte[salt.Length + nonce.Length + tag.Length + cipherBytes.Length];
            Buffer.BlockCopy(salt, 0, combined, 0, salt.Length);
            Buffer.BlockCopy(nonce, 0, combined, salt.Length, nonce.Length);
            Buffer.BlockCopy(tag, 0, combined, salt.Length + nonce.Length, tag.Length);
            Buffer.BlockCopy(cipherBytes, 0, combined, salt.Length + nonce.Length + tag.Length, cipherBytes.Length);

            // Create new filename with "_encrypted" appended
            string directory = Path.GetDirectoryName(inputFile);
            string filenameWithoutExt = Path.GetFileNameWithoutExtension(inputFile);
            string extension = Path.GetExtension(inputFile);
            string newFileName = Path.Combine(directory, $"{filenameWithoutExt}_encrypted{extension}");

            // Write encrypted binary data to the new file
            File.WriteAllBytes(newFileName, combined);
        }


        internal static string EncryptBase64ForFile(string base64, string password)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] tag = new byte[16];
            byte[] key = KeyManager.DeriveKey(password, salt);

            byte[] plainBytes = Convert.FromBase64String(base64);
            byte[] cipherBytes = new byte[plainBytes.Length];

            using var aesGcm = new AesGcm(key, 16);
            aesGcm.Encrypt(nonce, plainBytes, cipherBytes, tag);

            byte[] combined = new byte[salt.Length + nonce.Length + tag.Length + cipherBytes.Length];
            Buffer.BlockCopy(salt, 0, combined, 0, salt.Length);
            Buffer.BlockCopy(nonce, 0, combined, salt.Length, nonce.Length);
            Buffer.BlockCopy(tag, 0, combined, salt.Length + nonce.Length, tag.Length);
            Buffer.BlockCopy(cipherBytes, 0, combined, salt.Length + nonce.Length + tag.Length, cipherBytes.Length);

            return Convert.ToBase64String(combined);
        }

        internal static byte[] EncryptBytesForFile(byte[] bytes, string password)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] tag = new byte[16];
            byte[] key = KeyManager.DeriveKey(password, salt);

            byte[] plainBytes =bytes;
            byte[] cipherBytes = new byte[plainBytes.Length];

            using var aesGcm = new AesGcm(key, 16);
            aesGcm.Encrypt(nonce, plainBytes, cipherBytes, tag);

            byte[] combined = new byte[salt.Length + nonce.Length + tag.Length + cipherBytes.Length];
            Buffer.BlockCopy(salt, 0, combined, 0, salt.Length);
            Buffer.BlockCopy(nonce, 0, combined, salt.Length, nonce.Length);
            Buffer.BlockCopy(tag, 0, combined, salt.Length + nonce.Length, tag.Length);
            Buffer.BlockCopy(cipherBytes, 0, combined, salt.Length + nonce.Length + tag.Length, cipherBytes.Length);

            return combined;
        }


       
        internal static string DecryptFromBase64(string base64Data, string password)
        {
            byte[] combined = Convert.FromBase64String(base64Data);

            byte[] salt = new byte[16];
            byte[] nonce = new byte[12];
            byte[] tag = new byte[16];
            byte[] cipherBytes = new byte[combined.Length - salt.Length - nonce.Length - tag.Length];

            Buffer.BlockCopy(combined, 0, salt, 0, salt.Length);
            Buffer.BlockCopy(combined, salt.Length, nonce, 0, nonce.Length);
            Buffer.BlockCopy(combined, salt.Length + nonce.Length, tag, 0, tag.Length);
            Buffer.BlockCopy(combined, salt.Length + nonce.Length + tag.Length, cipherBytes, 0, cipherBytes.Length);

            byte[] key = KeyManager.DeriveKey(password, salt);
            byte[] plainBytes = new byte[cipherBytes.Length];

            using var aesGcm = new AesGcm(key, 16);
            aesGcm.Decrypt(nonce, cipherBytes, tag, plainBytes);

            return Convert.ToBase64String(plainBytes);
        }


        internal static byte[] DecryptFromBytes(byte[] byteArrayData, string password)
        {
            byte[] combined = byteArrayData;

            byte[] salt = new byte[16];
            byte[] nonce = new byte[12];
            byte[] tag = new byte[16];
            byte[] cipherBytes = new byte[combined.Length - salt.Length - nonce.Length - tag.Length];

            Buffer.BlockCopy(combined, 0, salt, 0, salt.Length);
            Buffer.BlockCopy(combined, salt.Length, nonce, 0, nonce.Length);
            Buffer.BlockCopy(combined, salt.Length + nonce.Length, tag, 0, tag.Length);
            Buffer.BlockCopy(combined, salt.Length + nonce.Length + tag.Length, cipherBytes, 0, cipherBytes.Length);

            byte[] key = KeyManager.DeriveKey(password, salt);
            byte[] plainBytes = new byte[cipherBytes.Length];

            using var aesGcm = new AesGcm(key,16);
            aesGcm.Decrypt(nonce, cipherBytes, tag, plainBytes);

            return plainBytes;
            
        }



        internal static void DecryptFromBase64ToFile(string base64Data, string outputFile, string password)
        {
            byte[] combined = Convert.FromBase64String(base64Data);

            byte[] salt = new byte[16];
            byte[] nonce = new byte[12];
            byte[] tag = new byte[16];
            byte[] cipherBytes = new byte[combined.Length - salt.Length - nonce.Length - tag.Length];

            Buffer.BlockCopy(combined, 0, salt, 0, salt.Length);
            Buffer.BlockCopy(combined, salt.Length, nonce, 0, nonce.Length);
            Buffer.BlockCopy(combined, salt.Length + nonce.Length, tag, 0, tag.Length);
            Buffer.BlockCopy(combined, salt.Length + nonce.Length + tag.Length, cipherBytes, 0, cipherBytes.Length);

            byte[] key = KeyManager.DeriveKey(password, salt);
            byte[] plainBytes = new byte[cipherBytes.Length];

            using var aesGcm = new AesGcm(key, 16);
            aesGcm.Decrypt(nonce, cipherBytes, tag, plainBytes);

            File.WriteAllBytes(outputFile, plainBytes);
        }


        internal static void DecryptFromBytesToFile(byte[] byteArrayData, string outputFile, string password)
        {
            byte[] combined = byteArrayData;

            byte[] salt = new byte[16];
            byte[] nonce = new byte[12];
            byte[] tag = new byte[16];
            byte[] cipherBytes = new byte[combined.Length - salt.Length - nonce.Length - tag.Length];

            Buffer.BlockCopy(combined, 0, salt, 0, salt.Length);
            Buffer.BlockCopy(combined, salt.Length, nonce, 0, nonce.Length);
            Buffer.BlockCopy(combined, salt.Length + nonce.Length, tag, 0, tag.Length);
            Buffer.BlockCopy(combined, salt.Length + nonce.Length + tag.Length, cipherBytes, 0, cipherBytes.Length);

            byte[] key = KeyManager.DeriveKey(password, salt);
            byte[] plainBytes = new byte[cipherBytes.Length];

            using var aesGcm = new AesGcm(key,16);
            aesGcm.Decrypt(nonce, cipherBytes, tag, plainBytes);

            File.WriteAllBytes(outputFile, plainBytes);

        }


        internal static void DecryptFromBase64FileToFile(string inputFile, string outputFile, string password)
        {
            string filesContent = File.ReadAllText(inputFile);
            byte[] combined = Convert.FromBase64String(filesContent);

            byte[] salt = new byte[16];
            byte[] nonce = new byte[12];
            byte[] tag = new byte[16];
            byte[] cipherBytes = new byte[combined.Length - salt.Length - nonce.Length - tag.Length];

            Buffer.BlockCopy(combined, 0, salt, 0, salt.Length);
            Buffer.BlockCopy(combined, salt.Length, nonce, 0, nonce.Length);
            Buffer.BlockCopy(combined, salt.Length + nonce.Length, tag, 0, tag.Length);
            Buffer.BlockCopy(combined, salt.Length + nonce.Length + tag.Length, cipherBytes, 0, cipherBytes.Length);

            byte[] key = KeyManager.DeriveKey(password, salt);
            byte[] plainBytes = new byte[cipherBytes.Length];

            using var aesGcm = new AesGcm(key, 16);
            aesGcm.Decrypt(nonce, cipherBytes, tag, plainBytes);

            File.WriteAllBytes(outputFile, plainBytes);
        }


        internal static void DecryptFromBytesFileToFile(string inputFile, string outputFile, string password)
        {
            byte[] combined = File.ReadAllBytes(inputFile); 

            byte[] salt = new byte[16];
            byte[] nonce = new byte[12];
            byte[] tag = new byte[16];
            byte[] cipherBytes = new byte[combined.Length - salt.Length - nonce.Length - tag.Length];

            Buffer.BlockCopy(combined, 0, salt, 0, salt.Length);
            Buffer.BlockCopy(combined, salt.Length, nonce, 0, nonce.Length);
            Buffer.BlockCopy(combined, salt.Length + nonce.Length, tag, 0, tag.Length);
            Buffer.BlockCopy(combined, salt.Length + nonce.Length + tag.Length, cipherBytes, 0, cipherBytes.Length);

            byte[] key = KeyManager.DeriveKey(password, salt);
            byte[] plainBytes = new byte[cipherBytes.Length];

            using var aesGcm = new AesGcm(key, 16);
            aesGcm.Decrypt(nonce, cipherBytes, tag, plainBytes);

            File.WriteAllBytes(outputFile, plainBytes);

        }

    }

}
