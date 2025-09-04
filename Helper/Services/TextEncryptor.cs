using System;
using System.Security.Cryptography;
using System.Text;

namespace UniversalSecureEncriptor.Helper.Services
{
    internal static  class TextEncryptor
    {
        internal static string EncryptToBase64(string plainText, string password)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] tag = new byte[16];
            byte[] key = KeyManager.DeriveKey(password, salt);

            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
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

            return Encoding.UTF8.GetString(plainBytes);
        }
    }

}
