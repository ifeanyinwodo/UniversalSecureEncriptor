using System.Security.Cryptography;

namespace UniversalSecureEncriptor.Helper.Services
{
    internal static class KeyManager
    {
        internal static byte[] DeriveKey(string password, byte[] salt, int iterations = 100_000)
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
            return pbkdf2.GetBytes(32);
        }
    }

}
