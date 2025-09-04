using System.Security.Cryptography;

namespace UniversalSecureEncriptor.Helper.Utilities
{
    internal class HashUtility
    {
        internal static string ComputeSHA256(byte[] data)
        {
            using var sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(data);
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }
    }

}
