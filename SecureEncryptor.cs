using UniversalSecureEncriptor.Helper;
using UniversalSecureEncriptor.Helper.Services;

namespace UniversalSecureEncriptor
{
    public class SecureEncryptor
    {

        public static string EncryptText(string message, string encryptionPassword)
        {
            return TextEncryptor.EncryptToBase64(message, encryptionPassword);
        }

        public static string DecryptText(string encryptedText, string encryptionPassword)
        {
            return TextEncryptor.DecryptFromBase64(encryptedText, encryptionPassword);
        }

        public static string EncryptFileToBase64(string inputFile, string encryptionPassword)
        {
            return FileEncryptor.EncryptToBase64(inputFile, encryptionPassword); 
        }

        public static byte[] EncryptFileToBytes(string inputFile, string encryptionPassword)
        {
            return FileEncryptor.EncryptToBytes(inputFile, encryptionPassword);
        }

        public static void DecryptFromBase64ToFile(string encryptedFileBase64, string outputFile, string encryptionPassword)
        {
             FileEncryptor.DecryptFromBase64ToFile(encryptedFileBase64, outputFile, encryptionPassword);
        }

        public static string DecryptFromBase64(string encryptedFileBase64, string encryptionPassword)
        {
           return FileEncryptor.DecryptFromBase64(encryptedFileBase64, encryptionPassword);
        }

        public static byte[] DecryptFromBytes(byte[] encryptedFileBytes, string encryptionPassword)
        {
           return FileEncryptor.DecryptFromBytes(encryptedFileBytes,encryptionPassword);
        }

        public static void DecryptFromBytesToFile(byte[] encryptedFileBytes, string outputFile, string encryptionPassword)
        {
            FileEncryptor.DecryptFromBytesToFile(encryptedFileBytes, outputFile, encryptionPassword);
        }

        public static void EncryptToBase64ToFile(string inputFile, string password)
        {
            FileEncryptor.EncryptToBase64ToFile(inputFile, password);
        }

        public static void EncryptToBytesToFile(string inputFile, string password)
        {
            FileEncryptor.EncryptToBytesToFile(inputFile, password);
        }

        public static string EncryptBase64ForFile(string base64, string password)
        {
           return FileEncryptor.EncryptBase64ForFile(base64, password);
        }

        public static byte[] EncryptBytesForFile(byte[] bytes, string password)
        {
            return FileEncryptor.EncryptBytesForFile(bytes, password);
        }

        public static void DecryptFromBase64FileToFile(string inputFile, string outputFile, string password)
        {
            FileEncryptor.DecryptFromBase64FileToFile(inputFile, outputFile, password);
        }

        public static void DecryptFromBytesFileToFile(string inputFile, string outputFile, string password)
        {
            FileEncryptor.DecryptFromBytesFileToFile(inputFile, outputFile, password);
        }

    }
}
