using System;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace Org.X509Crypto {
    public static class Util {
        internal static bool IsAdministrator = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        internal static Regex OnlyMatchHexadecimal = new(RegexPattern.OnlyMatchHexidecimal);

        internal static void VerifyFileExists(string filePath) {
            if (!File.Exists(filePath)) {
                throw new FileNotFoundException("The expected file was not created", filePath);
            }
        }

        public static string GetPlaintextFilename(string filename) {
            string withoutCiphertextExtension = string.Empty;

            if (Path.HasExtension(filename) && Path.GetExtension(filename).Matches(FileExtensions.Ciphertext)) {
                withoutCiphertextExtension = Path.GetFileNameWithoutExtension(filename);
                return Path.HasExtension(withoutCiphertextExtension)
                    ? $"{Path.GetDirectoryName(filename)}\\{withoutCiphertextExtension}"
                    : $"{Path.GetDirectoryName(filename)}\\{withoutCiphertextExtension}{FileExtensions.Plaintext}";
            }

            return $"{Path.GetDirectoryName(filename)}\\{filename}{FileExtensions.Plaintext}";
        }

        public static void CheckForExistingFile(string fileName, bool overwriteExisting, string overwriteArgument, string overwriteValue) {
            if (File.Exists(fileName)) {
                if (overwriteExisting) {
                    File.Delete(fileName);
                    if (File.Exists(fileName)) {
                        throw new X509CryptoException($"Unable to delete existing file '{fileName}'");
                    }
                } else {
                    throw new X509CryptoException($"A file named '{fileName}' already exists. Set '{overwriteArgument} = {overwriteValue}' to allow overwrite");
                }
            }
        }

        public static bool IsCertThumbprint(string expression) {
            return OnlyMatchHexadecimal.IsMatch(expression);
        }

        public static SecureString GetPassword(string prompt, int minLength, bool confirmMatch = false) {
            SecureString Secret = new SecureString();
            SecureString Confirm = new SecureString();

            Console.Write($"\r\n{prompt}: ");
            Secret = GetPasswordWorker();

            if (confirmMatch) {
                if (Secret.Length < minLength) {
                    Console.WriteLine($"Password must be at least {minLength} characters.\r\n");
                    return GetPassword(prompt, minLength, confirmMatch);
                }
                Console.Write($"Confirm: ");
                Confirm = GetPasswordWorker();
                if (!Secret.Matches(Confirm)) {
                    Console.WriteLine($"Entries do not match. Please try again.\r\n");
                    return GetPassword(prompt, minLength, confirmMatch);
                }
            }

            return Secret;
        }

        private static SecureString GetPasswordWorker() {
            SecureString Secret = new SecureString();
            ConsoleKeyInfo key;

            do {
                key = Console.ReadKey(true);
                if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter) {
                    Secret.AppendChar(key.KeyChar);
                    Console.Write("*");
                } else {
                    if (key.Key == ConsoleKey.Backspace && Secret.Length != 0) {
                        Secret.RemoveAt(Secret.Length - 1);
                        Console.Write("\b \b");
                    }
                }
            }
            while (key.Key != ConsoleKey.Enter);
            Console.WriteLine();
            return Secret;
        }

        public static bool WarnConfirm(string message, string affirm) {
            string entry = string.Empty;

            Console.WriteLine($"\r\nWARNING! {message} Enter '{affirm}' if you wish to proceed", ConsoleColor.Yellow);
            Console.Write("Your entry: ");
            entry = Console.ReadLine();
            if (entry.Matches(affirm, compareType: StringComparison.Ordinal)) {
                return true;
            } else {
                Console.WriteLine("\r\nThe action will not be taken.\r\n");
                return false;
            }
        }

        public static void ConsoleMessage(string message) {
            Console.WriteLine($"\r\n{message}\r\n");
        }

        public static void ConsoleWarning(string message) {
            Console.WriteLine($"\r\n{message}\r\n", ConsoleColor.Yellow);
        }

        //public static X509Certificate2 GetCertByThumbprint(string thumbprint, X509Context Context) {
        //    thumbprint = thumbprint.RemoveNonHexChars();

        //    X509Store Store = new X509Store(StoreName.My, Context.Location);
        //    Store.Open(OpenFlags.ReadOnly);
        //    foreach (X509Certificate2 cert in Store.Certificates) {
        //        if (cert.Thumbprint.Matches(thumbprint)) {
        //            return cert;
        //        }
        //    }

        //    throw new X509CryptoCertificateNotFoundException(thumbprint, Context);
        //}

        public static byte[] GetSecureRandom(int byteLength) {
            using RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] payLoad = new byte[byteLength];
            rng.GetBytes(payLoad);

            return payLoad;
        }
    }
}
