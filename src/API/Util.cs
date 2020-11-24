using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using System.Security;

namespace Org.X509Crypto
{
    public static class Util
    {
        internal static bool IsAdministrator = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

        internal static void VerifyFileExists(string filePath)
        {
            if (File.Exists(filePath))
            {
                X509CryptoLog.Info($"File \"{filePath}\" exists.");
            }
            else
            {
                FileNotFoundException ex = new FileNotFoundException(@"The expected file was not created", filePath);
                X509CryptoLog.Exception(ex, Criticality.CRITICAL);
                throw ex;
            }
        }

        public static string GetPlaintextFilename(string filename)
        {
            string withoutCiphertextExtension = string.Empty;

            if (Path.HasExtension(filename) && Path.GetExtension(filename).Matches(FileExtensions.Ciphertext))
            {
                withoutCiphertextExtension = Path.GetFileNameWithoutExtension(filename);
                if (Path.HasExtension(withoutCiphertextExtension))
                {
                    return $"{Path.GetDirectoryName(filename)}\\{withoutCiphertextExtension}";
                }
                else
                {
                    return $"{Path.GetDirectoryName(filename)}\\{withoutCiphertextExtension}{FileExtensions.Plaintext}";
                }
            }
            else
            {
                return $"{Path.GetDirectoryName(filename)}\\{filename}{FileExtensions.Plaintext}";
            }
        }

        public static void CheckForExistingFile(string fileName, bool overwriteExisting, string overwriteArgument, string overwriteValue)
        {
            if (File.Exists(fileName))
            {
                if (overwriteExisting)
                {
                    File.Delete(fileName);
                    if (File.Exists(fileName))
                    {
                        throw new X509CryptoException($"Unable to delete existing file {fileName.InQuotes()}");
                    }
                }
                else
                {
                    throw new X509CryptoException($"A file named {fileName.InQuotes()} already exists. Set \"{overwriteArgument} = {overwriteValue}\" to allow overwrite");
                }
            }
        }

        public static bool AddSecret(string secretName, string ciphertext, X509Alias Alias)
        {
            bool secretAdded = false;
            KeyValuePair<string, string> tuple = new KeyValuePair<string, string>(secretName, ciphertext);
            try
            {
                Alias.AddSecret(tuple, AllowSecretOverwrite.No);
                secretAdded = true;
            }
            catch (X509SecretAlreadyExistsException ex)
            {
                if (Util.WarnConfirm(ex.Message, Constants.Affirm))
                {
                    Alias.AddSecret(tuple, AllowSecretOverwrite.Yes);
                    secretAdded = true;
                }
            }

            if (secretAdded)
            {
                Alias.Commit();
                Console.WriteLine($"\r\nSecret {secretName} has been added to {nameof(X509Alias)} {Alias.Name} in the {Alias.Context.Name} {nameof(X509Context)}\r\n");
            }

            return secretAdded;
        }

        public static SecureString GetPassword(string prompt, bool confirmMatch = false)
        {
            SecureString Secret = new SecureString();
            SecureString Confirm = new SecureString();

            Console.Write($"\r\n{prompt}: ");
            Secret = GetPasswordWorker();

            if (confirmMatch)
            {
                Console.Write($"Confirm: ");
                Confirm = GetPasswordWorker();
                if (!Secret.Matches(Confirm))
                {
                    Console.WriteLine($"Entries do not match. Please try again.\r\n");
                    return GetPassword(prompt, confirmMatch);
                }
            }

            return Secret;
        }

        private static SecureString GetPasswordWorker()
        {
            SecureString Secret = new SecureString();
            ConsoleKeyInfo key;

            do
            {
                key = Console.ReadKey(true);
                if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
                {
                    Secret.AppendChar(key.KeyChar);
                    Console.Write("*");
                }
                else
                {
                    if (key.Key == ConsoleKey.Backspace && Secret.Length != 0)
                    {
                        Secret.RemoveAt(Secret.Length - 1);
                        Console.Write("\b \b");
                    }
                }
            }
            while (key.Key != ConsoleKey.Enter);
            Console.WriteLine();
            return Secret;
        }

        public static bool WarnConfirm(string message, string affirm)
        {
            string entry = string.Empty;

            Console.WriteLine($"\r\nWARNING! {message} Enter {affirm.InQuotes()} if you wish to proceed", ConsoleColor.Yellow);
            Console.Write(@"Your entry: ");
            entry = Console.ReadLine();
            if (entry.Matches(affirm, caseSensitive: true))
            {
                return true;
            }
            else
            {
                Console.WriteLine("\r\nNo action was taken.\r\n");
                return false;
            }
        }

        public static void ConsoleMessage(string message)
        {
            Console.WriteLine($"\r\n{message}\r\n");
        }

        public static void ConsoleWarning(string message)
        {
            Console.WriteLine($"\r\n{message}\r\n", ConsoleColor.Yellow);
        }
    }
}
