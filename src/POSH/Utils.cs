using System;
using System.IO;
using Org.X509Crypto;

namespace X509CryptoPOSH
{
    internal class Utils
    {
        internal static void CheckForExistingFile(string fileName, bool overwriteExisting, string overwriteArgument)
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
                    throw new X509CryptoException($"A file named {fileName.InQuotes()} already exists. Set \"{overwriteArgument.InQuotes()} = $True\" to allow overwrite");
                }
            }
        }

        internal static bool WarnConfirm(string message)
        {
            string entry = string.Empty;

            Console.WriteLine($"\r\nWARNING! {message} Enter {Constants.Affirm.InQuotes()} if you wish to proceed", ConsoleColor.Yellow);
            Console.Write(@"Your entry: ");
            entry = Console.ReadLine();
            if (entry.Matches(Constants.Affirm, caseSensitive: true))
            {
                return true;
            }
            else
            {
                Console.WriteLine($"\r\nNo action was taken.\r\n");
                return false;
            }
        }
    }
}
