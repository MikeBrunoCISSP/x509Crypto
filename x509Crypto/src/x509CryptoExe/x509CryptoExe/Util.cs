using System;
using System.Collections.Generic;
using System.IO;
using Org.X509Crypto;

namespace X509CryptoExe
{
    partial class Program
    {
        private static void CheckForExistingFile(string fileName, bool overwriteExisting)
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
                    throw new X509CryptoException($"A file named {fileName.InQuotes()} already exists. Use {$"{Parameter.OverWriteExistingFile.Name} {Constants.Affirm}".InQuotes()} argument to overwrite");
                }
            }
        }

        private static string GetPlaintextFilename(string filename)
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

        private static bool AddSecret(string secretName, string ciphertext, X509Alias Alias)
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
                if (WarnConfirm(ex.Message))
                {
                    Alias.AddSecret(tuple, AllowSecretOverwrite.Yes);
                    secretAdded = true;
                }
            }

            if (secretAdded)
            {
                Alias.Commit();
                ConsoleMessage($"Secret {secretName} has been added to {nameof(X509Alias)} {Alias.Name} in the {Alias.Context.Name} {nameof(X509Context)}");
            }

            return secretAdded;
        }
    }
}
