using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.Globalization;
using System.Threading;
using System.IO;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;

namespace x509Crypto
{
    public class x509Utils
    {
        #region Constants and Static Fields

        /// <summary>
        /// String representation of System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser
        /// </summary>
        public static readonly string sSTORELOCATION_CURRENTUSER = @"CURRENTUSER";

        /// <summary>
        /// String representation of System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine
        /// </summary>
        public static readonly string sSTORELOCATION_LOCALMACHINE = @"LOCALMACHINE";

        private static bool eventLogSourceEstablished = false;

        private const string PREFERRED_EVENT_LOG_SOURCE = @"x509Crypto";
        private const string BACKUP_EVENT_LOG_SOURCE = @".NET Runtime";
        private const int eventId = 509;
        private static string eventLogSource = PREFERRED_EVENT_LOG_SOURCE;

        #endregion

        #region Private Methods

        private static void LogResults(string command, string standardOut, string standardErr)
        {
            string fullMessage;

            if (standardOut == string.Empty)
                standardOut = @"NULL";
            if (standardErr == string.Empty)
                standardErr = @"NULL";

            fullMessage = string.Format("Command: {0}\r\n\r\nStandard Output:\r\n {1}\r\n\r\nStandard Error:\r\n{2}\r\n", command, standardOut, standardErr);
            x509CryptoLog.Verbose("Command Execution Summary:\r\n" + fullMessage);
            LogEvent(fullMessage, EventLogEntryType.Information);
        }

        private static void LogEvent(string message, EventLogEntryType entryType)
        {

            if (!eventLogSourceEstablished)
                EstablishEventLogSource();

            EventLog.WriteEntry(eventLogSource, message, entryType, eventId);
        }

        private static void EstablishEventLogSource()
        {
            if (!EventLog.SourceExists(eventLogSource))
            {
                try
                {
                    EventLog.CreateEventSource(eventLogSource, @"Application");
                }
                catch (Exception)
                {
                    eventLogSource = BACKUP_EVENT_LOG_SOURCE;
                }
            }

            eventLogSourceEstablished = true;
        }

        #endregion

        #region Internal Methods

        internal static StoreLocation GetStoreLocation(string sStoreLocation)
        {
            string sStoreLocationFixed = Regex.Replace(sStoreLocation, @"\s+", "").ToUpper();

            if (string.Equals(sStoreLocationFixed, sSTORELOCATION_CURRENTUSER, StringComparison.OrdinalIgnoreCase))
                return StoreLocation.CurrentUser;
            else
            {
                if (string.Equals(sStoreLocationFixed, sSTORELOCATION_LOCALMACHINE, StringComparison.OrdinalIgnoreCase))
                {
                    return StoreLocation.LocalMachine;
                }
                else
                    throw new Exception(string.Format("Unknown value for StoreLocation {0}. Acceptable values are {1} and {2}", sStoreLocation, sSTORELOCATION_CURRENTUSER, sSTORELOCATION_LOCALMACHINE));
            }
        }

        internal static string cleanThumbprint(string certThumbprint)
        {
            throw new NotImplementedException();
        }

        internal static void VerifyFile(string pfxPath)
        {
            throw new NotImplementedException();
        }

        internal static string Exec(string command, bool debugMode = false)
        {
            string standardOut,
                   standardErr;

            Thread.CurrentThread.CurrentCulture = new CultureInfo(@"en-US");
            ProcessStartInfo procStartInfo = new ProcessStartInfo(@"cmd", @"/c " + command);
            procStartInfo.RedirectStandardOutput = true;
            procStartInfo.RedirectStandardError = true;
            procStartInfo.UseShellExecute = false;
            procStartInfo.CreateNoWindow = true;

            Process proc = new Process();
            proc.StartInfo = procStartInfo;
            proc.Start();

            proc.WaitForExit();
            standardOut = proc.StandardOutput.ReadToEnd();
            standardErr = proc.StandardError.ReadToEnd();
            if (debugMode)
                LogResults(command, standardOut, standardErr);

            return standardOut;
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Load the contents of a text file into a string expression
        /// </summary>
        /// <param name="path">The fully-qualified path to the file whose contents are to be loaded</param>
        /// <returns>The contents of the specified text file as a string expression</returns>
        public static string LoadStringFromFile(string path)
        {
            string contents;

            if (!File.Exists(path))
                throw new FileNotFoundException(string.Format("The specified file could not be found: {0}", path));

            using (FileStream inStream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                using (TextReader streamReader = new StreamReader(inStream))
                {
                    contents = streamReader.ReadToEnd();
                    streamReader.Close();
                }
                inStream.Close();
            }

            return contents;
        }

        /// <summary>
        /// Decrypts the specified ciphertext expression
        /// </summary>
        /// <param name="thumbprint">The thumbprint of the certificate corresponding to the private key to use for decryption</param>
        /// <param name="cipherText">The ciphertext expression to decrypt</param>
        /// <param name="storeLocation">The System.Security.X509Certificates.StoreLocation where the encryption certificate resides (either CurrentUser or LocalMachine)</param>
        /// <returns></returns>
        public static string DecryptText(string thumbprint, string cipherText, StoreLocation storeLocation)
        {
            using (x509CryptoAgent cryptoAgent = new x509CryptoAgent(thumbprint, storeLocation))
            {
                return cryptoAgent.DecryptText(cipherText);
            }
        }

        /// <summary>
        /// Decrypts the specified ciphertext expression
        /// </summary>
        /// <param name="thumbprint">The thumbprint of the certificate corresponding to the private key to use for decryption</param>
        /// <param name="cipherText">The ciphertext expression to decrypt</param>
        /// <param name="sStoreLocation">The string representation of the StoreLocation where the encryption certificate is located (either CurrentUser or LocalMachine)</param>
        /// <returns>The decrypted text expression</returns>
        public static string DecryptText(string thumbprint, string cipherText, string sStoreLocation)
        {
            using (x509CryptoAgent cryptoAgent = new x509CryptoAgent(thumbprint, sStoreLocation))
            {
                return cryptoAgent.DecryptText(cipherText);
            }
        }

        /// <summary>
        /// Decrypts the specified file
        /// </summary>
        /// <param name="certThumbprint">The thumbprint of the certificate corresponding to the private key to use for decryption</param>
        /// <param name="cipherTextFilePath">The fully-qualified path of the file to be decrypted</param>
        /// <param name="plainTextFilePath">The fully-qualified path in which to write the decrypted file</param>
        /// <param name="storeLocation">The System.Security.X509Certificates.StoreLocation where the encryption certificate resides (either CurrentUser or LocalMachine)</param>
        /// <returns>True or False depending upon whether the file decryption was successful</returns>
        public static bool DecryptFile(string certThumbprint, string cipherTextFilePath, string plainTextFilePath, StoreLocation storeLocation)
        {
            if (!File.Exists(cipherTextFilePath))
                throw new FileNotFoundException(string.Format("The ciphertext file path \"{0}\" could not be found.", cipherTextFilePath));

            if (File.Exists(plainTextFilePath))
                File.Delete(plainTextFilePath);

            using (x509CryptoAgent cryptoAgent = new x509CryptoAgent(certThumbprint, storeLocation))
            {
                cryptoAgent.DecryptFile(cipherTextFilePath, plainTextFilePath);
            }

            return File.Exists(plainTextFilePath);
        }

        /// <summary>
        /// Decrypts the specified file
        /// </summary>
        /// <param name="certThumbprint">The thumbprint of the certificate corresponding to the private key to use for decryption</param>
        /// <param name="cipherTextFilePath">The fully-qualified path of the file to be decrypted</param>
        /// <param name="plainTextFilePath">The fully-qualified path in which to write the decrypted file</param>
        /// <param name="sStoreLocation">The string representation of the StoreLocation where the encryption certificate is located (either CurrentUser or LocalMachine)</param>
        /// <returns>True or False depending upon whether the file decryption was successful</returns>
        public static bool DecryptFile(string certThumbprint, string cipherTextFilePath, string plainTextFilePath, string sStoreLocation)
        {
            return DecryptFile(certThumbprint, cipherTextFilePath, plainTextFilePath, GetStoreLocation(sStoreLocation));
        }

        /// <summary>
        /// Encrypts the specified string
        /// </summary>
        /// <param name="certThumbprint">The thumbprint of the certificate corresponding to the public key to use for encryption</param>
        /// <param name="plainText">The plaintext expression to encrypt</param>
        /// <param name="storeLocation">The System.Security.X509Certificates.StoreLocation where the encryption certificate resides (either CurrentUser or LocalMachine)</param>
        /// <returns>The encrypted string</returns>
        public static string EncryptText(string certThumbprint, string plainText, StoreLocation storeLocation)
        {
            using (x509CryptoAgent cryptoAgent = new x509CryptoAgent(certThumbprint, storeLocation))
            {
                return cryptoAgent.EncryptText(plainText);
            }
        }

        /// <summary>
        /// Encrypts the specified string
        /// </summary>
        /// <param name="certThumbprint">The thumbprint of the certificate corresponding to the public key to use for encryption</param>
        /// <param name="plainText">The plaintext expression to encrypt</param>
        /// <param name="sStoreLocation">The string representation of the StoreLocation where the encryption certificate is located (either CurrentUser or LocalMachine)</param>
        /// <returns>The encrypted string</returns>
        public static string EncryptText(string certThumbprint, string plainText, string sStoreLocation)
        {
            using (x509CryptoAgent cryptoAgent = new x509CryptoAgent(certThumbprint, GetStoreLocation(sStoreLocation)))
            {
                return cryptoAgent.EncryptText(plainText);
            }
        }

        /// <summary>
        /// Encrypts the specified file
        /// </summary>
        /// <param name="certThumbprint">The thumbprint of the certificate corresponding to the public key to use for encryption</param>
        /// <param name="plainTextFilePath">The fully-qualified path of the file to be encrypted</param>
        /// <param name="cipherTextFilePath">The fully-qualified path in which to write the encrypted file</param>
        /// <param name="storeLocation">The System.Security.X509Certificates.StoreLocation where the encryption certificate resides (either CurrentUser or LocalMachine)</param>
        /// <returns>True or False depending on whether the file encryption is successful</returns>
        public static bool EncryptFile(string certThumbprint, string plainTextFilePath, string cipherTextFilePath, StoreLocation storeLocation)
        {
            if (!File.Exists(plainTextFilePath))
                throw new Exception(string.Format("The plaintext file path \"{0}\" could not be found.", plainTextFilePath));

            if (File.Exists(cipherTextFilePath))
                File.Delete(cipherTextFilePath);

            using (x509CryptoAgent cryptoAgent = new x509CryptoAgent(certThumbprint, storeLocation))
            {
                cryptoAgent.EncryptFile(plainTextFilePath, cipherTextFilePath);
            }

            return File.Exists(cipherTextFilePath);
        }

        /// <summary>
        /// Encrypts the specified file
        /// </summary>
        /// <param name="certThumbprint">The thumbprint of the certificate corresponding to the public key to use for encryption</param>
        /// <param name="plainTextFilePath">The fully-qualified path of the file to be encrypted</param>
        /// <param name="cipherTextFilePath">The fully-qualified path in which to write the encrypted file</param>
        /// <param name="sStoreLocation">The string representation of the StoreLocation where the encryption certificate is located (either CurrentUser or LocalMachine)</param>
        /// <returns>True or False depending on whether the file encryption is successful</returns>
        public static bool EncryptFile(string certThumbprint, string plainTextFilePath, string cipherTextFilePath, string sStoreLocation)
        {
            return EncryptFile(certThumbprint, plainTextFilePath, cipherTextFilePath, GetStoreLocation(sStoreLocation));
        }

        /// <summary>
        /// Re-Encrypts a ciphertext string using a different certificate
        /// </summary>
        /// <param name="oldCipherText">The ciphertext string to be re-encrypted</param>
        /// <param name="oldCertThumbprint">The thumbprint of the certificate that was originally used to encrypt the text</param>
        /// <param name="newCertThumbprint">The thumbprint of the new certificate which will re-encrypt the text</param>
        /// <param name="oldStoreLocation">The System.Security.X509Certificates.StoreLocation where the old certificate is located (Default: StoreLocation.CurrentUser)</param>
        /// <param name="newStoreLocation">The System.Security.X509Certificates.StoreLocation where the new certificate is located (Default: StoreLocation.CurrentUser)</param>
        /// <returns>The re-encrypted ciphertext expression</returns>
        public static string ReEncryptText(string oldCipherText, string oldCertThumbprint, string newCertThumbprint, StoreLocation oldStoreLocation = StoreLocation.CurrentUser, StoreLocation newStoreLocation = StoreLocation.CurrentUser)
        {
            using (x509CryptoAgent agentOld = new x509CryptoAgent(oldCertThumbprint, oldStoreLocation))
            {
                using (x509CryptoAgent agentNew = new x509CryptoAgent(newCertThumbprint, newStoreLocation))
                {
                    return agentNew.EncryptText(agentOld.DecryptText(oldCipherText));
                }
            }
        }

        /// <summary>
        /// Re-encrypts a ciphertext string using a different certificate
        /// </summary>
        /// <param name="oldCipherText">The ciphertext string to be re-encrypted</param>
        /// <param name="oldCertThumbprint">The thumbprint of the certificate that was originally used to encrypt the text</param>
        /// <param name="newCertThumbprint">The thumbprint of the new certificate which will re-encrypt the text</param>
        /// <param name="sOldStoreLocation">The string representation of the StoreLocation where the old certificate is located (Default: StoreLocation.CurrentUser)</param>
        /// <param name="sNewStoreLocation">The string representation of the StoreLocation where the new certificate is located (Default: StoreLocation.CurrentUser)</param>
        /// <returns></returns>
        public static string ReEncryptString(string oldCipherText, string oldCertThumbprint, string newCertThumbprint, string sOldStoreLocation = @"CURRENTUSER", string sNewStoreLocation = @"CURRENTUSER")
        {
            return ReEncryptText(oldCipherText, oldCertThumbprint, newCertThumbprint, GetStoreLocation(sOldStoreLocation), GetStoreLocation(sNewStoreLocation));
        }

        public static void ReEncryptFile(string cipherTextFilePath, string oldCertThumbprint, string newCertThumbprint, StoreLocation oldStoreLocation = StoreLocation.CurrentUser, StoreLocation newStoreLocation = StoreLocation.CurrentUser)
        {
            string tmpCipherTextPath;

            if (!File.Exists(cipherTextFilePath))
                throw new FileNotFoundException(string.Format("The ciphertext file path \"{0}\" was not found.", cipherTextFilePath));

            using (x509CryptoAgent agentOld = new x509CryptoAgent(oldCertThumbprint, oldStoreLocation))
            {
                byte[] data = agentOld.DecryptFileToByteArray(cipherTextFilePath);

                do
                {
                    tmpCipherTextPath = Path.GetDirectoryName(cipherTextFilePath) + "\\cryptotmp_" + rnd(6);
                }
                while (File.Exists(tmpCipherTextPath));
                File.Move(cipherTextFilePath, tmpCipherTextPath);

                using (x509CryptoAgent agentNew = new x509CryptoAgent(newCertThumbprint, newStoreLocation))
                {
                    agentNew.EncryptFileFromByteArray(data, cipherTextFilePath);
                }
            }

            if (!File.Exists(cipherTextFilePath))
            {
                File.Move(tmpCipherTextPath, cipherTextFilePath);
                throw new Exception(string.Format("The ciphertext file was not found after re-encryption.  The original ciphertext file {0} has been restored and no changes have been made", cipherTextFilePath));
            }
        }

        #endregion
    }
}
