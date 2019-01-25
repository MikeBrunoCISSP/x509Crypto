using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.ComponentModel;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using System.Globalization;
using System.Security.Cryptography;

namespace x509Crypto
{

    public static class x509Utils
    {
        #region Constants and Static Fields

        private static string allowedThumbprintCharsPattern = "[^a-fA-F0-9]";

        #endregion

        #region Public Methods

        /// <summary>
        /// Loads the contents of a text file into a string expression
        /// </summary>
        /// <param name="path">The fully-qualified path to the file from which contents are being loaded</param>
        /// <returns>The contents of the specified text file as a string expression</returns>
        public static string LoadTextFromFile(string path)
        {
            string contents;

            if (!File.Exists(path))
            {
                string message = string.Format(@"Path does not exist: {0}", path);
                x509CryptoLog.Error(message, @"LoadTextFromFile");
                throw new FileNotFoundException(message);
            }

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
        /// Removes all illegal characters from a string, leaving only the hexidecimal characters (0-9, a-f)
        /// </summary>
        /// <param name="thumbprint">string containing a thumbprint value</param>
        /// <returns></returns>
        public static string FormatThumbprint(string thumbprint)
        {
            return Regex.Replace(thumbprint, allowedThumbprintCharsPattern, "").ToUpper();
        }

        /// <summary>
        /// Decrypts the specified ciphertext expression
        /// </summary>
        /// <param name="thumbprint">The thumbprint of the certificate corresponding to the public key used to encrypt the file</param>
        /// <param name="ciphertext">The ciphertext expression to decrypt</param>
        /// <param name="certStore">The certificate store location where the specified private key resides</param>
        /// <returns>Plaintext string expression resulting from decryption of the specified ciphertext expression</returns>
        public static string DecryptText(string thumbprint, string ciphertext, CertStore certStore)
        {
            using (x509CryptoAgent cryptoAgent = new x509CryptoAgent(FormatThumbprint(thumbprint), certStore))
            {
                return cryptoAgent.DecryptText(ciphertext);
            }
        }

        /// <summary>
        /// Decrypts the specified encrypted file
        /// </summary>
        /// <param name="thumbprint">The thumbprint of the certificate corresponding to the public key used to encrypt the file</param>
        /// <param name="ciphertextFilePath">The fully-qualified path of the encrypted file</param>
        /// <param name="plaintextFilePath">The fully-qualified path in which to write the decrypted file</param>
        /// <param name="certStore">The certificate store where the encryption certificate resides</param>
        /// <returns></returns>
        public static bool DecryptFile(string thumbprint, string ciphertextFilePath, string plaintextFilePath, CertStore certStore)
        {
            CheckForFile(ciphertextFilePath);

            File.Delete(plaintextFilePath);

            using (x509CryptoAgent cryptoAgent = new x509CryptoAgent(FormatThumbprint(thumbprint), certStore))
            {
                cryptoAgent.DecryptFile(ciphertextFilePath, plaintextFilePath);
            }

            return File.Exists(plaintextFilePath);
        }

        /// <summary>
        /// Encrypts the specified plaintext expression
        /// </summary>
        /// <param name="thumbprint">The thumbprint of the certificate to use for encryption</param>
        /// <param name="plaintext">The plaintext expression to encrypt</param>
        /// <param name="certStore">The certificate store where the encryption certificate resides</param>
        /// <returns></returns>
        public static string EncryptText(string thumbprint, string plaintext, CertStore certStore)
        {
            using (x509CryptoAgent cryptoAgent = new x509CryptoAgent(FormatThumbprint(thumbprint), certStore))
            {
                return cryptoAgent.EncryptText(plaintext);
            }
        }

        /// <summary>
        /// Encrypts the specified file
        /// </summary>
        /// <param name="thumbprint">The thumbprint of the certificate to use for encryption</param>
        /// <param name="plaintextFilePath">The fully-qualified path of the plaintext file (can be text or binary)</param>
        /// <param name="ciphertextFilePath">The fully-qualified path in which to write the encrypted file</param>
        /// <param name="certStore">The certificate store where the encryption certificate resides</param>
        /// <returns></returns>
        public static bool EncryptFile(string thumbprint, string plaintextFilePath, string ciphertextFilePath, CertStore certStore)
        {
            CheckForFile(plaintextFilePath);
            File.Delete(ciphertextFilePath);

            using (x509CryptoAgent cryptoAgent = new x509CryptoAgent(FormatThumbprint(thumbprint), certStore))
            {
                cryptoAgent.EncryptFile(plaintextFilePath, ciphertextFilePath);
            }

            return File.Exists(ciphertextFilePath);
        }

        /// <summary>
        /// Re-encrypts a ciphertext expression using a different certificate
        /// </summary>
        /// <param name="oldThumbprint">The thumbprint of the old certificate used for prior encryption</param>
        /// <param name="oldStore">The certificate store where the old encryption certificate resides</param>
        /// <param name="newThumbprint">The thumbprint of the new certificate to be used for re-encryption</param>
        /// <param name="newStore">The certificate store where the new encryption certificate resides</param>
        /// <param name="ciphertext">The ciphertext expression to be re-encrypted</param>
        /// <returns></returns>
        public static string ReEncryptText(string oldThumbprint, CertStore oldStore, string newThumbprint, CertStore newStore, string ciphertext)
        {
            using (x509CryptoAgent oldAgent = new x509CryptoAgent(FormatThumbprint(oldThumbprint), oldStore))
            {
                using (x509CryptoAgent newAgent = new x509CryptoAgent(FormatThumbprint(newThumbprint), newStore))
                {
                    return newAgent.EncryptText(oldAgent.DecryptText(ciphertext));
                }
            }
        }

        /// <summary>
        /// Re-encrypts an encrypted file using a different encryption certificate
        /// </summary>
        /// <param name="oldThumbprint">The thumbprint of the old certificate used for prior encryption</param>
        /// <param name="oldStore">The certificate store where the old encryption certificate resides</param>
        /// <param name="newThumbprint">The thumbprint of the new certificate to be used for re-encryption</param>
        /// <param name="newStore">The certificate store where the new encryption certificate resides</param>
        /// <param name="ciphertextFilePath">The fully-qualified path to the ciphertext file to be re-encrypted</param>
        public static void ReEncryptFile(string oldThumbprint, CertStore oldStore, string newThumbprint, CertStore newStore, string ciphertextFilePath)
        {
            CheckForFile(ciphertextFilePath);

            byte[] hashOrig,
                   hashCopy;

            string tmpCopy;

            hashOrig = Hash(ciphertextFilePath);
            tmpCopy = string.Format(@"{0}\cryptotmp_{1}", Path.GetDirectoryName(ciphertextFilePath), Rnd(6));
            File.Copy(ciphertextFilePath, tmpCopy);
            hashCopy = Hash(tmpCopy);

            if (hashOrig.SequenceEqual(hashCopy))
                File.Delete(ciphertextFilePath);
            else
            {
                try { File.Delete(tmpCopy); } catch { }
                throw new Exception(string.Format("Could not back up original file \"{0}\"", ciphertextFilePath));
            }

            try
            {
                using (x509CryptoAgent oldAgent = new x509CryptoAgent(FormatThumbprint(oldThumbprint), oldStore))
                {
                    byte[] data = oldAgent.DecryptFileToByteArray(tmpCopy);

                    using (x509CryptoAgent newAgent = new x509CryptoAgent(FormatThumbprint(newThumbprint), newStore))
                    {
                        newAgent.EncryptFileFromByteArray(data, ciphertextFilePath);
                    }
                }

                if (!File.Exists(ciphertextFilePath))
                    throw new FileNotFoundException(string.Format("\"{0}\": File not found after cryptographic operation. Restoring original", ciphertextFilePath));
            }
            catch (Exception ex)
            {
                if (File.Exists(ciphertextFilePath))
                {
                    if (!Hash(ciphertextFilePath).SequenceEqual(hashCopy))
                    {
                        File.Delete(ciphertextFilePath);
                        File.Copy(tmpCopy, ciphertextFilePath);
                    }
                }
                else
                    File.Copy(tmpCopy, ciphertextFilePath);

                throw ex;
            }
        }
             
        #endregion

        #region Internal Methods


        internal static string cleanThumbprint(string certThumbprint)
        {
            throw new NotImplementedException();
        }

        internal static void VerifyFile(string pfxPath)
        {
            throw new NotImplementedException();
        }

        #endregion

        #region Private Methods

        private static void CheckForFile(string path)
        {
            if (!File.Exists(path))
                throw new FileNotFoundException(string.Format("\"{0}\": File not found", path));
        }

        private static string Rnd(int length)
        {
            Random random = new Random();
            string charSet = @"abcdefghijklmopqrstuvwxyz0123456789";
            return new string(Enumerable.Repeat(charSet, length)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        private static byte[] Hash(string path)
        {
            using (var md5 = MD5.Create())
            {
                using (var stream = File.OpenRead(path))
                {
                    return md5.ComputeHash(stream);
                }
            }
        }

        #endregion
    }
}
