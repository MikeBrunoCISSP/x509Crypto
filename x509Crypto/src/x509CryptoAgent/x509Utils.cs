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

        /// <summary>
        /// Exports the certificate and public/private key pair corresponding to the specified certificate thumbprint to a PKCS#12 bundle written to the specified file path
        /// </summary>
        /// <param name="certThumbprint">Certificate thumbprint (case-insensitive)</param>
        /// <param name="storeLocation">Certificate store location where the specified certificate and private key are located (either StoreLocation.CurrentUser or StoreLocation.LocalMachine)</param>
        /// <param name="exportPath">Fully-qualified path to where the PKCS#12 bundle file should be written (a ".pfx" file extension will be added if no file extension is detected)</param>
        /// <param name="password">Password to protect the private key once stored in the PKCS#12 bundle file</param>
        /// <returns>The fully-qualified path to where the PKCS#12 bundle file was ultimately written</returns>
        public static string ExportPFX(string certThumbprint, CertStore certStore, string exportPath, string password)
        {
            if (!Path.HasExtension(exportPath))
                exportPath += @".pfx";

            if (File.Exists(exportPath))
                File.Delete(exportPath);

            certThumbprint = x509Utils.cleanThumbprint(certThumbprint);
            x509CryptoLog.Massive(string.Format("Sanitized certificate thumbprint: {0}", certThumbprint));

            X509Store store = new X509Store(StoreName.My, certStore.Location);
            store.Open(OpenFlags.ReadOnly);
            foreach (X509Certificate2 cert in store.Certificates)
            {
                if (string.Equals(certThumbprint, cert.Thumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    byte[] certBytes = cert.Export(X509ContentType.Pkcs12, password);
                    File.WriteAllBytes(exportPath, certBytes);
                    x509Utils.VerifyFile(exportPath);
                    return exportPath;
                }
            }

            throw new CertificateNotFoundException(certThumbprint, certStore);
        }

        /// <summary>
        /// Exports the certificate corresponding to the specified certificate thumbprint to a Base64-encoded text file
        /// </summary>
        /// <param name="certThumbprint">Certificate thumbprint (case-insensitive)</param>
        /// <param name="storeLocation">Certificate store location where the specified certificate is located (either StoreLocation.CurrentUser or StoreLocation.LocalMachine)</param>
        /// <param name="exportPath">Fully-qualified path to where the Base64-encoded file should be written (a ".cer" file extension will be added if no file extension is detected)</param>
        /// <returns>The fully-qualified path to where the Base64-encoded certificate file was ultimately written</returns>
        public static string ExportCert(string certThumbprint, CertStore certStore, string exportPath)
        {
            if (!Path.HasExtension(exportPath))
                exportPath += @".cer";

            if (!File.Exists(exportPath))
                File.Delete(exportPath);

            certThumbprint = x509Utils.cleanThumbprint(certThumbprint);
            X509Store store = new X509Store(StoreName.My, certStore.Location);
            store.Open(OpenFlags.ReadOnly);

            foreach (X509Certificate2 cert in store.Certificates)
            {
                if (string.Equals(certThumbprint, cert.Thumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    StringBuilder sb = new StringBuilder();
                    sb.AppendLine(@"-----BEGIN CERTIFICATE-----");
                    sb.AppendLine(Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
                    sb.AppendLine(@"-----END CERTIFICATE-----");
                    File.WriteAllText(exportPath, sb.ToString());
                    sb = null;

                    VerifyFile(exportPath);

                    try
                    {
                        X509Certificate2 test = new X509Certificate2(exportPath);
                    }
                    catch (CryptographicException ex)
                    {
                        x509CryptoLog.Exception(ex, Criticality.ERROR, string.Format("Certificate with thumbprint {0} was exported to path \"{1}\" but the file seems to be corrupt and unusable", certThumbprint, exportPath));
                        throw ex;
                    }

                    return exportPath;
                }
            }

            throw new CertificateNotFoundException(certThumbprint, certStore);
        }

        /// <summary>
        /// Overwrites a file (as stored on disk) with random bits in order to prevent forensic recovery of the data
        /// </summary>
        /// <param name="filePath">The fully-qualified path of the file to wipe from disk</param>
        /// <param name="timesToWrite">The number of times to overwrite the disk sectors where the file is/was stored</param>
        public static void WipeFile(string filePath, int timesToWrite)
        {
            if (File.Exists(filePath))
            {
                File.SetAttributes(filePath, FileAttributes.Normal);
                double sectors = Math.Ceiling(new FileInfo(filePath).Length / 512.0);
                byte[] dummyBuffer = new byte[512];
                RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();

                FileStream inputStream = new FileStream(filePath, FileMode.Open);
                for (int currentPass = 0; currentPass < timesToWrite; currentPass++)
                {
                    inputStream.Position = 0;
                    for (int sectorsWritten = 0; sectorsWritten < sectors; sectorsWritten++)
                    {
                        rng.GetBytes(dummyBuffer);
                        inputStream.Write(dummyBuffer, 0, dummyBuffer.Length);
                    }
                }

                inputStream.SetLength(0);
                inputStream.Close();

                DateTime dt = new DateTime(2037, 1, 1, 0, 0, 0);
                File.SetCreationTime(filePath, dt);
                File.SetLastAccessTime(filePath, dt);
                File.SetLastWriteTime(filePath, dt);

                File.SetCreationTimeUtc(filePath, dt);
                File.SetLastAccessTimeUtc(filePath, dt);
                File.SetLastWriteTimeUtc(filePath, dt);

                File.Delete(filePath);
            }

            else
                throw new FileNotFoundException("The file could not be wiped because the specified path could not be found", filePath);
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
