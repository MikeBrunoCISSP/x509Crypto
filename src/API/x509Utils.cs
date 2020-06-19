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
using System.Security.Principal;
using System.Diagnostics;
using System.DirectoryServices;
using System.Security;
using System.Security.AccessControl;

namespace Org.X509Crypto
{
    /// <summary>
    /// A static class which provides access to X509Crypto namespace functionality without instantiating a X509CryptoAgent object.
    /// </summary>
    public static class X509Utils
    {
        #region Constants and Static Fields

        private static bool iisGroupChecked = false;
        private static bool iisGroupExists = false;

        private static string allowedThumbprintCharsPattern = "[^a-fA-F0-9]";

        /// <summary>
        /// Indicates whether the invoking user is a local administrator on the system
        /// </summary>
        public static readonly bool INVOKER_IS_ADMINISTRATOR = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

        //Crypto File Extensions

        /// <summary>
        /// Default file extension for files encrypted with the X509Crypto library
        /// </summary>
        public static readonly string CRYPTO_ENCRYPTED_FILE_EXT = @".ctx";

        /// <summary>
        /// Default file extension for files decrypted using the X509Crypto library (only used if the appropriate file extension cannot be inferred from the ciphertext file path
        /// </summary>
        public static readonly string CRYPTO_DECRYPTED_FILE_EXT = @".ptx";

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
                X509CryptoLog.Error(message, MethodName(), true, true);
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
        /// Removes all but hexidecimal characters (0-9, a-f) from the indicated text expression
        /// </summary>
        /// <param name="thumbprint">string containing a thumbprint value</param>
        /// <param name="verbose">True enables verbose logging</param>
        /// <returns>Text expression with all non hexidecimal characters removed</returns>
        /// <example>
        /// <code>
        /// string thumb = @"cc dc 67 3c 40 eb b2 a4 33 30 0c 0c 8a 2b a6 f4 43 da 56 88";
        /// string formattedThumb = X509Utils.FormatThumbprint(thumb);
        /// //formattedThumb = @"ccdc673c40ebb2a433300c0c8a2ba6f443da5688"
        /// </code>
        /// </example>
        public static string FormatThumbprint(string thumbprint, bool verbose = false)
        {
            X509CryptoLog.Massive(string.Format(@" Original Thumbprint: {0}", thumbprint), MethodName(), verbose, verbose);
            string formattedThumbprint = Regex.Replace(thumbprint, allowedThumbprintCharsPattern, "").ToUpper();
            X509CryptoLog.Massive(string.Format(@"Formatted Thumbprint: {0}", formattedThumbprint), MethodName(), verbose, verbose);
            return formattedThumbprint;
        }

        /// <summary>
        /// Decrypts the specified ciphertext expression
        /// </summary>
        /// <param name="thumbprint">The thumbprint of the certificate corresponding to the public key used to encrypt the file</param>
        /// <param name="ciphertext">The ciphertext expression to decrypt</param>
        /// <param name="Context">The certificate store location where the specified private key resides</param>
        /// <param name="verbose">True enables verbose logging</param>
        /// <returns>Plaintext string expression resulting from decryption of the specified ciphertext expression</returns>
        /// <example>
        /// <code>
        /// string thumbprint = @"ccdc673c40ebb2a433300c0c8a2ba6f443da5688";
        /// <see cref="X509Context"/> Context = <see cref="X509Context"/>.<see cref="X509Context.UserReadOnly"/>;
        /// string ciphertext = File.ReadAllText(@"C:\data\connectionString.txt");
        /// string plaintext = <see cref="X509Utils"/>.DecryptText(thumbprint, ciphertext, Context);
        /// </code>
        /// </example>
        public static string DecryptText(string thumbprint, string ciphertext, X509Context Context, bool verbose = false)
        {
            using (X509CryptoAgent cryptoAgent = new X509CryptoAgent(FormatThumbprint(thumbprint), Context))
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
        /// <param name="Context">The certificate store where the encryption certificate resides</param>
        /// <param name="verbose">True enables verbose logging</param>
        /// <returns>True or false depending upon whether the file decryption succeeded</returns>
        /// <example>
        /// <code>
        /// string thumbprint = @"ccdc673c40ebb2a433300c0c8a2ba6f443da5688";
        /// <see cref="X509Context"/> certStore = <see cref="X509Context"/>.<see cref="X509Context.UserReadOnly"/>;
        /// string encryptedFilePath = @"C:\Data\accounts.csv.ctx";
        /// bool success = <see cref="X509Utils"/>.DecryptFile(thumbprint, encryptedFilePath, certStore);
        /// </code>
        /// </example>
        public static bool DecryptFile(string thumbprint, string ciphertextFilePath, string plaintextFilePath, X509Context Context, bool verbose = false)
        {
            CheckForFile(ciphertextFilePath);

            File.Delete(plaintextFilePath);

            using (X509CryptoAgent cryptoAgent = new X509CryptoAgent(FormatThumbprint(thumbprint), Context))
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
        /// <param name="Context">The certificate store where the encryption certificate resides</param>
        /// <param name="verbose">True enables verbose logging</param>
        /// <returns></returns>
        /// <example>
        /// <code>
        /// string thumbprint = @"ccdc673c40ebb2a433300c0c8a2ba6f443da5688";
        /// <see cref="X509Context"/> certStore = <see cref="X509Context"/>.<see cref="X509Context.UserReadOnly"/>;
        /// string plaintext = @"Please encrypt this";
        /// string ciphertext = <see cref="X509Utils"/>.EncryptText(thumbprint, plaintext, certStore);
        /// </code>
        /// </example>
        public static string EncryptText(string thumbprint, string plaintext, X509Context Context, bool verbose = false)
        {
            using (X509CryptoAgent cryptoAgent = new X509CryptoAgent(FormatThumbprint(thumbprint), Context))
            {
                return cryptoAgent.EncryptText(plaintext);
            }
        }

        /// <summary>
        /// Encrypts the specified file
        /// </summary>
        /// <param name="thumbprint">The thumbprint of the certificate to use for encryption</param>
        /// <param name="plaintextFilePath">The fully-qualified path of the plaintext file (can be text or binary)</param>
        /// <param name="Context">(Optional) The certificate store where the encryption certificate resides (Default: <see cref="X509Context"/>.<see cref="X509Context.UserReadOnly"/>)</param>
        /// <param name="ciphertextFilePath">(Optional) The fully-qualified path in which to write the encrypted file (If not specified, the plaintext file path is appended with a ".ctx" extension)</param>
        /// <param name="verbose">(Optional) True enables verbose logging</param>
        /// <returns></returns>
        /// <example>
        /// <code>
        /// string thumbprint = @"ccdc673c40ebb2a433300c0c8a2ba6f443da5688";
        /// <see cref="X509Context"/> certStore = <see cref="X509Context"/>.<see cref="X509Context.UserReadOnly"/>
        /// string plaintextFilePath = @"C:\Data\accounts.csv";
        /// string ciphertextFilePath = 
        /// bool success = <see cref="X509Utils"/>.EncryptFile(thumbprint, plaintextFilePath, certStore);
        /// </code>
        /// </example>
        public static bool EncryptFile(string thumbprint, string plaintextFilePath, X509Context Context = null, string ciphertextFilePath = "", bool verbose = false)
        {
            CheckForFile(plaintextFilePath);

            if (Context == null)
                Context = X509Context.UserReadOnly;

            if (string.IsNullOrEmpty(ciphertextFilePath))
                ciphertextFilePath = plaintextFilePath + CRYPTO_ENCRYPTED_FILE_EXT;
            File.Delete(ciphertextFilePath);

            using (X509CryptoAgent cryptoAgent = new X509CryptoAgent(FormatThumbprint(thumbprint), Context))
            {
                cryptoAgent.EncryptFile(plaintextFilePath, ciphertextFilePath);
            }

            return File.Exists(ciphertextFilePath);
        }

        /// <summary>
        /// Re-encrypts a ciphertext expression using a different certificate
        /// </summary>
        /// <param name="oldThumbprint">The thumbprint of the old certificate used for prior encryption</param>
        /// <param name="newThumbprint">The thumbprint of the new certificate to be used for re-encryption</param>
        /// <param name="ciphertext">The ciphertext expression to be re-encrypted</param>
        /// <param name="OldContext">(Optional) The X509Context where the old encryption certificate resides (Default: <see cref="X509Context"/>.<see cref="X509Context.UserReadOnly"/>)</param>
        /// <param name="NewContext">(Optional) The X509Context where the new encryption certificate resides (Default: <see cref="X509Context"/>.<see cref="X509Context.UserReadOnly"/>)</param>
        /// <param name="verbose">(Optional) True enables verbose logging (Default: false)</param>
        /// <returns>The text expression re-encrypted using the new certificate</returns>
        /// <example>
        /// <code>
        /// string oldThumbprint = @"ccdc673c40ebb2a433300c0c8a2ba6f443da5688";
        /// string newThumbprint = @"0e7e327aab74e47a702c02d90c659da1115b29f7";
        /// string ciphertext = File.ReadAllText(@"C:\data\connectionString.txt");
        /// string updatedCiphertext = <see cref="X509Utils"/>.ReEncryptText(oldThumbprint, newThumbprint, ciphertext);
        /// File.WriteAllText(@"C:\data\connectionString.txt", updatedCiphertext);
        /// </code>
        /// </example>
        public static string ReEncryptText(string oldThumbprint, string newThumbprint, string ciphertext, X509Context OldContext = null, X509Context NewContext = null, bool verbose = false)
        {
            if (OldContext == null)
                OldContext = X509Context.UserReadOnly;
            if (NewContext == null)
                NewContext = X509Context.UserReadOnly;

            using (X509CryptoAgent oldAgent = new X509CryptoAgent(FormatThumbprint(oldThumbprint), OldContext))
            {
                using (X509CryptoAgent newAgent = new X509CryptoAgent(FormatThumbprint(newThumbprint), NewContext))
                {
                    return newAgent.EncryptText(oldAgent.DecryptText(ciphertext));
                }
            }
        }

        /// <summary>
        /// Re-encrypts an encrypted file using a different encryption certificate
        /// </summary>
        /// <param name="oldThumbprint">The thumbprint of the old certificate used for prior encryption</param>
        /// <param name="newThumbprint">The thumbprint of the new certificate to be used for re-encryption</param>
        /// <param name="ciphertextFilePath">The fully-qualified path to the ciphertext file to be re-encrypted</param>
        /// <param name="OldContext">(Optional) The certificate store where the old encryption certificate resides (Default: <see cref="X509Context"/>.<see cref="X509Context.UserReadOnly"/>)</param>
        /// <param name="NewContext">(Optional) The certificate store where the new encryption certificate resides (Default: <see cref="X509Context"/>.<see cref="X509Context.UserReadOnly"/>)</param>
        /// <param name="verbose">(Optional) True enables verbose logging (Default: false)</param>
        /// <example>
        /// <code>
        /// string oldThumbprint = @"ccdc673c40ebb2a433300c0c8a2ba6f443da5688";
        /// string newThumbprint = @"0e7e327aab74e47a702c02d90c659da1115b29f7";
        /// string encryptedFilePath = @"C:\data\accounts.csv.ctx";
        /// <see cref="X509Utils"/>.ReEncryptFile"(oldThumbprint, newThumbprint, encryptedFilePath);
        /// </code>
        /// </example>
        public static void ReEncryptFile(string oldThumbprint, string newThumbprint, string ciphertextFilePath, X509Context OldContext = null, X509Context NewContext = null, bool verbose = false)
        {
            CheckForFile(ciphertextFilePath);

            if (OldContext == null)
                OldContext = X509Context.UserReadOnly;
            if (NewContext == null)
                NewContext = X509Context.UserReadOnly;

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
                using (X509CryptoAgent oldAgent = new X509CryptoAgent(oldThumbprint.RemoveNonHexChars(), OldContext))
                {
                    byte[] data = oldAgent.DecryptFileToByteArray(tmpCopy);

                    using (X509CryptoAgent newAgent = new X509CryptoAgent(newThumbprint.RemoveNonHexChars(), NewContext))
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
        /// Re-encrypts an encrypted file using a different
        /// </summary>
        /// <param name="OldAlias">The old X509Alias that was originally used to encrypt the file</param>
        /// <param name="NewAlias">The new X509Alias that will be used to re-encrypt the file</param>
        /// <param name="ciphertextFilePath">The path to the ciphertext file to be re-encrypted</param>
        public static void ReEncryptFile(X509Alias OldAlias, X509Alias NewAlias, string ciphertextFilePath)
        {
            ReEncryptFile(OldAlias.Thumbprint, NewAlias.Thumbprint, ciphertextFilePath, OldAlias.Context, NewAlias.Context);
        }

        /// <summary>
        /// Installs an encryption certificate and associated key pair in the specified X509Context
        /// </summary>
        /// <param name="infile">The PKCS#12 (usually with a .pfx or .p12 extension) containing the bundled certificate and key pair</param>
        /// <param name="PfxPassword">The password to unlock the PKCS#12 file</param>
        /// <param name="Context">The X509Context in which to place the certificate and key pair</param>
        /// <returns></returns>
        public static string InstallCert(string infile, SecureString PfxPassword, X509Context Context)
        {
            bool certInstalled = false;
            X509Certificate2Collection certCol = new X509Certificate2Collection();
            X509Store keyChain;
            string thumbprint = string.Empty;

            try
            {
                certCol.Import(infile, PfxPassword.Plaintext(), X509KeyStorageFlags.PersistKeySet);
                keyChain = new X509Store(StoreName.My, Context.Location);
                keyChain.Open(OpenFlags.ReadWrite);

                foreach(X509Certificate2 cert in certCol)
                {
                    if (X509CryptoAgent.IsUsable(cert, Constants.ProbeMode))
                    {
                        keyChain.Add(cert);
                        if (Context.Index == X509Context.Indexer.SystemFull || Context.Index == X509Context.Indexer.SystemReadOnly)
                        {
                            AddIISKeyAccess(cert.Thumbprint);
                        }
                        certInstalled = true;
                        thumbprint = cert.Thumbprint;
                        break;
                    }
                }
                if (!certInstalled)
                {
                    throw new X509CryptoException($"The PKCS#12 file {Path.GetFileName(infile).InQuotes()} did not contain a valid encryption certificate");
                }
                else
                {
                    return thumbprint;
                }
            }
            finally
            {
                certCol = null;
                keyChain = null;
            }
        }

        /// <summary>
        /// Exports the certificate and public/private key pair corresponding to the specified certificate thumbprint to a PKCS#12 bundle written to the specified file path
        /// </summary>
        /// <param name="certThumbprint">Certificate thumbprint (case-insensitive)</param>
        /// <param name="exportPath">Fully-qualified path to where the PKCS#12 bundle file should be written (a ".pfx" file extension will be added if no file extension is detected)</param>
        /// <param name="password">Password to protect the private key once stored in the PKCS#12 bundle file</param>
        /// <param name="Context">(Optional) The certificate store where the encryption certificate resides (Default: <see cref="X509Context"/>.<see cref="X509Context.UserReadOnly"/>)</param>
        /// <param name="verbose">(Optional) True enables verbose logging (Default: false)</param>
        /// <returns>The fully-qualified path to where the PKCS#12 bundle file was ultimately written</returns>
        /// <example>
        /// <code>
        /// string thumbprint = @"ccdc673c40ebb2a433300c0c8a2ba6f443da5688";
        /// string exportPath = @"C:\data\bundle";
        /// string password = @"0n3T!m3U$e";
        /// <see cref="X509Context"/> certStore = <see cref="X509Context"/>.<see cref="X509Context.UserReadOnly"/>;
        /// string finalExportPath = <see cref="X509Utils"/>.ExportPFX(thumbprint, exportPath, password, certStore);
        /// //finalExportPath is @"C:\data\bundle.pfx"
        /// </code>
        /// </example>
        public static string ExportPFX(string certThumbprint, string exportPath, string password, X509Context Context = null, bool verbose = false)
        {
            if (Context == null)
                Context = X509Context.UserReadOnly;

            if (!Path.HasExtension(exportPath))
                exportPath += @".pfx";

            if (File.Exists(exportPath))
                File.Delete(exportPath);

            certThumbprint = FormatThumbprint(certThumbprint, verbose);

            X509Store store = new X509Store(StoreName.My, Context.Location);
            store.Open(OpenFlags.ReadOnly);
            foreach (X509Certificate2 cert in store.Certificates)
            {
                if (string.Equals(certThumbprint, cert.Thumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    byte[] certBytes = cert.Export(X509ContentType.Pkcs12, password);
                    File.WriteAllBytes(exportPath, certBytes);
                    X509Utils.VerifyFile(exportPath);
                    return exportPath;
                }
            }

            throw new X509CryptoCertificateNotFoundException(certThumbprint, Context);
        }

        /// <summary>
        /// Exports the certificate corresponding to the specified certificate thumbprint to a Base64-encoded text file
        /// </summary>
        /// <param name="certThumbprint">Certificate thumbprint (case-insensitive)</param>
        /// <param name="exportPath">Fully-qualified path to where the Base64-encoded file should be written (a ".cer" file extension will be added if no file extension is detected)</param>
        /// <param name="Context">(Optional) The certificate store where the encryption certificate resides (Default: <see cref="X509Context"/>.<see cref="X509Context.UserReadOnly"/>)</param>
        /// <param name="verbose">True enables verbose logging</param>
        /// <returns>The fully-qualified path to where the Base64-encoded certificate file was ultimately written</returns>
        /// <example>
        /// <code>
        /// string thumbprint = @"ccdc673c40ebb2a433300c0c8a2ba6f443da5688";
        /// string exportPath = @"C:\data\cert";
        /// <see cref="X509Context"/> certStore = <see cref="X509Context"/>.<see cref="X509Context.UserReadOnly"/>;
        /// string finalExportPath = <see cref="X509Utils"/>.ExportCert(thumbprint, exportPath, certStore);
        /// //finalExportPath is @"C:\data\cert.cer"
        /// </code>
        /// </example>
        public static string ExportCert(string certThumbprint, string exportPath, X509Context Context = null, bool verbose = false)
        {
            if (Context == null)
                Context = X509Context.UserReadOnly;

            if (!Path.HasExtension(exportPath))
                exportPath += @".cer";

            if (!File.Exists(exportPath))
                File.Delete(exportPath);

            certThumbprint = FormatThumbprint(certThumbprint, verbose);
            X509Store store = new X509Store(StoreName.My, Context.Location);
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
                        X509CryptoLog.Exception(ex, Criticality.ERROR, string.Format("Certificate with thumbprint {0} was exported to path \"{1}\" but the file seems to be corrupt and unusable", certThumbprint, exportPath));
                        throw ex;
                    }

                    return exportPath;
                }
            }

            throw new X509CryptoCertificateNotFoundException(certThumbprint, Context);
        }

        /// <summary>
        /// Overwrites a file (as stored on disk) with random bits in order to prevent forensic recovery of the data
        /// </summary>
        /// <param name="filePath">The fully-qualified path of the file to wipe from disk</param>
        /// <param name="timesToWrite">The number of times to overwrite the disk sectors where the file is/was stored</param>
        /// <example>
        /// <code>
        /// string path = @"C:\temp\SSNs.txt";
        /// int timesToWrite = 10;
        /// <see cref="X509Utils"/>.<see cref="WipeFile"/>(path, timesToWrite);
        /// </code>
        /// </example>
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

        /// <summary>
        /// Lists the thumbprint value for each certificate in the specified store location which include "Key Encipherment" in its Key Usage extension
        /// </summary>
        /// <param name="certStore">Store location from which to list certificate details (Either <see cref="X509Context.UserReadOnly"/> or <see cref="CertStore.LocalMachine"/>)</param>
        /// <param name="allowExpired">If set to True, expired certificates will be included in the output (Note that .NET will not perform cryptographic operations using a certificate which is not within its validity period)</param>
        /// <returns>A string expression listing all available certificate thumbprints and their expiration dates</returns>
        /// <example>
        /// <code>
        /// string availableCerts = <see cref="X509Utils"/>.<see cref="ListCerts"/>(<see cref="X509Context.UserReadOnly"/>);
        /// </code>
        /// </example>
        public static string ListCerts(CertStore certStore = null, bool allowExpired = false)
        {
            if (certStore == null)
                certStore = CertStore.CurrentUser;

            string output = "Key Encipherment Certificates found:\r\n\r\n";
            bool firstAdded = false;

            X509Store store = new X509Store(certStore.Location);
            store.Open(OpenFlags.ReadOnly);
            foreach (X509Certificate2 cert in store.Certificates)
            {
                if (X509CryptoAgent.IsUsable(cert, allowExpired))
                {
                    firstAdded = true;
                    output += cert.Subject + "\t" +
                              string.Format("Expires {0}", cert.NotAfter.ToShortDateString()) + "\t" +
                              cert.Thumbprint + "\r\n";
                }
            }

            if (!firstAdded)
                output += "None.\r\n";

            return output;
        }

        /// <summary>
        /// Deletes the specified file
        /// </summary>
        /// <param name="filePath">The path of the file to be deleted</param>
        /// <param name="complainIfNotFound">If true, an exception is thrown if the file does not currently exist</param>
        /// <param name="confirmDelete">If true, the file will be confirmed to no longer exist. If it still exists, an exception is thrown</param>
        public static void DeleteFile(string filePath, bool complainIfNotFound = false, bool confirmDelete = false)
        {
            if (!File.Exists(filePath) && complainIfNotFound)
            {
                throw new FileNotFoundException(filePath);
            }

            File.Delete(filePath);

            if (confirmDelete && File.Exists(filePath))
            {
                throw new IOException($"The file {filePath.InQuotes()} could not be deleted");
            }
        }

        /// <summary>
        /// Gets the name of the calling method
        /// </summary>
        /// <returns>The name of the calling method</returns>
        public static string MethodName()
        {
            return new StackTrace(1).GetFrame(0).GetMethod().Name;
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

        internal static bool IISGroupExists()
        {
            if (iisGroupChecked)
            {
                return iisGroupExists;
            }
            else
            {
                var machine = Environment.MachineName;
                var server = new DirectoryEntry($"WinNT://{machine},Computer");
                iisGroupExists = server.Children.Cast<DirectoryEntry>().Any(d => d.SchemaClassName.Equals(Constants.Group) && d.Name.Equals(Constants.IISGroup));
                iisGroupChecked = true;
                return iisGroupExists;
            }
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

        private static void AddIISKeyAccess(string thumbprint)
        {
            if (!IISGroupExists())
            {
                return;
            }

            X509Certificate2 cert = null;
            bool certFound = false;

            X509Store Store = new X509Store(StoreLocation.LocalMachine);
            Store.Open(OpenFlags.ReadWrite);
            foreach(X509Certificate2 machineCert in Store.Certificates)
            {
                if (machineCert.Thumbprint.Matches(thumbprint) && machineCert.HasPrivateKey)
                {
                    cert = machineCert;
                    certFound = true;
                    break;
                }
            }

            if (!certFound)
            {
                throw new X509CryptoException($"The certificate was not found in the {X509Context.SystemReadOnly.Name} {nameof(X509Context)}");
            }

            RSACryptoServiceProvider Rsa = cert.PrivateKey as RSACryptoServiceProvider;

            if (Rsa != null)
            {
                string keyFilePath = FindKeyLocation(Rsa.CspKeyContainerInfo.UniqueKeyContainerName);
                FileInfo file = new FileInfo(keyFilePath);
                FileSecurity FileSec = file.GetAccessControl();
                FileSec.AddAccessRule(new FileSystemAccessRule(Constants.IISGroup, FileSystemRights.Read, AccessControlType.Allow));
                file.SetAccessControl(FileSec);
            }
        }

        private static string FindKeyLocation(string containerName)
        {
            string keyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), Constants.MachineKeyPath, containerName);
            if (File.Exists(keyPath))
            {
                return keyPath;
            }
            else
            {
                throw new FileNotFoundException(@"The indicated path where the machine private key material should be located does not exist");
            }
        }

        #region MakeCert Methods



        #endregion

        #endregion
    }
}
