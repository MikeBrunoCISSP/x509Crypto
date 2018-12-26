using System;
using System.Text;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.IO;
using System.Runtime.Serialization;

namespace x509Crypto
{
    /// <summary>
    /// Instantiatable class which can be used to perform cryptographic operations on string expressions and files
    /// </summary>
    public class x509CryptoAgent : IDisposable
    {
        #region Constants and Static Fields

        const bool LEAVE_MEMSTREAM_OPEN = true;

        internal static bool INVOKER_IS_ADMINISTRATOR = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

        #endregion

        #region Member Fields

        private RSACryptoServiceProvider publicKey,
                                         privateKey;

        private string thumbprint;
        private StoreLocation certStoreLocation;

        public string Thumbprint
        {
            get
            {
                return thumbprint;
            }
        }

        public string CertStoreLocationName
        {
            get
            {
                return x509Utils.GetEnumDescription(certStoreLocation);
            }
        }

        public StoreLocation CertStoreLocation
        {
            get
            {
                return certStoreLocation;
            }
        }

        /// <summary>
        /// Indicates whether the instantiated x509CrytoAgent object is bound to a valid certificate and corresponding private key that can be used for encryption and decryption respectively
        /// </summary>
        public bool valid = false;

        #endregion

        #region Constructors and Destructors

        /// <summary>
        /// x509CryptoAgent Constructor
        /// </summary>
        /// <param name="certThumbprint">The thumbprint of the encryption certificate.  The certificate must be present in the CURRENTUSER store location</param>
        public x509CryptoAgent(string certThumbprint)
        {
            GetRSAKeys(certThumbprint.ToUpper().Replace(" ", ""), StoreLocation.CurrentUser);
        }

        /// <summary>
        /// x509CryptoAgent Constructor
        /// </summary>
        /// <param name="certThumbprint">The thumbprint of the encryption certificate.</param>
        /// <param name="sStoreLocation">String representation of the certificate store where the encryption certificate resides ("CURRENTUSER" or "LOCALMACHINE")</param>
        public x509CryptoAgent(string certThumbprint, string sStoreLocation)
        {
            GetRSAKeys(certThumbprint.ToUpper().Replace(" ", ""), x509Utils.GetStoreLocation(sStoreLocation));
        }

        /// <summary>
        /// x509CryptoAgent Constructor
        /// </summary>
        /// <param name="inStream">FileStream pointing to a text file containing the encryption certificate thumbprint. The certificate must be present in the CURRENTUSER store location</param>
        public x509CryptoAgent(FileStream inStream)
        {
            string thumbprint;
            using (StreamReader reader = new StreamReader(inStream))
            {
                thumbprint = reader.ReadToEnd();
                reader.Close();
            }

            GetRSAKeys(thumbprint.ToUpper().Replace(" ", ""), StoreLocation.CurrentUser);
        }

        /// <summary>
        /// x509CryptoAgent Constructor
        /// </summary>
        /// <param name="inStream">FileStream pointing to a text file containing the encryption certificate thumbprint.</param>
        /// <param name="location">The System.Security.X509Certificates.StoreLocation where the encryption certificate resides (either CurrentUser or LocalMachine)</param>
        public x509CryptoAgent(FileStream inStream, StoreLocation location)
        {
            string thumbprint;
            using (StreamReader reader = new StreamReader(inStream))
            {
                thumbprint = reader.ReadToEnd();
                reader.Close();
            }

            GetRSAKeys(thumbprint.ToUpper().Replace(" ", ""), location);
        }

        /// <summary>
        /// x509CryptoAgent Constructor
        /// </summary>
        /// <param name="inStream">FileStream pointing to a text file containing the encryption certificate thumbprint.</param>
        /// <param name="sStoreLocation">String representation of the certificate store where the encryption certificate resides ("CURRENTUSER" or "LOCALMACHINE")</param>
        public x509CryptoAgent(FileStream inStream, string sStoreLocation)
        {
            string thumbprint;
            using (StreamReader reader = new StreamReader(inStream))
            {
                thumbprint = reader.ReadToEnd();
                reader.Close();
            }

            GetRSAKeys(thumbprint.ToUpper().Replace(" ", ""), x509Utils.GetStoreLocation(sStoreLocation));
        }

        /// <summary>
        /// x509CryptoAgent Destructor
        /// </summary>
        public void Dispose()
        {
            publicKey = null;
            privateKey = null;
        }

        #endregion

        #region Member Methods

        private void GetRSAKeys(string certThumbprint, StoreLocation storeLocation)
        {
            certThumbprint = x509Utils.cleanThumbprint(certThumbprint);
            x509CryptoLog.Massive(string.Format("Sanitized thumbprint: {0}", certThumbprint));
            X509Certificate2Collection colletion = new X509Certificate2Collection();
            X509Store keyStore = new X509Store(storeLocation);
            keyStore.Open(OpenFlags.ReadOnly);
            foreach(X509Certificate2 cert in keyStore.Certificates)
            {
                if (string.Equals(cert.Thumbprint, certThumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    if (cert.HasPrivateKey & isUsable(cert, false))
                        colletion.Add(cert);
                }
            }

            if (colletion.Count != 1)
                throw new CertificateNotFoundException(certThumbprint, storeLocation);

            foreach (X509Certificate2 cert in colletion)
            {
                publicKey = (RSACryptoServiceProvider)cert.PublicKey.Key;
                privateKey = (RSACryptoServiceProvider)cert.PrivateKey;
            }
            x509CryptoLog.Info(string.Format("Successfully loaded keypair of certificate with thumbprint {0}", certThumbprint));
            valid = true;
        }

        /// <summary>
        /// Encrypts the specified string expression
        /// </summary>
        /// <param name="plainText">string expression to encrypt</param>
        /// <returns>Base64-encoded ciphertext string expression</returns>
        public string EncryptText(string plainText)
        {
            byte[] cipherTextBytes;
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            using (AesManaged aesManaged = new AesManaged())
            {
                aesManaged.KeySize = 256;
                aesManaged.BlockSize = 128;
                aesManaged.Mode = CipherMode.CBC;

                using (ICryptoTransform transform = aesManaged.CreateDecryptor())
                {
                    RSAPKCS1KeyExchangeFormatter keyFormatter = new RSAPKCS1KeyExchangeFormatter(publicKey);
                    byte[] keyEncrypted = keyFormatter.CreateKeyExchange(aesManaged.Key, aesManaged.GetType());

                    //Contain the length values of the key and IV respectively
                    byte[] KeyLengthIndicator = new byte[4];
                    byte[] IVLengthIndicator = new byte[4];

                    //
                    int keyLength = keyEncrypted.Length;
                    KeyLengthIndicator = BitConverter.GetBytes(keyLength);

                    int IVLength = aesManaged.IV.Length;
                    IVLengthIndicator = BitConverter.GetBytes(IVLength);

                    using (MemoryStream memStream = new MemoryStream())
                    {
                        memStream.Write(KeyLengthIndicator, 0, 4);
                        memStream.Write(IVLengthIndicator, 0, 4);

                        memStream.Write(keyEncrypted, 0, keyLength);
                        memStream.Write(aesManaged.IV, 0, IVLength);

                        //Write the ciphertext using a CryptoStream
                        using (CryptoStream cryptoStream = new CryptoStream(memStream, transform, CryptoStreamMode.Write))
                        {
                            int count = 0;
                            int offset = 0;
                            int blockSizeInBytes = aesManaged.BlockSize / 8;
                            int bytesRead = 0;

                            byte[] data = new byte[blockSizeInBytes];

                            using (MemoryStream inStream = new MemoryStream(plainTextBytes, false))
                            {
                                do
                                {
                                    count = inStream.Read(data, 0, blockSizeInBytes);
                                    offset += count;
                                    cryptoStream.Write(data, 0, count);
                                    bytesRead += blockSizeInBytes;
                                }
                                while (count > 0);
                                inStream.Close();
                            }

                            cryptoStream.FlushFinalBlock();
                            cryptoStream.Close();
                            cipherTextBytes = memStream.ToArray();

                        }
                    }
                }

                return Convert.ToBase64String(cipherTextBytes);
            }
        }

        /// <summary>
        /// Encrypts the specified plaintext file.  Text and binary file types are supported.
        /// </summary>
        /// <param name="plainText">Fully-qualified path of the file to be encrypted</param>
        /// <param name="cipherText">Fully-qualified path in which to write the encrypted file</param>
        public void EncryptFile(string plainText, string cipherText)
        {
            using (AesManaged aesManaged = new AesManaged())
            {
                aesManaged.KeySize = 256;
                aesManaged.BlockSize = 128;
                aesManaged.Mode = CipherMode.CBC;

                using (ICryptoTransform transform = aesManaged.CreateEncryptor())
                {
                    RSAPKCS1KeyExchangeFormatter keyFormatter = new RSAPKCS1KeyExchangeFormatter(publicKey);
                    byte[] keyEncrypted = keyFormatter.CreateKeyExchange(aesManaged.Key, aesManaged.GetType());

                    //Contain the length values of the key and IV respectively
                    byte[] KeyLengthIndicator = new byte[4];
                    byte[] IVLengthIndicator = new byte[4];

                    //
                    int keyLength = keyEncrypted.Length;
                    KeyLengthIndicator = BitConverter.GetBytes(keyLength);

                    int IVLength = aesManaged.IV.Length;
                    IVLengthIndicator = BitConverter.GetBytes(IVLength);

                    using (FileStream outFS = new FileStream(cipherText, FileMode.Create))
                    {
                        outFS.Write(KeyLengthIndicator, 0, 4);
                        outFS.Write(IVLengthIndicator, 0, 4);

                        outFS.Write(keyEncrypted, 0, keyLength);
                        outFS.Write(aesManaged.IV, 0, IVLength);

                        using (CryptoStream outStreamEncrypted = new CryptoStream(outFS, transform, CryptoStreamMode.Write))
                        {
                            int count = 0;
                            int offset = 0;
                            int blockSizeInBytes = aesManaged.BlockSize / 8;
                            int bytesRead = 0;

                            byte[] data = new byte[blockSizeInBytes];

                            using (FileStream inStream = new FileStream(plainText, FileMode.Open))
                            {
                                do
                                {
                                    count = inStream.Read(data, 0, blockSizeInBytes);
                                    offset += count;
                                    outStreamEncrypted.Write(data, 0, count);
                                    bytesRead += blockSizeInBytes;
                                }
                                while (count > 0);
                                inStream.Close();
                            }
                            outStreamEncrypted.FlushFinalBlock();
                            outStreamEncrypted.Close();
                        }
                        outFS.Close();
                    }
                }
                if (!File.Exists(cipherText))
                    throw new FileNotFoundException(string.Format("\"{0}\": Ciphertext file not created", cipherText));
            }
        }

        /// <summary>
        /// Encrypts an array of bytes and stores the encrypted playload in the specified file path
        /// </summary>
        /// <param name="memBytes">The byte array to encrypt</param>
        /// <param name="cipherText">The file path in which to store the encrypted payload</param>
        public void EncryptFileFromByteArray(byte[] memBytes, string cipherText)
        {
            using (AesManaged aesManaged = new AesManaged())
            {
                aesManaged.KeySize = 256;
                aesManaged.BlockSize = 128;
                aesManaged.Mode = CipherMode.CBC;

                using (ICryptoTransform transform = aesManaged.CreateEncryptor())
                {
                    RSAPKCS1KeyExchangeFormatter keyFormatter = new RSAPKCS1KeyExchangeFormatter(publicKey);
                    byte[] keyEncrypted = keyFormatter.CreateKeyExchange(aesManaged.Key, aesManaged.GetType());

                    //Contain the length values of the key and IV respectively
                    byte[] KeyLengthIndicator = new byte[4];
                    byte[] IVLengthIndicator = new byte[4];

                    //
                    int keyLength = keyEncrypted.Length;
                    KeyLengthIndicator = BitConverter.GetBytes(keyLength);

                    int IVLength = aesManaged.IV.Length;
                    IVLengthIndicator = BitConverter.GetBytes(IVLength);

                    using (FileStream outFS = new FileStream(cipherText, FileMode.Create))
                    {
                        outFS.Write(KeyLengthIndicator, 0, 4);
                        outFS.Write(IVLengthIndicator, 0, 4);

                        outFS.Write(keyEncrypted, 0, keyLength);
                        outFS.Write(aesManaged.IV, 0, IVLength);

                        using (CryptoStream outStreamEncrypted = new CryptoStream(outFS, transform, CryptoStreamMode.Write))
                        {
                            int count = 0;
                            int offset = 0;
                            int blockSizeInBytes = aesManaged.BlockSize / 8;
                            int bytesRead = 0;

                            byte[] data = new byte[blockSizeInBytes];

                            using (MemoryStream memStream = new MemoryStream(memBytes))
                            {
                                do
                                {
                                    count = memStream.Read(data, 0, blockSizeInBytes);
                                    offset += count;
                                    outStreamEncrypted.Write(data, 0, count);
                                    bytesRead += blockSizeInBytes;
                                }
                                while (count > 0);
                            }

                            outStreamEncrypted.FlushFinalBlock();
                            outStreamEncrypted.Close();
                        }
                        outFS.Close();
                    }
                }

                if (!File.Exists(cipherText))
                    throw new FileNotFoundException(string.Format("\"{0}\": Ciphertext file not created", cipherText));
            }
        }

        /// <summary>
        /// Decrypts the specified ciphertext string expression
        /// </summary>
        /// <param name="cipherText">Base64-encoded ciphertext string expression</param>
        /// <returns>decrypted string expression</returns>
        public string DecryptText(string cipherText)
        {
            string plainText;

            byte[] cipherTextBytes = Convert.FromBase64String(cipherText);
            byte[] plainTextBytes = new byte[cipherTextBytes.Length];

            using (AesManaged aesManaged = new AesManaged())
            {
                aesManaged.KeySize = 256;
                aesManaged.BlockSize = 128;
                aesManaged.Mode = CipherMode.CBC;

                byte[] KeyLengthIndicator = new byte[4];
                byte[] IVLengthIndicator = new byte[4];

                using (MemoryStream inStream = new MemoryStream(cipherTextBytes))
                {
                    inStream.Seek(0, SeekOrigin.Begin);
                    inStream.Seek(0, SeekOrigin.Begin);
                    inStream.Read(KeyLengthIndicator, 0, 3);

                    inStream.Seek(4, SeekOrigin.Begin);
                    inStream.Read(IVLengthIndicator, 0, 3);

                    int keyLength = BitConverter.ToInt32(KeyLengthIndicator, 0);
                    int IVLength = BitConverter.ToInt32(IVLengthIndicator, 0);

                    int cipherTextStartingPoint = keyLength + IVLength + 8;
                    int cipherTextLength = (int)inStream.Length - cipherTextStartingPoint;

                    byte[] keyEncrypted = new byte[keyLength];
                    byte[] IV = new byte[IVLength];

                    //Read the encrypted symetric key
                    inStream.Seek(8, SeekOrigin.Begin);
                    inStream.Read(keyEncrypted, 0, keyLength);

                    //Read in the Initialization Vector
                    inStream.Seek(8 + keyLength, SeekOrigin.Begin);
                    inStream.Read(IV, 0, IVLength);

                    byte[] keyDecrypted = privateKey.Decrypt(keyEncrypted, false);

                    using (ICryptoTransform transform = aesManaged.CreateDecryptor(keyDecrypted, IV))
                    {
                        using (MemoryStream outStream = new MemoryStream())
                        {
                            int count = 0;
                            int offset = 0;
                            int blockSizeInBytes = aesManaged.BlockSize / 8;

                            byte[] data = new byte[blockSizeInBytes];
                            inStream.Seek(cipherTextStartingPoint, SeekOrigin.Begin);

                            using (CryptoStream cryptoStream = new CryptoStream(outStream, transform, CryptoStreamMode.Write))
                            {
                                do
                                {
                                    count = inStream.Read(data, 0, blockSizeInBytes);
                                    offset += count;
                                    cryptoStream.Write(data, 0, count);
                                }
                                while (count > 0);

                                cryptoStream.FlushFinalBlock();
                                outStream.Flush();
                                outStream.Position = 0;

                                using (StreamReader reader = new StreamReader(outStream))
                                    plainText = reader.ReadToEnd();

                                cryptoStream.Close();
                            }
                            outStream.Close();
                        }
                    }
                }
            }
            return plainText;
        }

        /// <summary>
        /// Decrypts the specified ciphertext file
        /// </summary>
        /// <param name="cipherText">Fully-qualified path to the encrypted file</param>
        /// <param name="plainText">Fully-qualified path in which to write the decrypted file</param>
        public void DecryptFile(string cipherText, string plainText)
        {
            using (AesManaged aesManaged = new AesManaged())
            {
                aesManaged.KeySize = 256;
                aesManaged.BlockSize = 128;
                aesManaged.Mode = CipherMode.CBC;

                byte[] KeyLengthIndicator = new byte[4];
                byte[] IVLengthIndicator = new byte[4];

                using (FileStream inFS = new FileStream(cipherText, FileMode.Open))
                {
                    inFS.Seek(0, SeekOrigin.Begin);
                    inFS.Seek(0, SeekOrigin.Begin);
                    inFS.Read(KeyLengthIndicator, 0, 3);

                    inFS.Seek(4, SeekOrigin.Begin);
                    inFS.Read(IVLengthIndicator, 0, 3);

                    int keyLength = BitConverter.ToInt32(KeyLengthIndicator, 0);
                    int IVLength = BitConverter.ToInt32(IVLengthIndicator, 0);

                    int cipherTextStart = keyLength + IVLength + 8;
                    int cipherTextLength = (int)inFS.Length - cipherTextStart;

                    byte[] keyEncrypted = new byte[keyLength];
                    byte[] IV = new byte[IVLength];

                    inFS.Seek(8, SeekOrigin.Begin);
                    inFS.Read(keyEncrypted, 0, keyLength);

                    inFS.Seek(8 + keyLength, SeekOrigin.Begin);
                    inFS.Read(IV, 0, IVLength);

                    byte[] keyDecrypted = privateKey.Decrypt(keyEncrypted, false);

                    using (ICryptoTransform transform = aesManaged.CreateDecryptor(keyDecrypted, IV))
                    {
                        using (FileStream outFS = new FileStream(plainText, FileMode.Create))
                        {
                            int count = 0;
                            int offset = 0;
                            int blockSizeInBytes = aesManaged.BlockSize / 8;

                            byte[] data = new byte[blockSizeInBytes];

                            inFS.Seek(cipherTextStart, SeekOrigin.Begin);
                            using (CryptoStream decryptedStream = new CryptoStream(outFS, transform, CryptoStreamMode.Write))
                            {
                                do
                                {
                                    count = inFS.Read(data, 0, blockSizeInBytes);
                                    offset += count;
                                    decryptedStream.Write(data, 0, count);
                                }
                                while (count > 0);

                                decryptedStream.FlushFinalBlock();
                                decryptedStream.Close();
                            }
                            outFS.Close();
                        }
                    }
                }
            }
            if (!File.Exists(plainText))
                throw new FileNotFoundException(string.Format("\"{0}\": plaintext file not created.", plainText));
        }

        /// <summary>
        /// Decrypts a file and stores the payload in a byte array
        /// </summary>
        /// <param name="cipherText">The fully-qualified path to the encrypted file</param>
        /// <returns>Byte array containing the decrypted contents of the ciphertext file</returns>
        public byte[] DecryptFileToByteArray(string cipherText)
        {
            MemoryStream outMs = new MemoryStream();
            CryptoStream decryptedStream = null;
            byte[] memBytes = null;

            using (AesManaged aesManaged = new AesManaged())
            {
                aesManaged.KeySize = 256;
                aesManaged.BlockSize = 128;
                aesManaged.Mode = CipherMode.CBC;

                byte[] KeyLengthIndicator = new byte[4];
                byte[] IVLengthIndicator = new byte[4];

                using (FileStream inFS = new FileStream(cipherText, FileMode.Open))
                {
                    inFS.Seek(0, SeekOrigin.Begin);
                    inFS.Seek(0, SeekOrigin.Begin);
                    inFS.Read(KeyLengthIndicator, 0, 3);

                    inFS.Seek(4, SeekOrigin.Begin);
                    inFS.Read(IVLengthIndicator, 0, 3);

                    int keyLength = BitConverter.ToInt32(KeyLengthIndicator, 0);
                    int IVLength = BitConverter.ToInt32(IVLengthIndicator, 0);

                    int cipherTextStart = keyLength + IVLength + 8;
                    int cipherTextLength = (int)inFS.Length - cipherTextStart;

                    byte[] keyEncrypted = new byte[keyLength];
                    byte[] IV = new byte[IVLength];

                    inFS.Seek(8, SeekOrigin.Begin);
                    inFS.Read(keyEncrypted, 0, keyLength);

                    inFS.Seek(8 + keyLength, SeekOrigin.Begin);
                    inFS.Read(IV, 0, IVLength);

                    byte[] keyDecrypted = privateKey.Decrypt(keyEncrypted, false);

                    using (ICryptoTransform transform = aesManaged.CreateDecryptor(keyDecrypted, IV))
                    {
                            int count = 0;
                            int offset = 0;
                            int blockSizeInBytes = aesManaged.BlockSize / 8;

                            byte[] data = new byte[blockSizeInBytes];

                            inFS.Seek(cipherTextStart, SeekOrigin.Begin);
                            using (decryptedStream = new CryptoStream(outMs, transform, CryptoStreamMode.Write))
                            {
                                do
                                {
                                    count = inFS.Read(data, 0, blockSizeInBytes);
                                    offset += count;
                                    decryptedStream.Write(data, 0, count);
                                }
                                while (count > 0);

                                decryptedStream.FlushFinalBlock();
                                memBytes = new byte[outMs.Length];
                                outMs.Position = 0;
                                outMs.Read(memBytes, 0, memBytes.Length);
                                decryptedStream.Close();
                            }
                            inFS.Close();
                    }
                }
            }

            return memBytes;
        }

        /// <summary>
        /// Decrypts a ciphertext expression that is stored in a text file
        /// </summary>
        /// <param name="path">The fully-qualified path to the file containing the ciphertext expression</param>
        /// <returns>decrypted text expression</returns>
        public string DecryptTextFromFile(string path)
        {
            if (!File.Exists(path))
                throw new FileNotFoundException(string.Format("\"{0}\": file not found.", path));

            string cipherText;
            using (FileStream inStream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                using (StreamReader reader = new StreamReader(inStream))
                {
                    cipherText = reader.ReadToEnd().Trim(new char[] { '\r', '\n', ' '});
                    reader.Close();
                }
                inStream.Close();
            }

            return DecryptText(cipherText);
        }


        #endregion

        #region Static Methods

        /// <summary>
        /// Indicates whether the specified certificate thumbprint was found in the specified certificate store
        /// </summary>
        /// <param name="certThumbprint">The certificate thumbprint value to search for (case-insensitive)</param>
        /// <param name="storeLocation">The certificate store location in which to search (either StoreLocation.CurrentUser or StoreLocation.LocalMachine)</param>
        /// <returns>True or False depending upon whether the certificate and corresponding private key was found in the certificate store</returns>
        public static bool thumbprintFound(string certThumbprint, StoreLocation storeLocation)
        {
            certThumbprint = x509Utils.cleanThumbprint(certThumbprint);

            X509Store store = new X509Store(StoreName.My, storeLocation);
            store.Open(OpenFlags.ReadOnly);
            foreach (X509Certificate2 cert in store.Certificates)
            {
                if (string.Equals(certThumbprint, cert.Thumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    if (cert.HasPrivateKey)
                        return true;
                    else
                    {
                        x509CryptoLog.Warning(string.Format("A certificate with thumbprint {0} was found, but the corresponding private key is not present in the {1} certificate store", certThumbprint, x509Utils.GetEnumDescription(storeLocation)));
                        return false;
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Exports the certificate and public/private key pair corresponding to the specified certificate thumbprint to a PKCS#12 bundle written to the specified file path
        /// </summary>
        /// <param name="certThumbprint">Certificate thumbprint (case-insensitive)</param>
        /// <param name="storeLocation">Certificate store location where the specified certificate and private key are located (either StoreLocation.CurrentUser or StoreLocation.LocalMachine)</param>
        /// <param name="exportPath">Fully-qualified path to where the PKCS#12 bundle file should be written (a ".pfx" file extension will be added if no file extension is detected)</param>
        /// <param name="password">Password to protect the private key once stored in the PKCS#12 bundle file</param>
        /// <returns>The fully-qualified path to where the PKCS#12 bundle file was ultimately written</returns>
        public static string exportPFX(string certThumbprint, StoreLocation storeLocation, string exportPath, string password)
        {
            if (!Path.HasExtension(exportPath))
                exportPath += @".pfx";

            if (File.Exists(exportPath))
                File.Delete(exportPath);

            certThumbprint = x509Utils.cleanThumbprint(certThumbprint);
            x509CryptoLog.Massive(string.Format("Sanitized certificate thumbprint: {0}", certThumbprint));

            X509Store store = new X509Store(StoreName.My, storeLocation);
            store.Open(OpenFlags.ReadOnly);
            foreach(X509Certificate2 cert in store.Certificates)
            {
                if (string.Equals(certThumbprint, cert.Thumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    byte[] certBytes = cert.Export(X509ContentType.Pkcs12, password);
                    File.WriteAllBytes(exportPath, certBytes);
                    x509Utils.VerifyFile(exportPath);
                    return exportPath;
                }
            }

            throw new CertificateNotFoundException(certThumbprint, storeLocation);
        }

        /// <summary>
        /// Exports the certificate corresponding to the specified certificate thumbprint to a Base64-encoded text file
        /// </summary>
        /// <param name="certThumbprint">Certificate thumbprint (case-insensitive)</param>
        /// <param name="storeLocation">Certificate store location where the specified certificate is located (either StoreLocation.CurrentUser or StoreLocation.LocalMachine)</param>
        /// <param name="exportPath">Fully-qualified path to where the Base64-encoded file should be written (a ".cer" file extension will be added if no file extension is detected)</param>
        /// <returns>The fully-qualified path to where the Base64-encoded certificate file was ultimately written</returns>
        public static string exportCert(string certThumbprint, StoreLocation storeLocation, string exportPath)
        {
            if (!Path.HasExtension(exportPath))
                exportPath += @".cer";

            if (!File.Exists(exportPath))
                File.Delete(exportPath);

            certThumbprint = x509Utils.cleanThumbprint(certThumbprint);
            X509Store store = new X509Store(StoreName.My, storeLocation);
            store.Open(OpenFlags.ReadOnly);

            foreach(X509Certificate2 cert in store.Certificates)
            {
                if (string.Equals(certThumbprint, cert.Thumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    using (FileStream outStream = new FileStream(exportPath, FileMode.CreateNew, FileAccess.ReadWrite))
                    {
                        using (TextWriter streamWriter = new StreamWriter(outStream))
                        {
                            streamWriter.WriteLine(@"-----BEGIN CERTIFICATE-----");
                            streamWriter.WriteLine(Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
                            streamWriter.WriteLine(@"-----END CERTIFICATE-----");
                            streamWriter.Close();
                        }
                        outStream.Close();
                    }

                    x509Utils.VerifyFile(exportPath);

                    try
                    {
                        X509Certificate2 test = new X509Certificate2(exportPath);
                        x509CryptoLog.Info(string.Format("Certificate with thumbprint {0} was successfully exported to {1}", certThumbprint, exportPath));
                    }
                    catch (CryptographicException ex)
                    {
                        x509CryptoLog.Exception( ex, x509CryptoLog.Level.ERROR, string.Format("Certificate with thumbprint {0} was exported to path \"{1}\" but the file seems to be corrupt and unusable", certThumbprint, exportPath));
                    }

                    return exportPath;
                }
            }

            throw new CertificateNotFoundException(certThumbprint, storeLocation);
        }

        /// <summary>
        /// Lists the thumbprint value for each certificate in the specified store location which include "Key Encipherment" in its Key Usage extension
        /// </summary>
        /// <param name="storeLocation">Store location from which to list certificate details (Either StoreLocation.CurrentUser or StoreLocation.LocalMachine)</param>
        /// <param name="allowExpired">If set to True, expired certificates will be included in the output (Note that .NET will not perform cryptographic operations using a certificate which is not within its validity period)</param>
        /// <returns></returns>
        public static string listCerts(StoreLocation storeLocation, bool allowExpired)
        {
            string output = "Key Encipherment Certificates found:\r\n\r\n";
            bool firstAdded = false;

            X509Store store = new X509Store(storeLocation);
            store.Open(OpenFlags.ReadOnly);
            foreach(X509Certificate2 cert in store.Certificates)
            {
                if (isUsable(cert, allowExpired))
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

        private static bool isUsable(X509Certificate2 cert, bool allowExpired)
        {
            foreach (X509Extension extension in cert.Extensions)
            {
                if (extension.Oid.FriendlyName == "Key Usage")
                {
                    X509KeyUsageExtension ext = (X509KeyUsageExtension)extension;
                    if (ext.KeyUsages == X509KeyUsageFlags.KeyEncipherment)
                    {
                        return (allowExpired | (cert.NotAfter > DateTime.Now && cert.NotBefore <= DateTime.Now));
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Overwrites a file (as stored on disk) with random bits in order to prevent forensic recovery of the data
        /// </summary>
        /// <param name="filePath">The fully-qualified path of the file to wipe from disk</param>
        /// <param name="timesToWrite">The number of times to overwrite the disk sectors where the file is/was stored</param>
        public void WipeFile(string filePath, int timesToWrite)
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
    }

    internal class CertificateNotFoundException : Exception
    {
        public CertificateNotFoundException(string certThumbprint, StoreLocation storeLocation)
            :base(string.Format("A certificate with thumbprint {0} could not be found in the {1} store location", certThumbprint, x509Utils.GetEnumDescription(storeLocation)))
        {
        }
    }
}
