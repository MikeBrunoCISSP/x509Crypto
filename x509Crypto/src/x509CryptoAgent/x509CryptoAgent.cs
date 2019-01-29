using System;
using System.Text;
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

        const int AES_KEY_SIZE = 256;
        const int AES_BLOCK_SIZE = 128;

        const int AES_BYTES = 4;
        const int AES_READ_COUNT = AES_BYTES - 1;
        const int AES_BYTES_DOUBLED = AES_BYTES * 2;

        const bool LEAVE_MEMSTREAM_OPEN = true;

        #endregion

        #region Member Fields

        private RSACryptoServiceProvider publicKey,
                                         privateKey;

        private string thumbprint;

        public string Thumbprint
        {
            get
            {
                return thumbprint;
            }
            private set
            {
                thumbprint = x509Utils.FormatThumbprint(value);
            }
        }
        public CertStore Store { get; private set; }


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
        public x509CryptoAgent(string Thumbprint, CertStore Store)
        {
            this.Thumbprint = Thumbprint;
            this.Store = Store;
            GetRSAKeys();
        }

        /// <summary>
        /// x509CryptoAgent Constructor
        /// </summary>
        /// <param name="certThumbprint">The thumbprint of the encryption certificate.</param>
        /// <param name="sStore">String representation of the certificate store where the encryption certificate resides ("CURRENTUSER" or "LOCALMACHINE")</param>
        public x509CryptoAgent(string Thumbprint, string sStore)
        {
            this.Thumbprint = Thumbprint;
            Store = CertStore.GetByName(sStore);
            GetRSAKeys();
        }

        /// <summary>
        /// x509CryptoAgent Constructor
        /// </summary>
        /// <param name="inStream">FileStream pointing to a text file containing the encryption certificate thumbprint. The certificate must be present in the CURRENTUSER store location</param>
        public x509CryptoAgent(FileStream inStream, CertStore Store)
        {
            using (StreamReader reader = new StreamReader(inStream))
            {
                Thumbprint = reader.ReadToEnd();
                reader.Close();
            }

            this.Store = Store;

            GetRSAKeys();
        }

        /// <summary>
        /// x509CryptoAgent Constructor
        /// </summary>
        /// <param name="inStream">FileStream pointing to a text file containing the encryption certificate thumbprint.</param>
        /// <param name="sStore">String representation of the certificate store where the encryption certificate resides ("CURRENTUSER" or "LOCALMACHINE")</param>
        public x509CryptoAgent(FileStream inStream, string sStore)
        {
            using (StreamReader reader = new StreamReader(inStream))
            {
                Thumbprint = reader.ReadToEnd();
                reader.Close();
            }

            Store = CertStore.GetByName(sStore);

            GetRSAKeys();
        }

        /// <summary>
        /// x509CryptoAgent Destructor
        /// </summary>
        public void Dispose()
        {
            publicKey = null;
            privateKey = null;
            thumbprint = string.Empty;
            Store = null;
        }

        #endregion

        #region Member Methods

        private void GetRSAKeys()
        {
            X509Certificate2Collection colletion = new X509Certificate2Collection();
            X509Store keyStore = new X509Store(Store.Location);
            keyStore.Open(OpenFlags.ReadOnly);
            foreach(X509Certificate2 cert in keyStore.Certificates)
            {
                if (string.Equals(cert.Thumbprint, Thumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    if (cert.HasPrivateKey & IsUsable(cert, false))
                        colletion.Add(cert);
                }
            }

            if (colletion.Count != 1)
                throw new CertificateNotFoundException(Thumbprint, Store);

            foreach (X509Certificate2 cert in colletion)
            {
                publicKey = (RSACryptoServiceProvider)cert.PublicKey.Key;
                privateKey = (RSACryptoServiceProvider)cert.PrivateKey;
            }
            x509CryptoLog.Info(string.Format("Successfully loaded keypair of certificate with thumbprint {0}", Thumbprint));
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
                aesManaged.KeySize = AES_KEY_SIZE;
                aesManaged.BlockSize = AES_BLOCK_SIZE;
                aesManaged.Mode = CipherMode.CBC;

                using (ICryptoTransform transform = aesManaged.CreateEncryptor())
                {
                    RSAPKCS1KeyExchangeFormatter keyFormatter = new RSAPKCS1KeyExchangeFormatter(publicKey);
                    byte[] keyEncrypted = keyFormatter.CreateKeyExchange(aesManaged.Key, aesManaged.GetType());

                    //Contain the length values of the key and IV respectively
                    byte[] KeyLengthIndicator = new byte[AES_BYTES];
                    byte[] IVLengthIndicator = new byte[AES_BYTES];

                    //Byte arrays to contain the length values of the key and IV
                    int keyLength = keyEncrypted.Length;
                    KeyLengthIndicator = BitConverter.GetBytes(keyLength);

                    int IVLength = aesManaged.IV.Length;
                    IVLengthIndicator = BitConverter.GetBytes(IVLength);

                    using (MemoryStream memStream = new MemoryStream())
                    {
                        memStream.Write(KeyLengthIndicator, 0, AES_BYTES);
                        memStream.Write(IVLengthIndicator, 0, AES_BYTES);

                        memStream.Write(keyEncrypted, 0, keyLength);
                        memStream.Write(aesManaged.IV, 0, IVLength);

                        //Write the ciphertext using a CryptoStream
                        using (CryptoStream cryptoStream = new CryptoStream(memStream, transform, CryptoStreamMode.Write))
                        {
                            int count = 0;
                            int offset = 0;
                            int blockSizeInBytes = aesManaged.BlockSize / AES_BYTES_DOUBLED;

                            byte[] data = new byte[blockSizeInBytes];
                            int bytesRead = 0;

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
                aesManaged.KeySize = AES_KEY_SIZE;
                aesManaged.BlockSize = AES_BLOCK_SIZE;
                aesManaged.Mode = CipherMode.CBC;

                using (ICryptoTransform transform = aesManaged.CreateEncryptor())
                {
                    RSAPKCS1KeyExchangeFormatter keyFormatter = new RSAPKCS1KeyExchangeFormatter(publicKey);
                    byte[] keyEncrypted = keyFormatter.CreateKeyExchange(aesManaged.Key, aesManaged.GetType());

                    //Contain the length values of the key and IV respectively
                    byte[] KeyLengthIndicator = new byte[AES_BYTES];
                    byte[] IVLengthIndicator = new byte[AES_BYTES];

                    
                    int keyLength = keyEncrypted.Length;
                    KeyLengthIndicator = BitConverter.GetBytes(keyLength);

                    int IVLength = aesManaged.IV.Length;
                    IVLengthIndicator = BitConverter.GetBytes(IVLength);

                    using (FileStream outFS = new FileStream(cipherText, FileMode.Create))
                    {
                        outFS.Write(KeyLengthIndicator, 0, AES_BYTES);
                        outFS.Write(IVLengthIndicator, 0, AES_BYTES);

                        outFS.Write(keyEncrypted, 0, keyLength);
                        outFS.Write(aesManaged.IV, 0, IVLength);

                        using (CryptoStream outStreamEncrypted = new CryptoStream(outFS, transform, CryptoStreamMode.Write))
                        {
                            int count = 0;
                            int offset = 0;
                            int blockSizeInBytes = aesManaged.BlockSize / AES_BYTES_DOUBLED;

                            byte[] data = new byte[blockSizeInBytes];
                            int bytesRead = 0;

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
                aesManaged.KeySize = AES_KEY_SIZE;
                aesManaged.BlockSize = AES_BLOCK_SIZE;
                aesManaged.Mode = CipherMode.CBC;

                using (ICryptoTransform transform = aesManaged.CreateEncryptor())
                {
                    RSAPKCS1KeyExchangeFormatter keyFormatter = new RSAPKCS1KeyExchangeFormatter(publicKey);
                    byte[] keyEncrypted = keyFormatter.CreateKeyExchange(aesManaged.Key, aesManaged.GetType());

                    //Contain the length values of the key and IV respectively
                    byte[] KeyLengthIndicator = new byte[AES_BYTES];
                    byte[] IVLengthIndicator = new byte[AES_BYTES];

                    //
                    int keyLength = keyEncrypted.Length;
                    KeyLengthIndicator = BitConverter.GetBytes(keyLength);

                    int IVLength = aesManaged.IV.Length;
                    IVLengthIndicator = BitConverter.GetBytes(IVLength);

                    using (FileStream outFS = new FileStream(cipherText, FileMode.Create))
                    {
                        outFS.Write(KeyLengthIndicator, 0, AES_BYTES);
                        outFS.Write(IVLengthIndicator, 0, AES_BYTES);

                        outFS.Write(keyEncrypted, 0, keyLength);
                        outFS.Write(aesManaged.IV, 0, IVLength);

                        using (CryptoStream outStreamEncrypted = new CryptoStream(outFS, transform, CryptoStreamMode.Write))
                        {
                            int count = 0;
                            int offset = 0;
                            int blockSizeInBytes = aesManaged.BlockSize / AES_BYTES_DOUBLED;

                            byte[] data = new byte[blockSizeInBytes];
                            int bytesRead = 0;

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
                aesManaged.KeySize = AES_KEY_SIZE;
                aesManaged.BlockSize = AES_BLOCK_SIZE;
                aesManaged.Mode = CipherMode.CBC;

                byte[] KeyLengthIndicator = new byte[AES_BYTES];
                byte[] IVLengthIndicator = new byte[AES_BYTES];

                using (MemoryStream inStream = new MemoryStream(cipherTextBytes))
                {
                    inStream.Seek(0, SeekOrigin.Begin);
                    inStream.Seek(0, SeekOrigin.Begin);
                    inStream.Read(KeyLengthIndicator, 0, (AES_BYTES-1));

                    inStream.Seek(AES_BYTES, SeekOrigin.Begin);
                    inStream.Read(IVLengthIndicator, 0, (AES_BYTES - 1));

                    int keyLength = BitConverter.ToInt32(KeyLengthIndicator, 0);
                    int IVLength = BitConverter.ToInt32(IVLengthIndicator, 0);

                    int cipherTextStartingPoint = keyLength + IVLength + AES_BYTES_DOUBLED;
                    int cipherTextLength = (int)inStream.Length - cipherTextStartingPoint;

                    byte[] keyEncrypted = new byte[keyLength];
                    byte[] IV = new byte[IVLength];

                    //Read the encrypted symetric key
                    inStream.Seek(AES_BYTES_DOUBLED, SeekOrigin.Begin);
                    inStream.Read(keyEncrypted, 0, keyLength);

                    //Read in the Initialization Vector
                    inStream.Seek(AES_BYTES_DOUBLED + keyLength, SeekOrigin.Begin);
                    inStream.Read(IV, 0, IVLength);

                    byte[] keyDecrypted = privateKey.Decrypt(keyEncrypted, false);

                    using (ICryptoTransform transform = aesManaged.CreateDecryptor(keyDecrypted, IV))
                    {
                        using (MemoryStream outStream = new MemoryStream())
                        {
                            int count = 0;
                            int offset = 0;
                            int blockSizeInBytes = aesManaged.BlockSize / AES_BYTES_DOUBLED;

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
                aesManaged.KeySize = AES_KEY_SIZE;
                aesManaged.BlockSize = AES_BLOCK_SIZE;
                aesManaged.Mode = CipherMode.CBC;

                byte[] KeyLengthIndicator = new byte[AES_BYTES];
                byte[] IVLengthIndicator = new byte[AES_BYTES];

                using (FileStream inFS = new FileStream(cipherText, FileMode.Open))
                {
                    inFS.Seek(0, SeekOrigin.Begin);
                    inFS.Seek(0, SeekOrigin.Begin);
                    inFS.Read(KeyLengthIndicator, 0, AES_READ_COUNT);

                    inFS.Seek(4, SeekOrigin.Begin);
                    inFS.Read(IVLengthIndicator, 0, AES_READ_COUNT);

                    int keyLength = BitConverter.ToInt32(KeyLengthIndicator, 0);
                    int IVLength = BitConverter.ToInt32(IVLengthIndicator, 0);

                    int cipherTextStart = keyLength + IVLength + AES_BYTES_DOUBLED;
                    int cipherTextLength = (int)inFS.Length - cipherTextStart;

                    byte[] keyEncrypted = new byte[keyLength];
                    byte[] IV = new byte[IVLength];

                    inFS.Seek(AES_BYTES_DOUBLED, SeekOrigin.Begin);
                    inFS.Read(keyEncrypted, 0, keyLength);

                    inFS.Seek(AES_BYTES_DOUBLED + keyLength, SeekOrigin.Begin);
                    inFS.Read(IV, 0, IVLength);

                    byte[] keyDecrypted = privateKey.Decrypt(keyEncrypted, false);

                    using (ICryptoTransform transform = aesManaged.CreateDecryptor(keyDecrypted, IV))
                    {
                        using (FileStream outFS = new FileStream(plainText, FileMode.Create))
                        {
                            int count = 0;
                            int offset = 0;
                            int blockSizeInBytes = aesManaged.BlockSize / AES_BYTES_DOUBLED;

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
                aesManaged.KeySize = AES_KEY_SIZE;
                aesManaged.BlockSize = AES_BLOCK_SIZE;
                aesManaged.Mode = CipherMode.CBC;

                byte[] KeyLengthIndicator = new byte[AES_BYTES];
                byte[] IVLengthIndicator = new byte[AES_BYTES];

                using (FileStream inFS = new FileStream(cipherText, FileMode.Open))
                {
                    inFS.Seek(0, SeekOrigin.Begin);
                    inFS.Seek(0, SeekOrigin.Begin);
                    inFS.Read(KeyLengthIndicator, 0, AES_READ_COUNT);

                    inFS.Seek(AES_BYTES, SeekOrigin.Begin);
                    inFS.Read(IVLengthIndicator, 0, AES_READ_COUNT);

                    int keyLength = BitConverter.ToInt32(KeyLengthIndicator, 0);
                    int IVLength = BitConverter.ToInt32(IVLengthIndicator, 0);

                    int cipherTextStart = keyLength + IVLength + AES_BYTES_DOUBLED;
                    int cipherTextLength = (int)inFS.Length - cipherTextStart;

                    byte[] keyEncrypted = new byte[keyLength];
                    byte[] IV = new byte[IVLength];

                    inFS.Seek(AES_BYTES_DOUBLED, SeekOrigin.Begin);
                    inFS.Read(keyEncrypted, 0, keyLength);

                    inFS.Seek(AES_BYTES_DOUBLED + keyLength, SeekOrigin.Begin);
                    inFS.Read(IV, 0, IVLength);

                    byte[] keyDecrypted = privateKey.Decrypt(keyEncrypted, false);

                    using (ICryptoTransform transform = aesManaged.CreateDecryptor(keyDecrypted, IV))
                    {
                            int count = 0;
                            int offset = 0;
                            int blockSizeInBytes = aesManaged.BlockSize / AES_BYTES_DOUBLED;

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
        public static bool thumbprintFound(string certThumbprint, CertStore certStore)
        {
            certThumbprint = x509Utils.FormatThumbprint(certThumbprint);

            X509Store store = new X509Store(StoreName.My, certStore.Location);
            store.Open(OpenFlags.ReadOnly);
            foreach (X509Certificate2 cert in store.Certificates)
            {
                if (string.Equals(certThumbprint, cert.Thumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    if (cert.HasPrivateKey)
                        return true;
                    else
                    {
                        x509CryptoLog.Warning(string.Format("A certificate with thumbprint {0} was found, but the corresponding private key is not present in the {1} certificate store", certThumbprint, certStore.Name));
                        return false;
                    }
                }
            }

            return false;
        }

        internal static bool IsUsable(X509Certificate2 cert, bool allowExpired)
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

        #endregion
    }

    internal class CertificateNotFoundException : Exception
    {
        public CertificateNotFoundException(string certThumbprint, CertStore certStore)
            :base(string.Format("A certificate with thumbprint {0} could not be found in the {1} store location", certThumbprint, certStore.Name))
        {
        }
    }
}
