using System;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.IO;
using System.Runtime.Serialization;

namespace Org.X509Crypto
{
    /// <summary>
    /// Instantiatable class which can be used to perform cryptographic operations on string expressions and files. 
    /// </summary>
    /// <remarks>
    /// It is advisable to leverage an instance of this class in your method/module if you need to perform several cryptographic operations within the stack frame.
    /// </remarks>
    public class X509CryptoAgent : IDisposable
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

        private bool VerboseLogging;

        private string thumbprint;

        /// <summary>
        /// The thumbprint of the certificate used for cryptographic operations
        /// </summary>
        public string Thumbprint
        {
            get
            {
                return thumbprint;
            }
            private set
            {
                thumbprint = X509Utils.FormatThumbprint(value);
            }
        }

        /// <summary>
        /// The certificate store from which to load the encryption certificate and private key.
        /// </summary>
        /// <remarks>
        /// Possible values are <see cref="CertStore"/>.<see cref="CertStore.CurrentUser"/> or <see cref="CertStore"/>.<see cref="CertStore.LocalMachine"/><br/>
        /// If not specified, default value is <see cref="CertStore"/>.<see cref="CertStore.CurrentUser"/>
        /// </remarks>
        public CertStore Store { get; private set; }


        /// <summary>
        /// Indicates whether the instantiated <see cref="X509CryptoAgent"/> object is bound to an available valid certificate and corresponding private key that is appropriate for encryption
        /// </summary>
        public bool valid = false;

        #endregion

        #region Constructors and Destructors

        /// <summary>
        /// X509CryptoAgent Constructor
        /// </summary>
        /// <param name="Thumbprint">The thumbprint of the encryption certificate.  The certificate must be present in the CURRENTUSER store location</param>
        /// <param name="Store">
        /// <para>(Optional) The certificate store from which to load the encryption certificate.</para>  
        /// <para>Possible values are <see cref="CertStore"/>.<see cref="CertStore.CurrentUser"/> or <see cref="CertStore"/>.<see cref="CertStore.LocalMachine"/></para>
        /// <para>If not specified, default value is <see cref="CertStore"/>.<see cref="CertStore.CurrentUser"/></para></param>
        /// <param name="VerboseLogging">(Optional) Set to true to enable verbose activity logging</param>
        public X509CryptoAgent(string Thumbprint, CertStore Store = null, bool VerboseLogging = false)
        {
            this.Thumbprint = Thumbprint;

            if (Store == null)
                this.Store = CertStore.CurrentUser;
            else
                this.Store = Store;

            this.VerboseLogging = VerboseLogging;
            GetRSAKeys();
        }

        /// <summary>
        /// X509CryptoAgent Constructor
        /// </summary>
        /// <param name="inStream">FileStream pointing to a text file containing the encryption certificate thumbprint.</param>
        /// <param name="Store">
        /// <para>(Optional) The certificate store from which to load the encryption certificate.</para>
        /// <para>Possible values are <see cref="CertStore"/>.<see cref="CertStore.CurrentUser"/> or <see cref="CertStore"/>.<see cref="CertStore.LocalMachine"/></para>
        /// <para>If not specified, default value is <see cref="CertStore"/>.<see cref="CertStore.CurrentUser"/></para></param>
        /// <param name="VerboseLogging">(Optional) Set to true to enable verbose activity logging</param>
        public X509CryptoAgent(FileStream inStream, CertStore Store = null, bool VerboseLogging = false)
        {
            using (StreamReader reader = new StreamReader(inStream))
            {
                Thumbprint = reader.ReadToEnd();
                reader.Close();
            }

            if (Store == null)
                this.Store = CertStore.CurrentUser;
            else
                this.Store = Store;

            this.VerboseLogging = VerboseLogging;
            GetRSAKeys();
        }

        /// <summary>
        /// X509CryptoAgent Destructor
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
            X509CryptoLog.Info(string.Format("Successfully loaded keypair of certificate with thumbprint {0} from the {1} certificate store", Thumbprint, Store.Name), X509Utils.MethodName(), VerboseLogging, VerboseLogging);
            valid = true;
        }

        /// <summary>
        /// Encrypts the specified string expression
        /// </summary>
        /// <param name="plainText">Text expression to encrypt</param>
        /// <returns>Base64-encoded ciphertext expression</returns>
        /// <example>
        /// <code>
        /// string thumbprint = @"ccdc673c40ebb2a433300c0c8a2ba6f443da5688";
        /// <see cref="CertStore"/> certStore = <see cref="CertStore"/>.<see cref="CertStore.CurrentUser"/>;
        /// 
        /// string plaintext = @"Hello world!";
        /// string ciphertext;
        /// using (<see cref="X509CryptoAgent"/> agent = new <see cref="X509CryptoAgent"/>(thumbprint, certStore))
        /// {
        ///     ciphertext = agent.EncryptText(plaintext);
        /// }
        /// </code>
        /// </example>
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
        /// <example>
        /// <code>
        /// string thumbprint = @"ccdc673c40ebb2a433300c0c8a2ba6f443da5688";
        /// <see cref="CertStore"/> certStore = <see cref="CertStore"/>.<see cref="CertStore.CurrentUser"/>;
        /// string plaintextFilePath = @"C:\data\SSNs.txt";
        /// string ciphertextFilePath = Path.GetFileNameWithoutExtension(plaintextFilePath)" + <see cref="X509Utils.CRYPTO_ENCRYPTED_FILE_EXT"/>;
        /// 
        /// using (<see cref="X509CryptoAgent"/> agent = new <see cref="X509CryptoAgent"/>(thumbprint, certStore))
        /// {
        ///     agent.EncryptFile(plaintextFilePath, ciphertextFilePath);
        /// }
        /// </code>
        /// </example>
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
        /// <remarks>
        /// This method is implemented primarily to fascilitate re-encryption of a file when changing certificates
        /// </remarks>
        /// <param name="memBytes">The byte array to encrypt</param>
        /// <param name="cipherText">The file path in which to store the encrypted payload</param>
        /// <example>
        /// <code>
        /// string thumbprint = @"ccdc673c40ebb2a433300c0c8a2ba6f443da5688";
        /// <see cref="CertStore"/> certStore = <see cref="CertStore"/>.<see cref="CertStore.CurrentUser"/>;
        /// byte[] fileBytes = File.ReadAllBytes(@"C:\data\example.txt");
        /// string ciphertextFilePath = @"C:\data\example_encrypted.ctx";
        /// 
        /// using (<see cref="X509CryptoAgent"/> agent = new <see cref="X509CryptoAgent"/>(thumbprint, certStore))
        /// {
        ///     agent.EncryptFileFromByteArray(fileBytes, ciphertextFilePath);
        /// }
        /// </code>
        /// </example>
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
        /// Decrypts the specified ciphertext expression
        /// </summary>
        /// <param name="cipherText">Base64-encoded ciphertext expression</param>
        /// <returns>decrypted string expression</returns>
        /// <example>
        /// <code>
        /// string thumbprint = @"ccdc673c40ebb2a433300c0c8a2ba6f443da5688";
        /// <see cref="CertStore"/> certStore = <see cref="CertStore"/>.<see cref="CertStore.CurrentUser"/>;
        /// 
        /// string ciphertext = File.ReadAllText(@"C:\data\connectionString.txt");
        /// string plaintext;
        /// using (<see cref="X509CryptoAgent"/> agent = new <see cref="X509CryptoAgent"/>(thumbprint, certStore))
        /// {
        ///     plaintext = agent.DecryptText(ciphertext);
        /// }
        /// </code>
        /// </example>
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
        /// <example>
        /// <code>
        /// string thumbprint = @"ccdc673c40ebb2a433300c0c8a2ba6f443da5688";
        /// <see cref="CertStore"/> certStore = <see cref="CertStore"/>.<see cref="CertStore.CurrentUser"/>;
        /// 
        /// string ciphertextFilePath = @"C:\data\SSNs.txt.ctx";
        /// string plaintextFilePath = @"C:\data\SSNs.txt";
        /// using (<see cref="X509CryptoAgent"/> agent = new <see cref="X509CryptoAgent"/>(thumbprint, certStore))
        /// {
        ///     plaintext = agent.DecryptFile(ciphertextFilePath, plaintextFilePath);
        /// }
        /// </code>
        /// </example>
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
        /// <remarks>
        /// This method is implemented primarily to fascilitate re-encryption of a file when changing certificates
        /// </remarks>
        /// <param name="cipherText">The fully-qualified path to the encrypted file</param>
        /// <returns>Byte array containing the decrypted contents of the ciphertext file</returns>
        /// <example>
        /// <code>
        /// string thumbprint = @"ccdc673c40ebb2a433300c0c8a2ba6f443da5688";
        /// <see cref="CertStore"/> certStore = <see cref="CertStore"/>.<see cref="CertStore.CurrentUser"/>;
        /// 
        /// string ciphertextFilePath = @"C:\data\SSNs.txt.ctx";
        /// byte[] plaintextBytes;
        /// 
        /// using (<see cref="X509CryptoAgent"/> agent = new <see cref="X509CryptoAgent"/>(thumbprint, certStore))
        /// {
        ///     plaintextBytes = agent.DecryptFileToByteArray(ciphertextFilePath);
        /// }
        /// </code>
        /// </example>
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
        /// <example>
        /// <code>
        /// string thumbprint = @"ccdc673c40ebb2a433300c0c8a2ba6f443da5688";
        /// <see cref="CertStore"/> certStore = <see cref="CertStore"/>.<see cref="CertStore.CurrentUser"/>;
        /// 
        /// string ciphertextFilePath = @"C:\data\connectionString.txt";
        /// string plaintext;
        /// using (<see cref="X509CryptoAgent"/> agent = new <see cref="X509CryptoAgent"/>(thumbprint, certStore))
        /// {
        ///     plaintext = agent.DecryptTextFromFile(ciphertextFilePath);
        /// }
        /// </code>
        /// </example>
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
        /// Indicates whether the certificate with the specified thumbprint was found in the specified certificate store
        /// </summary>
        /// <param name="certThumbprint">The certificate thumbprint value to search for (case-insensitive)</param>
        /// <param name="Store">The certificate store from which to load the encryption certificate.  Either CertStore.CurrentUser (default) or CertStore.LocalMachine</param>
        /// <returns>True or False depending upon whether the certificate and corresponding private key was found in the certificate store</returns>
        /// <example>
        /// <code>
        /// string thumbprint = @"ccdc673c40ebb2a433300c0c8a2ba6f443da5688";
        /// <see cref="CertStore"/> certStore = <see cref="CertStore"/>.<see cref="CertStore.CurrentUser"/>;
        /// 
        /// bool found;
        /// 
        /// using (<see cref="X509CryptoAgent"/> agent = new <see cref="X509CryptoAgent"/>(thumbprint, certStore))
        /// {
        ///     found = agent.CertificateExists(thumbprint, certStore);
        /// }
        /// </code>
        /// </example>
        public static bool CertificateExists(string certThumbprint, CertStore Store)
        {
            certThumbprint = X509Utils.FormatThumbprint(certThumbprint);

            X509Store store = new X509Store(StoreName.My, Store.Location);
            store.Open(OpenFlags.ReadOnly);
            foreach (X509Certificate2 cert in store.Certificates)
            {
                if (string.Equals(certThumbprint, cert.Thumbprint, StringComparison.OrdinalIgnoreCase) && IsUsable(cert, true))
                {
                    return true;
                }
                else
                {
                    X509CryptoLog.Warning(text: string.Format("A certificate with thumbprint {0} was found in the {1} certificate store, but is not usable for encryption", certThumbprint, Store.Name),
                                          messageType: X509Utils.MethodName(), writeToEventLog: true, writeToScreen: true);
                    return false;
                }
            }

            return false;
        }

        internal static bool IsUsable(X509Certificate2 cert, bool allowExpired)
        {
            if (!cert.HasPrivateKey)
                return false;

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
