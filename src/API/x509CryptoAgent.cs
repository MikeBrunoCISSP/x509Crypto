using System;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.IO;
using System.Runtime.Serialization;
using System.Collections.Generic;
using System.Linq;

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

        #region Member Fields

        private RSACryptoServiceProvider publicKey,
                                         privateKey;

        /// <summary>
        /// The thumbprint of the certificate used for cryptographic operations
        /// </summary>
        public string Thumbprint { get; private set; }

        /// <summary>
        /// The certificate store from which to load the encryption certificate and private key.
        /// </summary>
        /// <remarks>
        /// Possible values are <see cref="X509Context"/>.<see cref="X509Context.UserReadOnly"/> or <see cref="X509Context"/>.<see cref="CertStore.LocalMachine"/><br/>
        /// If not specified, default value is <see cref="X509Context"/>.<see cref="X509Context.UserReadOnly"/>
        /// </remarks>
        public X509Context Context { get; private set; }


        /// <summary>
        /// Indicates whether the instantiated <see cref="X509CryptoAgent"/> object is bound to an available valid certificate and corresponding private key that is appropriate for encryption
        /// </summary>
        public bool valid = false;

        #endregion

        #region Constructors and Destructors

        /// <summary>
        /// X509CryptoAgent Constructor
        /// </summary>
        /// <param name="thumbprint">The thumbprint of the encryption certificate.  The certificate must be present in the CURRENTUSER store location</param>
        /// <param name="context">The X509Context where the encryption certificate can be accessed</param>  
        public X509CryptoAgent(string thumbprint, X509Context context)
        {
            Thumbprint = thumbprint.RemoveNonHexChars();
            Context = context;
            GetRSAKeys(Thumbprint);
        }

        internal X509CryptoAgent(X509Alias Alias)
            : this(Alias.Thumbprint, Alias.Context)
        { }


        /// <summary>
        /// X509CryptoAgent Destructor
        /// </summary>
        public void Dispose()
        {
            publicKey = null;
            privateKey = null;
        }

        #endregion

        #region Member Methods

        /// <summary>
        /// Encrypts the specified string expression
        /// </summary>
        /// <param name="plainText">Text expression to encrypt</param>
        /// <returns>Base64-encoded ciphertext expression</returns>
        /// <example>
        /// <code>
        /// string thumbprint = @"ccdc673c40ebb2a433300c0c8a2ba6f443da5688";
        /// <see cref="X509Context"/> certStore = <see cref="X509Context"/>.<see cref="X509Context.UserReadOnly"/>;
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
                aesManaged.KeySize = CryptoConstants.AESKeySize;
                aesManaged.BlockSize = CryptoConstants.AESBlockSize;
                aesManaged.Mode = CipherMode.CBC;

                using (ICryptoTransform transform = aesManaged.CreateEncryptor())
                {
                    RSAPKCS1KeyExchangeFormatter keyFormatter = new RSAPKCS1KeyExchangeFormatter(publicKey);
                    byte[] keyEncrypted = keyFormatter.CreateKeyExchange(aesManaged.Key, aesManaged.GetType());

                    //Contain the length values of the key and IV respectively
                    byte[] KeyLengthIndicator = new byte[CryptoConstants.AESBytes];
                    byte[] IVLengthIndicator = new byte[CryptoConstants.AESBytes];

                    //Byte arrays to contain the length values of the key and IV
                    int keyLength = keyEncrypted.Length;
                    KeyLengthIndicator = BitConverter.GetBytes(keyLength);

                    int IVLength = aesManaged.IV.Length;
                    IVLengthIndicator = BitConverter.GetBytes(IVLength);

                    using (MemoryStream memStream = new MemoryStream())
                    {
                        memStream.Write(KeyLengthIndicator, 0, CryptoConstants.AESBytes);
                        memStream.Write(IVLengthIndicator, 0, CryptoConstants.AESBytes);

                        memStream.Write(keyEncrypted, 0, keyLength);
                        memStream.Write(aesManaged.IV, 0, IVLength);

                        //Write the ciphertext using a CryptoStream
                        using (CryptoStream cryptoStream = new CryptoStream(memStream, transform, CryptoStreamMode.Write))
                        {
                            int count = 0;
                            int offset = 0;
                            int blockSizeInBytes = aesManaged.BlockSize / CryptoConstants.AESWords;

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
        /// Re-encrypts the specified ciphertext expression using a different X509CryptoAgent
        /// </summary>
        /// <param name="ciphertext">the ciphertext expression to be re-encrypted</param>
        /// <param name="newAgent">the X509CryptoAgent to be used to perform re-encryption</param>
        /// <returns></returns>
        public string ReEncryptText(string ciphertext, X509CryptoAgent newAgent)
        {
            return newAgent.EncryptText(DecryptText(ciphertext));
        }

        /// <summary>
        /// Encrypts the specified plaintext file.  Text and binary file types are supported.
        /// </summary>
        /// <param name="plainText">Fully-qualified path of the file to be encrypted</param>
        /// <param name="cipherText">Fully-qualified path in which to write the encrypted file</param>
        /// <example>
        /// <code>
        /// string thumbprint = @"ccdc673c40ebb2a433300c0c8a2ba6f443da5688";
        /// <see cref="X509Context"/> certStore = <see cref="X509Context"/>.<see cref="X509Context.UserReadOnly"/>;
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
                aesManaged.KeySize = CryptoConstants.AESKeySize;
                aesManaged.BlockSize = CryptoConstants.AESBlockSize;
                aesManaged.Mode = CipherMode.CBC;

                using (ICryptoTransform transform = aesManaged.CreateEncryptor())
                {
                    RSAPKCS1KeyExchangeFormatter keyFormatter = new RSAPKCS1KeyExchangeFormatter(publicKey);
                    byte[] keyEncrypted = keyFormatter.CreateKeyExchange(aesManaged.Key, aesManaged.GetType());

                    //Contain the length values of the key and IV respectively
                    byte[] KeyLengthIndicator = new byte[CryptoConstants.AESBytes];
                    byte[] IVLengthIndicator = new byte[CryptoConstants.AESBytes];

                    
                    int keyLength = keyEncrypted.Length;
                    KeyLengthIndicator = BitConverter.GetBytes(keyLength);

                    int IVLength = aesManaged.IV.Length;
                    IVLengthIndicator = BitConverter.GetBytes(IVLength);

                    using (FileStream outFS = new FileStream(cipherText, FileMode.Create))
                    {
                        outFS.Write(KeyLengthIndicator, 0, CryptoConstants.AESBytes);
                        outFS.Write(IVLengthIndicator, 0, CryptoConstants.AESBytes);

                        outFS.Write(keyEncrypted, 0, keyLength);
                        outFS.Write(aesManaged.IV, 0, IVLength);

                        using (CryptoStream outStreamEncrypted = new CryptoStream(outFS, transform, CryptoStreamMode.Write))
                        {
                            int count = 0;
                            int offset = 0;
                            int blockSizeInBytes = aesManaged.BlockSize / CryptoConstants.AESWords;

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
        /// <see cref="X509Context"/> certStore = <see cref="X509Context"/>.<see cref="X509Context.UserReadOnly"/>;
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
                aesManaged.KeySize = CryptoConstants.AESKeySize;
                aesManaged.BlockSize = CryptoConstants.AESBlockSize;
                aesManaged.Mode = CipherMode.CBC;

                using (ICryptoTransform transform = aesManaged.CreateEncryptor())
                {
                    RSAPKCS1KeyExchangeFormatter keyFormatter = new RSAPKCS1KeyExchangeFormatter(publicKey);
                    byte[] keyEncrypted = keyFormatter.CreateKeyExchange(aesManaged.Key, aesManaged.GetType());

                    //Contain the length values of the key and IV respectively
                    byte[] KeyLengthIndicator = new byte[CryptoConstants.AESBytes];
                    byte[] IVLengthIndicator = new byte[CryptoConstants.AESBytes];

                    
                    int keyLength = keyEncrypted.Length;
                    KeyLengthIndicator = BitConverter.GetBytes(keyLength);

                    int IVLength = aesManaged.IV.Length;
                    IVLengthIndicator = BitConverter.GetBytes(IVLength);

                    using (FileStream outFS = new FileStream(cipherText, FileMode.Create))
                    {
                        outFS.Write(KeyLengthIndicator, 0, CryptoConstants.AESBytes);
                        outFS.Write(IVLengthIndicator, 0, CryptoConstants.AESBytes);

                        outFS.Write(keyEncrypted, 0, keyLength);
                        outFS.Write(aesManaged.IV, 0, IVLength);

                        using (CryptoStream outStreamEncrypted = new CryptoStream(outFS, transform, CryptoStreamMode.Write))
                        {
                            int count = 0;
                            int offset = 0;
                            int blockSizeInBytes = aesManaged.BlockSize / CryptoConstants.AESWords;

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
        /// <see cref="X509Context"/> certStore = <see cref="X509Context"/>.<see cref="X509Context.UserReadOnly"/>;
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
                aesManaged.KeySize = CryptoConstants.AESKeySize;
                aesManaged.BlockSize = CryptoConstants.AESBlockSize;
                aesManaged.Mode = CipherMode.CBC;

                byte[] KeyLengthIndicator = new byte[CryptoConstants.AESBytes];
                byte[] IVLengthIndicator = new byte[CryptoConstants.AESBytes];

                using (MemoryStream inStream = new MemoryStream(cipherTextBytes))
                {
                    inStream.Seek(0, SeekOrigin.Begin);
                    inStream.Seek(0, SeekOrigin.Begin);
                    inStream.Read(KeyLengthIndicator, 0, (CryptoConstants.AESBytes-1));

                    inStream.Seek(CryptoConstants.AESBytes, SeekOrigin.Begin);
                    inStream.Read(IVLengthIndicator, 0, (CryptoConstants.AESBytes - 1));

                    int keyLength = BitConverter.ToInt32(KeyLengthIndicator, 0);
                    int IVLength = BitConverter.ToInt32(IVLengthIndicator, 0);

                    int cipherTextStartingPoint = keyLength + IVLength + CryptoConstants.AESWords;
                    int cipherTextLength = (int)inStream.Length - cipherTextStartingPoint;

                    byte[] keyEncrypted = new byte[keyLength];
                    byte[] IV = new byte[IVLength];

                    //Read the encrypted symetric key
                    inStream.Seek(CryptoConstants.AESWords, SeekOrigin.Begin);
                    inStream.Read(keyEncrypted, 0, keyLength);

                    //Read in the Initialization Vector
                    inStream.Seek(CryptoConstants.AESWords + keyLength, SeekOrigin.Begin);
                    inStream.Read(IV, 0, IVLength);

                    byte[] keyDecrypted = privateKey.Decrypt(keyEncrypted, false);

                    using (ICryptoTransform transform = aesManaged.CreateDecryptor(keyDecrypted, IV))
                    {
                        using (MemoryStream outStream = new MemoryStream())
                        {
                            int count = 0;
                            int offset = 0;
                            int blockSizeInBytes = aesManaged.BlockSize / CryptoConstants.AESWords;

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
        /// <see cref="X509Context"/> certStore = <see cref="X509Context"/>.<see cref="X509Context.UserReadOnly"/>;
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
                aesManaged.KeySize = CryptoConstants.AESKeySize;
                aesManaged.BlockSize = CryptoConstants.AESBlockSize;
                aesManaged.Mode = CipherMode.CBC;

                byte[] KeyLengthIndicator = new byte[CryptoConstants.AESBytes];
                byte[] IVLengthIndicator = new byte[CryptoConstants.AESBytes];

                using (FileStream inFS = new FileStream(cipherText, FileMode.Open))
                {
                    inFS.Seek(0, SeekOrigin.Begin);
                    inFS.Seek(0, SeekOrigin.Begin);
                    inFS.Read(KeyLengthIndicator, 0, CryptoConstants.AESReadCount);

                    inFS.Seek(4, SeekOrigin.Begin);
                    inFS.Read(IVLengthIndicator, 0, CryptoConstants.AESReadCount);

                    int keyLength = BitConverter.ToInt32(KeyLengthIndicator, 0);
                    int IVLength = BitConverter.ToInt32(IVLengthIndicator, 0);

                    int cipherTextStart = keyLength + IVLength + CryptoConstants.AESWords;
                    int cipherTextLength = (int)inFS.Length - cipherTextStart;

                    byte[] keyEncrypted = new byte[keyLength];
                    byte[] IV = new byte[IVLength];

                    inFS.Seek(CryptoConstants.AESWords, SeekOrigin.Begin);
                    inFS.Read(keyEncrypted, 0, keyLength);

                    inFS.Seek(CryptoConstants.AESWords + keyLength, SeekOrigin.Begin);
                    inFS.Read(IV, 0, IVLength);

                    byte[] keyDecrypted = privateKey.Decrypt(keyEncrypted, false);

                    using (ICryptoTransform transform = aesManaged.CreateDecryptor(keyDecrypted, IV))
                    {
                        using (FileStream outFS = new FileStream(plainText, FileMode.Create))
                        {
                            int count = 0;
                            int offset = 0;
                            int blockSizeInBytes = aesManaged.BlockSize / CryptoConstants.AESWords;

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
        /// <see cref="X509Context"/> certStore = <see cref="X509Context"/>.<see cref="X509Context.UserReadOnly"/>;
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
                aesManaged.KeySize = CryptoConstants.AESKeySize;
                aesManaged.BlockSize = CryptoConstants.AESBlockSize;
                aesManaged.Mode = CipherMode.CBC;

                byte[] KeyLengthIndicator = new byte[CryptoConstants.AESBytes];
                byte[] IVLengthIndicator = new byte[CryptoConstants.AESBytes];

                using (FileStream inFS = new FileStream(cipherText, FileMode.Open))
                {
                    inFS.Seek(0, SeekOrigin.Begin);
                    inFS.Seek(0, SeekOrigin.Begin);
                    inFS.Read(KeyLengthIndicator, 0, CryptoConstants.AESReadCount);

                    inFS.Seek(CryptoConstants.AESBytes, SeekOrigin.Begin);
                    inFS.Read(IVLengthIndicator, 0, CryptoConstants.AESReadCount);

                    int keyLength = BitConverter.ToInt32(KeyLengthIndicator, 0);
                    int IVLength = BitConverter.ToInt32(IVLengthIndicator, 0);

                    int cipherTextStart = keyLength + IVLength + CryptoConstants.AESWords;
                    int cipherTextLength = (int)inFS.Length - cipherTextStart;

                    byte[] keyEncrypted = new byte[keyLength];
                    byte[] IV = new byte[IVLength];

                    inFS.Seek(CryptoConstants.AESWords, SeekOrigin.Begin);
                    inFS.Read(keyEncrypted, 0, keyLength);

                    inFS.Seek(CryptoConstants.AESWords + keyLength, SeekOrigin.Begin);
                    inFS.Read(IV, 0, IVLength);

                    byte[] keyDecrypted = privateKey.Decrypt(keyEncrypted, false);

                    using (ICryptoTransform transform = aesManaged.CreateDecryptor(keyDecrypted, IV))
                    {
                            int count = 0;
                            int offset = 0;
                            int blockSizeInBytes = aesManaged.BlockSize / CryptoConstants.AESWords;

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
        /// <see cref="X509Context"/> certStore = <see cref="X509Context"/>.<see cref="X509Context.UserReadOnly"/>;
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
                throw new FileNotFoundException(path);

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

        private void GetRSAKeys(string thumbprint)
        {
            X509Certificate2Collection colletion = new X509Certificate2Collection();
            X509Store keyStore = new X509Store(Context.Location);
            keyStore.Open(OpenFlags.ReadOnly);
            foreach (X509Certificate2 cert in keyStore.Certificates)
            {
                if (cert.Thumbprint.Matches(thumbprint))
                {
                    if (cert.HasPrivateKey & IsUsable(cert, false))
                        colletion.Add(cert);
                }
            }

            if (colletion.Count != 1)
                throw new X509CryptoCertificateNotFoundException(thumbprint, Context);

            try
            {
                foreach (X509Certificate2 cert in colletion)
                {
                    publicKey = (RSACryptoServiceProvider)cert.PublicKey.Key;
                    privateKey = (RSACryptoServiceProvider)cert.PrivateKey;
                    //var pk = cert.GetRSAPrivateKey();
                    break;
                }
                valid = true;
            }
            catch (CryptographicException ex)
            {
                throw new X509CryptoException($"An exception occurred while attempting to load RSA key pair associated with the encryption certificate with thumbprint {thumbprint} from the {Context.Name} context", ex);
            }
        }


        #endregion

        #region Static Methods

        /// <summary>
        /// Indicates whether the certificate with the specified thumbprint was found in the specified certificate store
        /// </summary>
        /// <param name="certThumbprint">The certificate thumbprint value to search for (case-insensitive)</param>
        /// <param name="Context">The certificate store from which to load the encryption certificate.  Either CertStore.CurrentUser (default) or CertStore.LocalMachine</param>
        /// <returns>True or False depending upon whether the certificate and corresponding private key was found in the certificate store</returns>
        /// <example>
        /// <code>
        /// string thumbprint = @"ccdc673c40ebb2a433300c0c8a2ba6f443da5688";
        /// <see cref="X509Context"/> certStore = <see cref="X509Context"/>.<see cref="X509Context.UserReadOnly"/>;
        /// 
        /// bool found;
        /// 
        /// using (<see cref="X509CryptoAgent"/> agent = new <see cref="X509CryptoAgent"/>(thumbprint, certStore))
        /// {
        ///     found = agent.CertificateExists(thumbprint, certStore);
        /// }
        /// </code>
        /// </example>
        public static bool CertificateExists(string certThumbprint, X509Context Context)
        {
            certThumbprint = certThumbprint.RemoveNonHexChars();

            X509Store store = new X509Store(StoreName.My, Context.Location);
            store.Open(OpenFlags.ReadOnly);
            foreach (X509Certificate2 cert in store.Certificates)
            {
                if (cert.Thumbprint.Matches(certThumbprint) && IsUsable(cert, true))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Indicates whether the encryption certificate referenced by the specified X509Alias exists in the alias context.
        /// </summary>
        /// <param name="Alias">The X509Alias to check for encryption certificate existence</param>
        /// <returns>true if the encryption certificate referenced in the X509Alias exists in the alias context</returns>
        public static bool CertificateExists(X509Alias Alias)
        {
            return CertificateExists(Alias.Thumbprint, Alias.Context);
        }

        /// <summary>
        /// Exports the public certificate corresponding to the specified certificate thumbprint to a Base64-encoded file
        /// </summary>
        /// <param name="thumbprint">Thumbprint of the certificate to be exported</param>
        /// <param name="Context">The X509Context where the certificate to be exported exists</param>
        /// <param name="path">The storage path to where the file containing the public certificate should be written</param>
        public static void ExportCert(string thumbprint, X509Context Context, string path)
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }

            X509Certificate2 Cert = Util.GetCertByThumbprint(thumbprint, Context);
            StringBuilder sb = new StringBuilder(Constants.BeginBase64Certificate);
            sb.AppendLine(Convert.ToBase64String(Cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
            sb.AppendLine(Constants.EndBase64Certificate);
            File.WriteAllText(path, sb.ToString());
            Util.VerifyFileExists(path);

            try
            {
                X509Certificate2 test = new X509Certificate2(path);
                X509CryptoLog.Info($"Public certificate with thumbprint {thumbprint} successfully exported to file path \"{path}\"");
            }
            catch (CryptographicException ex)
            {
                X509CryptoLog.Exception(ex, Criticality.ERROR, text: $"Public certificate with thumbprint {thumbprint} was exported to file path \"{path}\" but the file contents are not usable");
                throw ex;
            }
        }

        /// <summary>
        /// Lists the thumbprint value for all encryption certificates which exist in the specified store location. Certificates which do not have the "Key Encipherment" key usage flag set are not included in the list.
        /// </summary>
        /// <param name="Context">The X509Context from which to list certificates</param>
        /// <param name="includeExpired">If true, expired certificates will be included in the resulting list</param>
        /// <returns>Line-break-separated list of certificate details</returns>
        public static string ListCerts(X509Context Context, bool includeExpired = false)
        {
            StringBuilder expression = new StringBuilder($"Key Encipherment certificates found in {Context.Name} context:\r\n\r\n");
            bool firstAdded = false;

            List<X509Alias> Aliases = Context.GetAliases();
            X509Alias AssignedAlias = null;
            string assignedAliasName = string.Empty;

            X509Store Store = new X509Store(Context.Location);
            Store.Open(OpenFlags.ReadOnly);
            foreach (X509Certificate2 cert in Store.Certificates)
            {
                if (IsUsable(cert, includeExpired))
                {
                    if (!firstAdded)
                    {
                        expression.AppendLine(ListCertFormat.HeaderRow);
                        firstAdded = true;
                    }

                    AssignedAlias = Aliases.FirstOrDefault(p => p.Thumbprint.Matches(cert.Thumbprint));
                    assignedAliasName = AssignedAlias == null ? Constants.NoAliasAssigned : AssignedAlias.Name;
                    expression.AppendLine($"{cert.Thumbprint.LeftAlign(Padding.Thumbprint)}   {assignedAliasName.LeftAlign(Padding.Assigned_Alias)}   {cert.NotAfter.ToString(Constants.DateFormat)}");
                }
            }

            if (!firstAdded)
            {
                expression.AppendLine(@"None.");
            }

            return expression.ToString();
        }

        /// <summary>
        /// Lists all aliases that are found in the specified X509Context
        /// </summary>
        /// <param name="Context">The X509Context from which to list existing aliases</param>
        /// <returns>Line-break-separated list of X509Alias details</returns>
        public static string ListAliases(X509Context Context)
        {
            StringBuilder expression = new StringBuilder($"X509Aliases found in the {Context.Name} context:\r\n\r\n");
            bool firstAdded = false;
            Dictionary<string, X509Certificate2> Aliases = X509Alias.GetAll(Context);
            foreach(KeyValuePair<string, X509Certificate2> Alias in Aliases)
            {
                if (!firstAdded)
                {
                    expression.AppendLine(ListAliasFormat.HeaderRow);
                    firstAdded = true;
                }
                expression.AppendLine($"{Alias.Key.LeftAlign(Padding.Alias)}   {Alias.Value.Thumbprint.LeftAlign(Padding.Thumbprint)}   {Alias.Value.NotAfter.ToString(Constants.DateFormat)}");
            }

            if (!firstAdded)
            {
                expression.AppendLine(@"None.");
            }

            return expression.ToString();
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

        /// <summary>
        /// Exports the encryption certificate and corresponding key pair to a file in PKCS#12 format
        /// </summary>
        /// <param name="thumbprint">The thumbprint of the encryption certificate</param>
        /// <param name="Context">The X509Context where the certificate and corresponding key pair exist</param>
        /// <param name="pfxPath">The path to where the PKCS#12 file should be written</param>
        /// <param name="password">The password which will protect the PKCS#12 file</param>
        public static void ExportPFX(string thumbprint, X509Context Context, string pfxPath, string password)
        {
            if (File.Exists(pfxPath))
            {
                File.Delete(pfxPath);
            }

            X509Certificate2 Cert = Util.GetCertByThumbprint(thumbprint, Context);
            byte[] certBytes = Cert.Export(X509ContentType.Pkcs12, password);
            File.WriteAllBytes(pfxPath, certBytes);
            Util.VerifyFileExists(pfxPath);
        }

        #endregion
    }
}
