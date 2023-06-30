using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security;
using System.Text;
using Org.X509Crypto.Dto;
using Org.X509Crypto.Services;

namespace Org.X509Crypto {
    /// <summary>
    /// Represents an X509Context, a certificate/key pair and 0 or more secrets encrypted by the certificate/key pair
    /// </summary>
    [DataContract]
    public class X509Alias : IDisposable {
        private static readonly CertService _certService = new();

        private EncryptionService cryptService;

        private string thumbprint;
        private bool certificateLoaded;
        private CertificateDto certificate;

        /// <summary>
        /// The identifier assigned to this alias
        /// </summary>
        [DataMember]
        public string Name { get; set; }
        /// <summary>
        /// The thumbprint of the certificate used for cryptographic operations in this alias
        /// </summary>
        [DataMember]
        public string Thumbprint {
            get => thumbprint;
            set => thumbprint = value.RemoveNonHexChars();
        }
        /// <summary>
        /// The context where cryptographic operations should occur (either system or user)
        /// </summary>
        [DataMember]
        public X509Context Context { get; set; }
        /// <summary>
        /// The fully-qualified name of the X509Alias in the format [Context]\[Name]
        /// </summary>
        public string FullName => $"{Context.Name}\\{Name}";

        internal CertificateDto Certificate {
            get => certificate;
            set {
                certificate = value;
                cryptService = new EncryptionService(certificate);
                certificateLoaded = true;
            }
        }

        [DataMember]
        public Dictionary<string, string> Secrets { get; set; } = new(StringComparer.InvariantCultureIgnoreCase);
        [DataMember]
        internal byte[] CertificateBlob { get; set; }

        private string StoragePath => Path.Combine(Context.GetStorageDirectory(), $"{Name}{FileExtensions.X509Alias}");

        /// <summary>
        /// Gets the certificate associated with this <see cref="X509Alias"/>
        /// </summary>
        /// <returns>An <see cref="CertificateDto"/></returns>
        /// <exception cref="X509CryptoException"></exception>
        public CertificateDto GetCertificate(bool nullSafe = false) {
            if (certificateLoaded || loadCertificate()) {
                return Certificate;
            }
            if (nullSafe) {
                return null;
            }

            throw new X509CryptoCertificateNotFoundException(Thumbprint, Context);

        }
        /// <summary>
        /// Determines whether the encryption certificate exists in the <see cref="X509Context"/>
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public bool HasCert(X509Context context) {
            return _certService.CertExistsInStore(Thumbprint, context);
        }

        /// <summary>
        /// Encrypts the specified text expression
        /// </summary>
        /// <param name="plaintext">the text expression to be encrypted</param>
        /// <returns>Base64-encoded ciphertext string</returns>
        public string EncryptText(string plaintext) {
            EncryptedSecretDto payload = cryptService.EncryptText(plaintext);
            return DataSerializer.SerializeObject(payload).Base64Encode();
        }
        /// <summary>
        /// Decrypts the specified Base64-encoded ciphertext expression
        /// </summary>
        /// <param name="ciphertext">The Base64-encoded ciphertext expression to be decrypted</param>
        /// <returns>A recovered plaintext string</returns>
        public string DecryptText(string ciphertext) {
            var secret = DataSerializer.DeserializeObject<EncryptedSecretDto>(ciphertext.Base64Decode(), true);
            if (secret is null) {
                throw new SerializationException("The secret could not be read.");
            }

            return cryptService.DecryptText(secret);
        }

        /// <summary>
        /// Encrypts the specified file. All file types are supported.
        /// </summary>
        /// <param name="inFile">The path to the file to be encrypted. Path must exist.</param>
        /// <param name="outFile">he path in which to write the encrypted file.</param>
        /// <param name="wipeTimesToWrite">Performs n-pass forensic wipe of the disk sectors where the input file was stored.</param>
        public void EncryptFile(string inFile, string outFile, int wipeTimesToWrite = 0) {
            byte[] data = cryptService.EncryptFile(inFile);
            File.WriteAllBytes(outFile, data);

            if (!File.Exists(outFile)) {
                throw new X509CryptoException($"Unable to encrypt the file '{inFile}'. The ciphertext file '{outFile}' could not be created.");
            }

            if (wipeTimesToWrite > 0) {
                X509CryptoUtils.WipeFile(inFile, wipeTimesToWrite);
            }
        }

        /// <summary>
        /// Re-encrypts the specified file using this X509Alias
        /// </summary>
        /// <param name="inFile">The path to the ciphertext file to re-encrypt</param>
        /// <param name="OldAlias">The X509Alias which was previously used to encrypt the file</param>
        public void ReEncryptFile(string inFile, X509Alias OldAlias) {
            //TODO: Re-implement this.
            //X509CryptoUtils.ReEncryptFile(OldAlias, this, inFile);
        }

        /// <summary>
        /// Recovers the specified encrypted file
        /// </summary>
        /// <param name="inFile">The path to the encrypted file to be recovered. Path must exist</param>
        /// <param name="outFile">The path in which to write the recovered plaintext file</param>
        /// <param name="wipeTimesToWrite">Performs n-pass forensic wipe of the disk sectors where the input file was stored.</param>
        public void DecryptFile(string inFile, string outFile, int wipeTimesToWrite = 0) {
            byte[] data = cryptService.DecryptFile(inFile);
            File.WriteAllBytes(outFile, data);

            if (!File.Exists(outFile)) {
                throw new X509CryptoException($"Unable to decrypt the file '{inFile}'. The plaintext file '{outFile}' could not be created.");
            }

            if (wipeTimesToWrite > 0) {
                X509CryptoUtils.WipeFile(inFile, wipeTimesToWrite);
            }
        }

        /// <summary>
        /// Re-Encrypts a ciphertext expression, currently encrypted in a different X509Alias, using this X509Alias
        /// </summary>
        /// <param name="ciphertext">The ciphertext expression to be reencrypted</param>
        /// <param name="OldAlias">The identifier of the X509Alias where the input secret is located</param>
        /// <returns>A Bas64-encoded ciphertext string</returns>
        public string ReEncryptText(string ciphertext, X509Alias OldAlias) {
            string plaintext = OldAlias.DecryptText(ciphertext);
            return EncryptText(plaintext);
        }

        /// <summary>
        /// Re-Encrypts a secret that is stored in a different X509Alias
        /// </summary>
        /// <param name="secretName">The identifier of the secret to be re-encrypted</param>
        /// <param name="OldAlias">The X509Alias where the secret is stored</param>
        /// <returns>A Base64-encoded ciphtertext string</returns>
        public string ReEncryptSecret(string secretName, X509Alias OldAlias) {
            string plaintext = OldAlias.RecoverSecret(secretName);
            return EncryptText(plaintext);
        }

        /// <summary>
        /// Encrypts the specified plaintext expression and stores it in this X509Alias
        /// </summary>
        /// <param name="identifier">The desired identifier for the secret (must be unique within the alias)</param>
        /// <param name="plaintext">The plaintext expression to be encrypted</param>
        /// <param name="overwriteExisting">Indicates whether an existing secret in the alias with the same value for "Name" as specified may be overwritten</param>
        /// <returns>A Base64-encoded ciphertext string</returns>
        /// <exception cref="X509SecretAlreadyExistsException"></exception>
        public string AddSecret(string identifier, string plaintext, bool overwriteExisting) {
            if (Secrets.ContainsKey(identifier) && !overwriteExisting) {
                throw new X509SecretAlreadyExistsException(this, identifier);
            }

            string payLoad = EncryptText(plaintext);
            if (Secrets.ContainsKey(identifier)) {
                Secrets[identifier] = payLoad;
            } else {
                Secrets.Add(identifier, plaintext);
            }

            return payLoad;
        }
        /// <summary>
        /// Re-encrypts a secret from a different X509Alias and stores it in this X509Alias
        /// </summary>
        /// <param name="identifier">The identifier of the secret as it is stored in the old X509Alias</param>
        /// <param name="OldAlias">The old X509Alias where the secret is currently encrypted and stored</param>
        /// <param name="overwriteExisting">If true, an existing secret in this X509Alias with the same identifier may be overwritten</param>
        /// <returns>A Base64-encoded ciphertext expression</returns>
        public string ReEncryptSecret(string identifier, X509Alias OldAlias, bool overwriteExisting) {
            return AddSecret(identifier, OldAlias.RecoverSecret(identifier), overwriteExisting);
        }
        /// <summary>
        /// Recovers a secret from an X509Alias with the specified identifier
        /// </summary>
        /// <param name="identifier">The identifier of the secret to be recovered</param>
        /// <returns>The recovered, plaintext secret</returns>
        /// <exception cref="X509CryptoSecretNotFoundException"></exception>
        public string RecoverSecret(string identifier) {
            if (Secrets.ContainsKey(identifier)) {
                return DecryptText(Secrets[identifier]);
            }

            throw new X509CryptoSecretNotFoundException(identifier, this);
        }
        /// <summary>
        /// Updates this X509Alias to use a new encryption certificate and key pair. The old certificate and key pair must still be available to perform this operation.
        /// </summary>
        /// <param name="newThumbprint">The SHA1 thumbprint of the new encryption certificate. The certificate and associated key pair must exist and be available in the specified X509Context</param>
        /// <param name="newContext">The X509Context where the new encryption certificate and key pair is located</param>
        public void ReEncrypt(string newThumbprint, X509Context newContext = null) {
            newContext ??= Context;

            newThumbprint = newThumbprint.RemoveNonHexChars();
            if (!_certService.CertExistsInStore(newThumbprint, newContext)) {
                throw new X509CryptoException($"A valid encryption certificate with thumbprint {newThumbprint} was not found in the {Context.Name} context");
            }

            var tmpAlias = Create(Name, newContext, newThumbprint);
            foreach (string identifier in Secrets.Keys) {
                Secrets[identifier] = tmpAlias.EncryptText(RecoverSecret(identifier));
            }

            Thumbprint = newThumbprint;
            Context = newContext;
            Commit();
        }
        /// <summary>
        /// Imports the encryption certificate from the specified encoded blob
        /// </summary>
        /// <param name="encodedCert">The encoded certificate blob</param>
        /// <param name="password">The password to unlock the private key</param>
        public void ImportCert(byte[] encodedCert, SecureString password) {
            Certificate = _certService.ImportCertificate(encodedCert, password, Context);
        }
        /// <summary>
        /// Exports the encryption certificate contained in this alias to a Base64-encoded text file. The private key is not exported.
        /// </summary>
        /// <param name="path">The fully-qualified path where the export file should be written</param>
        public void ExportCert(string path) {
            _certService.ExportCertificate(GetCertificate(), path);
        }

        /// <summary>
        /// Exports this X509Alias to a Json-formatted file
        /// Note: This method does NOT export the encryption certificate or the associated key pair. 
        /// </summary>
        /// <param name="exportPath">The path where the export file should be written (a .json extension is added if no file extension is specified)</param>
        /// <param name="overwriteExisting">Indicates whether an existing file may be overwritten if a file should exist at the indicated export path</param>
        public void Export(ref string exportPath, bool includeCert, bool overwriteExisting = false) {
            if (!Path.GetExtension(exportPath).Matches(FileExtensions.X509Alias)) {
                exportPath = $"{exportPath}{FileExtensions.X509Alias}";
            }

            if (File.Exists(exportPath) && !overwriteExisting) {
                throw new X509CryptoException($"Cannot export the X509Alias {FullName}: file exists: '{exportPath}'. Set overwriteExisting=true to overwrite");
            }

            File.Delete(exportPath);
            File.WriteAllText(exportPath, encode(includeCert));

            if (!File.Exists(exportPath)) {
                throw new FileNotFoundException($"Could not export X509Alias {FullName}: File not found at specified path ({exportPath})");
            }
        }

        /// <summary>
        /// Writes the X509Alias to the local file system for later retrieval
        /// </summary>
        public void Commit() {
            if (!Directory.Exists(Context.GetStorageDirectory())) {
                Directory.CreateDirectory(Context.GetStorageDirectory());
            }

            var tmp = StoragePath;
            Export(ref tmp, includeCert: false, overwriteExisting: true);
        }

        /// <summary>
        /// Removes this X509Alias from the file system
        /// </summary>
        public void Remove(bool deleteCert = false) {
            try {
                File.Delete(StoragePath);
                //X509CryptoUtils.DeleteFile(StoragePath, complainIfNotFound: true, confirmDelete: true);

                if (!deleteCert) {
                    return;
                }

                _certService.RemoveCertificate(Thumbprint, Context);
            } catch (Exception ex) {
                throw new X509CryptoException($"The X509Crypto alias '{Name}' could not be removed from the {Context.Name} context", ex);
            }
        }
        /// <summary>
        /// Generates a text report of the X509Artifacts contained within this X509Alias
        /// </summary>
        /// <param name="revealSecrets">Indicates whether the plaintext values of each X509Secret should be revealed in the output</param>
        /// <returns>A text report listing all X509Secrets contained within this X509Alias</returns>
        public string PrintSecrets(X509CryptSecretPrintFormat printFormat, bool revealSecrets) {
            if (Secrets.Count == 0) {
                return $@"No secrets stored in X509Alias '{Context.Name}\{Name}'";
            }

            string firstLine = printFormat switch {
                X509CryptSecretPrintFormat.Screen => $@"{Secrets.Count} secrets exist in X509Alias '{Context.Name}\{Name}':\r\n",
                X509CryptSecretPrintFormat.CommaSeparated => revealSecrets
                    ? CSVHeader.WithSecrets
                    : CSVHeader.WithoutSecrets
            };
            StringBuilder output = new StringBuilder($"{firstLine}");
            if (printFormat == X509CryptSecretPrintFormat.Screen) {
                output.AppendLine(firstLine.GetDivider());
            }
            int index = 1;
            foreach (KeyValuePair<string, string> secret in Secrets) {
                printSecret(index++, secret.Key, printFormat, revealSecrets);
            }
            output.AppendLine();
            return output.ToString();
        }
        /// <summary>
        /// Saves the X509CryptoAlias along with its certificate and key pair to a file
        /// </summary>
        /// <param name="path">The path to which to write the file</param>
        /// <param name="password">The password to protect the certificate private key.</param>
        /// <param name="overwrite">If true, an existing file may be overwritten</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        public void Save(string path, SecureString password, bool overwrite = false) {
            if (path is null) {
                throw new ArgumentNullException(nameof(path));
            }
            if (password is null) {
                throw new ArgumentNullException(nameof(password));
            }

            if (File.Exists(path) && !overwrite) {
                throw new ArgumentException($"'{path}': File already exists.");
            }

            save(path, X509CryptoAliasDto.FromX509Alias(this, password));
        }
        /// <summary>
        /// Saves the X509CryptoAlias to a file
        /// </summary>
        /// <param name="path">The path to which to write the file</param>
        /// <param name="overwrite">If true, an existing file may be overwritten</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        public void Save(string path, bool overwrite = false) {
            if (path is null) {
                throw new ArgumentNullException(nameof(path));
            }
            if (File.Exists(path) && !overwrite) {
                throw new ArgumentException($"'{path}': File already exists.");
            }

            save(path, X509CryptoAliasDto.FromX509Alias(this));
        }

        internal bool LoadIfExists(bool complainIfExists) {
            if (!File.Exists(StoragePath)) {
                return false;
            }

            if (complainIfExists) {
                throw new X509AliasAlreadyExistsException(this);
            }

            decodeFromFile();

            return true;
        }
        internal byte[] EncodeCert(SecureString password) => _certService.ExportBase64UnSecure(Thumbprint, password, Context);

        void save(string path, X509CryptoAliasDto dto) {
            string json = DataSerializer.SerializeObject(dto);
            var encoded = json.Base64Encode();
            File.WriteAllText(path, encoded);
        }
        string printSecret(int index, string identifier, X509CryptSecretPrintFormat printFormat, bool revealSecret) {
            if (revealSecret) {
                string plaintext = DecryptText(Secrets[identifier]);
                return printFormat switch {
                    X509CryptSecretPrintFormat.Screen => $"Secret #{index}\r\n  Name: {identifier}\r\n  Value: {plaintext}\r\n",
                    X509CryptSecretPrintFormat.CommaSeparated => $"{index},{identifier},'{plaintext}'"
                };
            }

            return printFormat switch {
                X509CryptSecretPrintFormat.Screen => $"Artifact #{index}\r\nName: {identifier}\r\n",
                X509CryptSecretPrintFormat.CommaSeparated => $"{index},{identifier}"
            };
        }
        private byte[] exportCertKeyBase64() {
            var password = Util.GetPassword("Enter a strong password to protect the X509Alias file", Constants.MinimumPasswordLength, true);
            return _certService.ExportBase64UnSecure(Thumbprint, password, Context);
        }
        private void importCertKeyBase64(byte[] certBlob) {
            var password = Util.GetPassword("Enter the password to unlock this X509Alias file", 0);
            Certificate = _certService.ImportCertificate(certBlob, password, Context);
        }
        private string encode(bool includeCert) {
            var Serializer = new DataContractJsonSerializer(typeof(X509Alias));
            string json,
                   encoded;

            if (includeCert && loadCertificate()) {
                CertificateBlob = exportCertKeyBase64();
            }

            try {
                using (MemoryStream memStream = new MemoryStream()) {
                    Serializer.WriteObject(memStream, this);
                    byte[] jsonBytes = memStream.ToArray();

                    json = Encoding.UTF8.GetString(jsonBytes, 0, jsonBytes.Length);

                    memStream.Close();
                }

                encoded = json.Base64Encode();
                return encoded;
            } catch (Exception ex) {
                throw new X509CryptoException($"Unable to encode X509Alias {FullName}", ex);
            }
        }

        private void decodeFromFile(string importPath = "", string newName = "") {
            string fileToDecode = string.IsNullOrEmpty(importPath) ? StoragePath : importPath;

            try {

                X509Alias tmp = Context.CreateX509Alias();
                var Serializer = new DataContractJsonSerializer(GetType());
                string json = File.ReadAllText(fileToDecode).Base64Decode();
                using (var memStream = new MemoryStream(Encoding.UTF8.GetBytes(json))) {
                    tmp = Serializer.ReadObject(memStream) as X509Alias;
                    memStream.Close();
                }

                if (tmp is null) {
                    throw new ArgumentException($"The X509Alias could not be deserialized from file.");
                }
                Name = string.IsNullOrEmpty(newName) ? tmp.Name : newName;
                Thumbprint = tmp.Thumbprint;
                Secrets = tmp.Secrets;

                if (tmp.CertificateBlob != null) {
                    importCertKeyBase64(tmp.CertificateBlob);
                }
            } catch (Exception ex) {
                throw new X509CryptoException($"Unable to load X509Alias from path '{fileToDecode}'", ex);
            }
        }
        private bool loadCertificate() {
            var payLoad = _certService.FindCertificate(Thumbprint, Context, true);
            if (payLoad == null) {
                return false;
            }

            Certificate = payLoad;
            certificateLoaded = true;
            return true;

        }

        /// <summary>
        /// Creates a new X509Alias
        /// </summary>
        /// <param name="name">The desired name of the X509Alias</param>
        /// <param name="context">The <see cref="X509Context"/> where the alias should be created</param>
        /// <param name="overWrite">If true, an existing alias may be overwritten</param>
        /// <returns></returns>
        /// <exception cref="X509AliasAlreadyExistsException"></exception>
        public static X509Alias Create(string name, X509Context context, bool overWrite = false) {
            var payLoad = new X509Alias {
                Name = name,
                Context = context
            };
            if (!overWrite && payLoad.LoadIfExists(true)) {
                throw new X509AliasAlreadyExistsException(payLoad);
            }
            payLoad.Certificate = _certService.CreateX509CryptCertificate(name, context);

            return payLoad;
        }
        /// <summary>
        /// Creates a new X509Alias pointing to an existing encryption certificate
        /// </summary>
        /// <param name="name">The desired name of the X509Alias</param>
        /// <param name="context">The <see cref="X509Context"/> where the alias should be created</param>
        /// <param name="thumbprint">The thumbprint of the encryption certificate</param>
        /// <param name="overWrite">If true, an existing alias may be overwritten</param>
        /// <returns></returns>
        /// <exception cref="X509AliasAlreadyExistsException"></exception>
        /// <exception cref="X509CryptoCertificateNotFoundException"></exception>
        public static X509Alias Create(string name, X509Context context, string thumbprint, bool overWrite = false) {
            var payLoad = new X509Alias {
                Name = name,
                Context = context
            };
            if (!overWrite && payLoad.LoadIfExists(true)) {
                throw new X509AliasAlreadyExistsException(payLoad);
            }
            payLoad.Certificate = _certService.FindCertificate(thumbprint, context, false);

            return payLoad;
        }
        /// <summary>
        /// Loads an existing X509Alias
        /// </summary>
        /// <param name="name">The name of the alias</param>
        /// <param name="context">The <see cref="X509Context"/> where the alias exists</param>
        /// <returns></returns>
        /// <exception cref="X509AliasNotFoundException"></exception>
        public static X509Alias Load(string name, X509Context context) {
            var payLoad = new X509Alias {
                Name = name,
                Context = context
            };
            if (!payLoad.LoadIfExists(false)) {
                throw new X509AliasNotFoundException(payLoad);
            }

            return payLoad;
        }

        /// <summary>
        /// Loads an existing X509Alias from a file
        /// </summary>
        /// <param name="path">The path where the alias is stored</param>
        /// <param name="password">The password to unlock the private key</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="FileNotFoundException"></exception>
        /// <exception cref="ArgumentException"></exception>
        public static X509Alias Load(FileInfo path, SecureString password) {
            if (path is null) {
                throw new ArgumentNullException(nameof(path));
            }
            if (password is null) {
                throw new ArgumentNullException(nameof(password));
            }
            if (!File.Exists(path.FullName)) {
                throw new FileNotFoundException(path.FullName);
            }
            string json = File.ReadAllText(path.FullName).Base64Decode();
            var dto = DataSerializer.DeserializeObject<X509CryptoAliasDto>(json, false);
            if (dto is null) {
                throw new ArgumentException("The file is corrupt.");
            }

            return dto.Decode(password);
        }

        /// <summary>
        /// Imports the X509Alias from the specified Json file
        /// Note: This method does not import the encryption certificate or its associated key pair needed to work with the X509Alias.
        /// </summary>
        /// <param name="importPath">The path where the json file is located</param>
        /// <param name="context">The X509Context in which to load the alias</param>
        /// <param name="newName">If specified, the alias will be identified by the specified expression. Otherwise, the alias name imported from the json file will be used.</param>
        /// <returns></returns>
        public static X509Alias Import(string importPath, X509Context context, string newName = "") {
            if (!File.Exists(importPath)) {
                throw new FileNotFoundException(importPath);
            }

            try {


                X509Alias alias = context.CreateX509Alias();
                alias.decodeFromFile(importPath, newName);
                return alias;
            } catch (Exception ex) {
                throw new X509CryptoException($"Unable to import X509Alias from path '{importPath}'", ex);
            }
        }
        /// <summary>
        /// Indicates whether there is already a storage path for the specified X509Alias on the system
        /// </summary>
        /// <param name="alias">The X509Alias for which to check for a storage path</param>
        /// <param name="context">The <see cref="X509Context"/> to check for the <see cref="X509Alias"/>. If not specified, only the file location will be checked.</param>
        /// <returns>true if a storage path exists for the specified X509Alias</returns>
        public static bool TestAliasExists(X509Alias alias, X509Context context = null) {
            if (!File.Exists(alias.StoragePath)) {
                return false;
            }

            if (context != null) {
                try {
                    context.CreateX509Alias().decodeFromFile(alias.StoragePath);
                } catch {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// X509Alias Destructor
        /// </summary>
        public void Dispose() {
            cryptService?.Dispose();
            Name = null;
            thumbprint = null;
            Context = null;
            Secrets = null;
        }
    }
}
