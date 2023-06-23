using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.X509Crypto.Services;

namespace Org.X509Crypto {
    /// <summary>
    /// Represents an X509Context, a certificate/key pair and 0 or more secrets encrypted by the certificate/key pair
    /// </summary>
    [DataContract]
    public class X509Alias : IDisposable {
        private static readonly CertService _certService = new();

        private string thumbprint;
        private bool certificateLoaded;
        private X509Certificate2 certificate;

        /// <summary>
        /// Default constructor
        /// </summary>
        public X509Alias() { }
        /// <summary>
        /// This constructor is intended to load an already-existing X509Alias
        /// </summary>
        /// <param name="name">The desired identifier for the alias (must be unique within the specified context</param>
        /// <param name="context">The context in which to create the alias</param>
        public X509Alias(string name, X509Context context) {
            Context = context;
            Name = name;

            if (!loadIfExists(false)) {
                throw new X509AliasNotFoundException(this);
            }
        }
        /// <summary>
        /// This constructor is intended to create a new X509Alias pointing to the specified encryption certificate
        /// </summary>
        /// <param name="name">The desired identifier for the alias</param>
        /// <param name="thumbprint">The SHA1 thumbprint of the certificate to be used for cryptographic operations. Must exist in the specified Context</param>
        /// <param name="context">The context in which to create the alias</param>
        /// <param name="complainIfExists">If set to true, an exception is thrown if an existing alias identifier is specified for "Name"</param>
        public X509Alias(string name, string thumbprint, X509Context context, bool complainIfExists) {
            Context = context;
            Name = name;
            Thumbprint = thumbprint;

            loadIfExists(complainIfExists);

            if (!X509CryptoAgent.CertificateExists(thumbprint, context)) {
                throw new X509CryptoCertificateNotFoundException(thumbprint, context);
            }
        }

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
        /// The context where cryptographic operations shoudl occur (either system or user)
        /// </summary>
        [DataMember]
        public X509Context Context { get; set; }
        /// <summary>
        /// The fully-qualified name of the X509Alias in the format [Context]\[Name]
        /// </summary>
        public string FullName => $"{Context.Name}\\{Name}";

        [DataMember]
        public Dictionary<string, X509CryptoSecret> Secrets { get; set; } = new();
        [DataMember]
        internal byte[] CertificateBlob { get; set; }

        private string StoragePath => Path.Combine(Context.GetStorageDirectory(), $"{Name}{FileExtensions.X509Alias}");

        private X509KeyStorageFlags StorageFlags {
            get {
                var flags = X509KeyStorageFlags.Exportable;
                if (Context.IsSystemContext()) {
                    flags |= X509KeyStorageFlags.MachineKeySet;
                } else {
                    flags |= X509KeyStorageFlags.UserKeySet;
                }

                return flags;
            }
        }

        /// <summary>
        /// Gets the certificate associated with this <see cref="X509Alias"/>
        /// </summary>
        /// <returns>An <see cref="X509Certificate2"/></returns>
        /// <exception cref="X509CryptoException"></exception>
        public X509Certificate2 GetCertificate() {
            if (!certificateLoaded && !loadCertificate()) {
                return null;
            }

            return certificate;
        }
        /// <summary>
        /// Determines whether the encryption certificate exists in the <see cref="X509Context"/>
        /// </summary>
        /// <param name="Context"></param>
        /// <returns></returns>
        public bool HasCert(X509Context Context) {
            return _certService.CertExistsInStore(Thumbprint, Context.Location);
        }

        /// <summary>
        /// Encrypts the specified text expression
        /// </summary>
        /// <param name="plaintext">the text expression to be encrypted</param>
        /// <returns>Base64-encoded ciphertext string</returns>
        public string EncryptText(string plaintext) {
            X509CryptoSecret Secret = new X509CryptoSecret(this, string.Empty, plaintext);
            return Secret.Value;
        }


        /// <summary>
        /// Encrypts the specified file. All file types are supported.
        /// </summary>
        /// <param name="inFile">The path to the file to be encrypted. Path must exist.</param>
        /// <param name="outFile">he path in which to write the encrypted file.</param>
        /// <param name="wipeTimesToWrite">Performs n-pass forensic wipe of the disk sectors where the input file was stored.</param>
        public void EncryptFile(string inFile, string outFile, int wipeTimesToWrite = 0) {
            using (X509CryptoAgent Agent = new X509CryptoAgent(this)) {
                Agent.EncryptFile(inFile, outFile);
            }

            if (!File.Exists(outFile)) {
                throw new X509CryptoException($"Unable to encrypt the file '{inFile}'. The ciphertext file '{outFile}' could not be created.");
            }

            if (wipeTimesToWrite > 0) {
                X509Utils.WipeFile(inFile, wipeTimesToWrite);
            }
        }

        /// <summary>
        /// Re-encrypts the specified file using this X509Alias
        /// </summary>
        /// <param name="inFile">The path to the ciphertext file to re-encrypt</param>
        /// <param name="OldAlias">The X509Alias which was previously used to encrypt the file</param>
        public void ReEncryptFile(string inFile, X509Alias OldAlias) {
            X509Utils.ReEncryptFile(OldAlias, this, inFile);
        }

        /// <summary>
        /// Recovers the specified encrypted file
        /// </summary>
        /// <param name="inFile">The path to the encrypted file to be recovered. Path must exist</param>
        /// <param name="outFile">The path in which to write the recovered plaintext file</param>
        /// <param name="wipeTimesToWrite">Performs n-pass forensic wipe of the disk sectors where the input file was stored.</param>
        public void DecryptFile(string inFile, string outFile, int wipeTimesToWrite = 0) {
            using (X509CryptoAgent Agent = new X509CryptoAgent(this)) {
                Agent.DecryptFile(inFile, outFile);
            }

            if (!File.Exists(outFile)) {
                throw new X509CryptoException($"Unable to decrypt the file '{inFile}'. The plaintext file '{outFile}' could not be created.");
            }

            if (wipeTimesToWrite > 0) {
                X509Utils.WipeFile(inFile, wipeTimesToWrite);
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
        /// Decrypts the specified Base64-encoded ciphertext expression
        /// </summary>
        /// <param name="ciphertext">The Base64-encoded ciphertext expression to be decrypted</param>
        /// <returns>A recovered plaintext string</returns>
        public string DecryptText(string ciphertext) {
            string plaintext = string.Empty;
            using (X509CryptoAgent Agent = new X509CryptoAgent(Thumbprint, Context)) {
                plaintext = Agent.DecryptText(ciphertext);
            }
            return plaintext;
        }

        /// <summary>
        /// Encrypts the specified plaintext expression and stores it in this X509Alias
        /// </summary>
        /// <param name="identifier">The desired identifier for the secret (must be unique within the alias)</param>
        /// <param name="plaintext">The plaintext expression to be encrypted</param>
        /// <param name="overwriteExisting">Indicates whether an existing secret in the alias with the same value for "Name" as specified may be overwritten</param>
        /// <returns>A Base64-encoded ciphertext string</returns>
        public string AddSecret(string identifier, string plaintext, bool overwriteExisting) {
            X509CryptoSecret secret = createSecret(identifier.ToLower(), plaintext);
            return AddSecret(secret, overwriteExisting);
        }
        /// <summary>
        /// Adds a secret (which has already been encrypted using the certificate associated with this X509Alias) and its identifier to this X509Alias
        /// </summary>
        /// <param name="secret">The <see cref="X509CryptoSecret"/> to add to the alias</param>
        /// <param name="overwriteExisting">Indicates whether an existing secret in the alias with the same value for "Name" as specified may be overwritten</param>
        public string AddSecret(X509CryptoSecret secret, bool overwriteExisting) {
            if (Secrets.ContainsKey(secret.Id)) {
                if (overwriteExisting) {
                    Secrets[secret.Id] = secret;
                }
                throw new X509SecretAlreadyExistsException(this, secret.Id);
            }
            Secrets.Add(secret.Id, secret);
            return secret.Value;
        }
        /// <summary>
        /// Re-encrypts a secret from a different X509Alias and stores it in this X509Alias
        /// </summary>
        /// <param name="identifier">The identifier of the secret as it is stored in the old X509Alias</param>
        /// <param name="OldAlias">The old X509Alias where the secret is currently encrypted and stored</param>
        /// <param name="overwriteExisting">If true, an existing secret in this X509Alias with the same identifier may be overwritten</param>
        /// <returns>A Base64-encoded ciphertext expression</returns>
        public string AddSecret(string identifier, X509Alias OldAlias, bool overwriteExisting) {
            return AddSecret(identifier.ToLower(), OldAlias.RecoverSecret(identifier), overwriteExisting);
        }

        /// <summary>
        /// Gets the ciphertext value for the specified secret from the current X509Alias
        /// </summary>
        /// <param name="identifier">The identifier of the secret</param>
        /// <returns>A Base64-encoded ciphertext expression</returns>
        public string GetEncryptedSecret(string identifier) {
            String normalizedIdentifier = identifier.ToLower();
            if (Secrets.ContainsKey(normalizedIdentifier)) {
                return Secrets[normalizedIdentifier].Value;
            }

            throw new X509CryptoException($"No secret named '{identifier}' was found in alias '{FullName}'");
        }

        /// <summary>
        /// Indicates whether a secret with the specified identifier exists within this X509Alias
        /// </summary>
        /// <param name="identifier">The secret identifier to check the X509Alias for</param>
        /// <returns>true if a secret with the specified identifier is found in this X509Alias</returns>
        public bool TestSecretExists(string identifier) {
            return Secrets.ContainsKey(identifier.ToLower());
        }

        /// <summary>
        /// Recovers a secret from an X509Alias with the specified identifier
        /// </summary>
        /// <param name="identifier">The identifier of the secret to be recovered</param>
        /// <returns>The recovered, plaintext secret</returns>
        public string RecoverSecret(string identifier) {
            String normalizedIdentifier = identifier.ToLower();
            if (Secrets.ContainsKey(normalizedIdentifier)) {
                return Secrets[normalizedIdentifier].RevealPlaintext(this);
            }

            throw new X509CryptoException($"No secret named '{identifier}' was found in alias '{FullName}'");
        }

        /// <summary>
        /// Updates this X509Alias to use a new encryption certificate and key pair. The old certificate and key pair must still be available to perform this operation.
        /// </summary>
        /// <param name="newThumbprint">The SHA1 thumbprint of the new encryption certificate. The certificate and associated key pair must exist and be available in the specified X509Context</param>
        /// <param name="newContext">The X509Context where the new encryption certificate and key pair is located</param>
        public void ReEncrypt(string newThumbprint, X509Context newContext = null) {
            newContext ??= Context;

            newThumbprint = newThumbprint.RemoveNonHexChars();
            if (!_certService.CertExistsInStore(newThumbprint, newContext.Location)) {
                throw new X509CryptoException($"A valid encryption certificate with thumbprint {newThumbprint} was not found in the {Context.Name} context");
            }

            foreach (X509CryptoSecret secret in Secrets.Values) {
                secret.ReEncrypt(this, newThumbprint, newContext);
            }

            Thumbprint = newThumbprint;
            Context = newContext;
            Commit();
        }

        /// <summary>
        /// Exports the encryption certificate contained in this alias to a Base64-encoded text file. The private key is not exported.
        /// </summary>
        /// <param name="path">The fully-qualified path where the export file should be written</param>
        public void ExportCert(string path) {
            X509CryptoAgent.ExportCert(Thumbprint, Context, path);
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
                X509Utils.DeleteFile(StoragePath, complainIfNotFound: true, confirmDelete: true);

                if (!deleteCert) {
                    return;
                }

                _certService.RemoveCertificate(Thumbprint, Context.Location);
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
            foreach (X509CryptoSecret secret in Secrets.Values) {
                output.AppendLine(revealSecrets
                    ? secret.PrintUnsecure(index, this, printFormat)
                    : secret.PrintIdentifierOnly(index, printFormat));
                index++;
            }
            output.AppendLine();
            return output.ToString();
        }

        X509CryptoSecret createSecret(string identifier, string plaintextValue) {
            return new X509CryptoSecret {
                Id = identifier,
                Value = EncryptText(plaintextValue)
            };
        }
        private byte[] exportCertKeyBase64() {
            var password = Util.GetPassword("Enter a strong password to protect the X509Alias file", Constants.MinimumPasswordLength, true);
            return _certService.ExportBase64UnSecure(Thumbprint, password, Context.Location);
        }
        private void importCertKeyBase64(byte[] certBlob) {
            var password = Util.GetPassword("Enter the password to unlock this X509Alias file", 0);
            _certService.ImportCertificate(certBlob, password, Context.Location, StorageFlags);
        }
        private bool loadIfExists(bool complainIfExists) {
            if (!File.Exists(StoragePath)) {
                return false;
            }

            if (complainIfExists) {
                throw new X509AliasAlreadyExistsException(this);
            }

            decodeFromFile();

            return true;
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
            using var store = new X509Store(Context.Location);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection result = store.Certificates.Find(X509FindType.FindByThumbprint, Thumbprint, false);
            if (result.Count > 0 && result[0].HasPrivateKey) {
                certificate = result[0];
                certificateLoaded = true;
                return true;
            }

            return false;
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

        internal static Dictionary<string, X509Certificate2> GetAll(X509Context context) {
            var aliases = new Dictionary<string, X509Certificate2>();
            X509Certificate2Collection certStore = GetCertificates(context);

            X509Alias currentAlias;
            foreach (string aliasName in context.GetAliasNames()) {
                currentAlias = new X509Alias(aliasName, context);
                using X509Store store = new X509Store(context.Location);
                store.Open(OpenFlags.ReadOnly);
                var searchResult = store.Certificates.Find(X509FindType.FindByThumbprint, currentAlias.Thumbprint, false);
                if (searchResult.Count > 0 && searchResult[0].HasPrivateKey) {
                    aliases.Add(aliasName, searchResult[0]);
                }
            }
            return aliases;
        }

        internal static string GetOne(string thumbprint, X509Context Context) {
            foreach (X509Alias Alias in Context.GetAliases()) {
                if (Alias.Thumbprint.Matches(thumbprint)) {
                    return Alias.Name;
                }
            }

            throw new X509AliasNotFoundException(thumbprint, Context);
        }

        private static X509Certificate2Collection GetCertificates(X509Context Context) {
            X509Store Store = new X509Store(Context.Location);
            Store.Open(OpenFlags.ReadOnly);
            return Store.Certificates;
        }

        /// <summary>
        /// X509Alias Destructor
        /// </summary>
        public void Dispose() {
            Name = null;
            thumbprint = null;
            Context = null;
            Secrets = null;
        }
    }
}
