﻿using System;
using System.IO;
using System.Text;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace Org.X509Crypto
{
    /// <summary>
    /// Represents an X509Context, a certificate/key pair and 0 or more secrets encrypted by the certificate/key pair
    /// </summary>
    [DataContract]
    public class X509Alias : IDisposable
    {
        private string thumbprint;

        /// <summary>
        /// The identifier assigned to this alias
        /// </summary>
        [DataMember]
        public string Name { get; set; }

        /// <summary>
        /// The thumbprint of the certificate used for cryptographic operations in this alias
        /// </summary>
        [DataMember]
        public string Thumbprint
        {
            get
            {
                return thumbprint;
            }
            set
            {
                thumbprint = value.RemoveNonHexChars();
            }
        }

        /// <summary>
        /// The context where cryptographic operations shoudl occur (either system or user)
        /// </summary>
        [DataMember]
        public X509Context Context { get; set; }

        /// <summary>
        /// The fully-qualified name of the X509Alias in the format [Context]\[Name]
        /// </summary>
        public string FullName
        {
            get
            {
                return $"{Context.Name}\\{Name}";
            }
        }

        [DataMember]
        internal X509Secret[] Secrets { get; set; }

        private string StoragePath
        {
            get
            {
                return Path.Combine(Context.StorageDirectory, $"{Name}{FileExtensions.X509Alias}");
            }
        }

        private X509Alias(X509Context Context)
        {
            this.Context = Context;
        }

        /// <summary>
        /// This constructor is intended to load an already-existing X509Alias
        /// </summary>
        /// <param name="Name">The desired identifier for the alias (must be unique within the specified context</param>
        /// <param name="Context">The context in which to create the alias</param>
        public X509Alias(string Name, X509Context Context)
            :this(Context)
        {
            this.Name = Name;

            if (!LoadIfExists(false))
            {
                throw new X509AliasNotFoundException(this);
            }
        }

        /// <summary>
        /// This constructor is intended to create a new X509Alias pointing to the specified encryption certificate
        /// </summary>
        /// <param name="Name">The desired identifier for the alias</param>
        /// <param name="Thumbprint">The SHA1 thumbprint of the certificate to be used for cryptographic operations. Must exist in the specified Context</param>
        /// <param name="Context">The context in which to create the alias</param>
        /// <param name="complainIfExists">If set to true, an exception is thrown if an existing alias identifier is specified for "Name"</param>
        public X509Alias(string Name, string Thumbprint, X509Context Context, bool complainIfExists)
            : this(Context)
        {
            this.Name = Name;
            this.Thumbprint = Thumbprint;

            LoadIfExists(complainIfExists);

            if (!X509CryptoAgent.CertificateExists(Thumbprint, Context))
            {
                throw new X509CryptoCertificateNotFoundException(Thumbprint, Context);
            }
        }

        public void Dispose()
        {
            Name = null;
            thumbprint = null;
            Context = null;
            Secrets = null;
        }

        /// <summary>
        /// Encrypts the specified text expression
        /// </summary>
        /// <param name="plaintext">the text expression to be encrypted</param>
        /// <returns>Base64-encoded ciphertext string</returns>
        public string EncryptText(string plaintext)
        {
            X509Secret Secret = new X509Secret(this, string.Empty, plaintext);
            return Secret.Value;
        }


        /// <summary>
        /// Encrypts the specified file. All file types are supported.
        /// </summary>
        /// <param name="inFile">The path to the file to be encrypted. Path must exist.</param>
        /// <param name="outFile">he path in which to write the encrypted file.</param>
        /// <param name="wipeTimesToWrite">Performs n-pass forensic wipe of the disk sectors where the input file was stored.</param>
        public void EncryptFile(string inFile, string outFile, int wipeTimesToWrite = 0)
        {
            using (X509CryptoAgent Agent = new X509CryptoAgent(this))
            {
                Agent.EncryptFile(inFile, outFile);
            }

            if (!File.Exists(outFile))
            {
                throw new X509CryptoException($"Unable to encrypt the file \"{inFile}\". The ciphertext file \"{outFile}\" could not be created.");
            }

            if (wipeTimesToWrite > 0)
            {
                X509Utils.WipeFile(inFile, wipeTimesToWrite);
            }
        }

        public void DecryptFile(string inFile, string outFile, int wipeTimesToWrite = 0)
        {
            using (X509CryptoAgent Agent = new X509CryptoAgent(this))
            {
                Agent.DecryptFile(inFile, outFile);
            }

            if (!File.Exists(outFile))
            {
                throw new X509CryptoException($"Unable to decrypt the file \"{inFile}\". The plaintext file \"{outFile}\" could not be created.");
            }

            if (wipeTimesToWrite > 0)
            {
                X509Utils.WipeFile(inFile, wipeTimesToWrite);
            }
        }

        /// <summary>
        /// Re-Encrypts and stores a secret from a different X509Alias in the current X509Alias
        /// </summary>
        /// <param name="Name">The identifier of the secret to be reencrypted</param>
        /// <param name="OldAlias">The identifier of the X509Alias where the input secret is located</param>
        /// <returns>A Bas64-encoded ciphertext string</returns>
        public string ReEncryptText(string Name, X509Alias OldAlias)
        {
            string plaintext = OldAlias.RecoverSecret(Name);
            return EncryptText(plaintext);
        }

        /// <summary>
        /// Decrypts the specified Base64-encoded ciphertext expression
        /// </summary>
        /// <param name="ciphertext">The Base64-encoded ciphertext expression to be decrypted</param>
        /// <returns>A recovered plaintext string</returns>
        public string DecryptText(string ciphertext)
        {
            string plaintext = string.Empty;
            using (X509CryptoAgent Agent = new X509CryptoAgent(Thumbprint, Context))
            {
                plaintext = Agent.DecryptText(ciphertext);
            }
            return plaintext;
        }

        /// <summary>
        /// Encrypts the specified plaintext expression and stores it in this X509Alias
        /// </summary>
        /// <param name="key">The desired identifier for the secret (must be unique within the alias)</param>
        /// <param name="plaintext">The plaintext expression to be encrypted</param>
        /// <param name="overwriteExisting">Indicates whether an existing secret in the alias with the same value for "Name" as specified may be overwritten</param>
        /// <returns>A Base64-encoded ciphertext string</returns>
        public string AddSecret(string key, string plaintext, bool overwriteExisting)
        {
            X509Secret Secret = new X509Secret(this, key, plaintext);
            ExtendSecrets(Secret, overwriteExisting);
            return Secret.Value;
        }

        /// <summary>
        /// Re-encrypts a secret from a different X509Alias and stores it in this X509Alias
        /// </summary>
        /// <param name="key">The identifier of the secret as it is stored in the old X509Alias</param>
        /// <param name="OldAlias">The old X509Alias where the secret is currently encrypted and stored</param>
        /// <returns>A Base64-encoded ciphertext expression</returns>
        public string AddSecret(string key, X509Alias OldAlias)
        {
            return AddSecret(key, OldAlias.RecoverSecret(key), false);
        }

        /// <summary>
        /// Gets the ciphertext value for the specified secret from the current X509Alias
        /// </summary>
        /// <param name="key">The identifier of the secret</param>
        /// <returns>A Base64-encoded ciphertext expression</returns>
        public string GetSecret(string key)
        {
            foreach(X509Secret Secret in Secrets)
            {
                if (Secret.Key.Matches(key))
                {
                    return Secret.Value;
                }
            }

            throw new X509CryptoException($"No secret named \"{key}\" was found in alias \"{FullName}\"");
        }

        /// <summary>
        /// Indicates whether a secret with the specified identifier exists within this X509Alias
        /// </summary>
        /// <param name="key">The secret identifier to check the X509Alias for</param>
        /// <returns>true if a secret with the specified identifier is found in this X509Alias</returns>
        public bool SecretExists(string key)
        {
            foreach (X509Secret secret in Secrets)
            {
                if (secret.Key.Matches(key))
                {
                    return true;
                }
            }
            return false;
        }

        public string RecoverSecret(string key)
        {
            foreach(X509Secret secret in Secrets)
            {
                if (secret.Key.Matches(key))
                {
                    return secret.Reveal(this);
                }
            }

            throw new X509CryptoException($"No secret named \"{key}\" was found in alias \"{FullName}\"");
        }

        /// <summary>
        /// Updates this X509Alias to use a new encryption certificate and key pair. The old certificate and key pair must still be available to perform this operation.
        /// </summary>
        /// <param name="newThumbprint">The SHA1 thumbprint of the new encryption certificate. The certificate and associated key pair must exist and be available in the specified X509Context</param>
        /// <param name="newContext">The X509Context where the new encryption certificate and key pair is located</param>
        public void ReEncrypt(string newThumbprint, X509Context newContext = null)
        {
            if (newContext == null)
            {
                newContext = Context;
            }

            newThumbprint = newThumbprint.RemoveNonHexChars();
            if (!X509CryptoAgent.CertificateExists(newThumbprint, newContext))
            {
                throw new X509CryptoException($"A valid encryption certificate with thumbprint {newThumbprint} was not found in the {Context.Name} context");
            }

            foreach(X509Secret secret in Secrets)
            {
                secret.ReEncrypt(this, newThumbprint, newContext);
            }

            Thumbprint = newThumbprint;
            Context = newContext;
        }

        /// <summary>
        /// Exports the encryption certificate contained in this alias to a Base64-encoded text file. The private key is not exported.
        /// </summary>
        /// <param name="path">The fully-qualified path where the export file should be written</param>
        public void ExportCert(string path)
        {
            X509CryptoAgent.ExportCert(Thumbprint, Context, path);
        }

        /// <summary>
        /// Exports this X509Alias to a Json-formatted file
        /// Note: This method does NOT export the encryption certificate or the associated key pair. 
        /// </summary>
        /// <param name="exportPath">The path where the export file should be written (a .json extension is added if no file extension is specified)</param>
        /// <param name="overwriteExisting">Indicates whether an existing file may be overwritten if a file should exist at the indicated export path</param>
        public void Export(string exportPath, bool overwriteExisting = false)
        {
            if (!Path.GetExtension(exportPath).Matches(FileExtensions.Json))
            {
                exportPath = $"{exportPath}{FileExtensions.Json}";
            }

            if (File.Exists(exportPath) && !overwriteExisting)
            {
                throw new X509CryptoException($"Cannot export the X509Alias {FullName}: file exists: \"{exportPath}\". Set overwriteExisting=true to overwrite");
            }

            File.Delete(exportPath);
            File.WriteAllText(exportPath, Encode());

            if (!File.Exists(exportPath))
            {
                throw new FileNotFoundException($"Could not export X509Alias {FullName}: File not found at specified path ({exportPath})");
            }
        }

        /// <summary>
        /// Writes the X509Alias to the local file system for later retrieval
        /// </summary>
        public void Commit()
        {
            if (!Directory.Exists(Context.StorageDirectory))
            {
                Directory.CreateDirectory(Context.StorageDirectory);
            }

            Export(StoragePath, true);
        }

        /// <summary>
        /// Removes this X509Alias from the file system
        /// </summary>
        public void Remove()
        {
            Directory.Delete(StoragePath, true);

            if (AliasExists(this))
            {
                throw new X509CryptoException($"The X509Crypto alias \"{Name}\" could not be removed from the {Context.Name} context");
            }
        }

        /// <summary>
        /// Generates a text report of the X509Artifacts contained within this X509Alias
        /// </summary>
        /// <param name="reveal">Indicates whether the plaintext values of each X509Secret should be revealed in the output</param>
        /// <returns>A text report listing all X509Secrets contained within this X509Alias</returns>
        public string DumpSecrets(bool reveal)
        {
            if (Secrets.Length == 0)
            {
                return $"No secrets stored in X509Alias {Context.Name}\\{Name}";
            }

            StringBuilder Output = new StringBuilder($"{Secrets.Length} secrets exist in X509Alias {Context.Name}\\{Name}:\r\n");
            Output.AppendLine(@"------------------------------------------------------------");
            for (int x = 0; x<Secrets.Length; x++)
            {
                Output.AppendLine(reveal ? Secrets[x].Dump(x, this) : Secrets[x].Dump(x));
            }
            Output.AppendLine();
            return Output.ToString();
        }

        /// <summary>
        /// Generates a comma-separated report of the X509Secrets contained within this X509Alias
        /// </summary>
        /// <param name="reveal">Indicates whether the plaintext values of each X509Secret should be revealed in the output</param>
        /// <returns>A comma-separated report listing all X509Secrets contained within this X509Alias</returns>
        public string DumpSecretsCSV(bool reveal)
        {
            StringBuilder Output = new StringBuilder(string.Empty);
            Output.AppendLine(reveal ? CSVHeader.WithSecrets : CSVHeader.WithoutSecrets);
            for (int x = 0; x<Secrets.Length; x++)
            {
                Output.AppendLine(reveal ? Secrets[x].DumpCSV(x, this) : Secrets[x].DumpCSV(x));
            }
            return Output.ToString();
        }

        private bool LoadIfExists(bool complainIfExists)
        {
            if (!File.Exists(StoragePath))
            {
                return false;
            }

            if (complainIfExists)
            {
                throw new X509AliasAlreadyExistsException(this);
            }
            else
            {
                DecodeFromFile();
            }
        }

        private void LoadSecret(string key, string ciphertext)
        {
            X509Secret Secret = new X509Secret(key, ciphertext);
            ExtendSecrets(Secret);
        }

        private void ExtendSecrets(X509Secret SecretToAdd, bool overwriteExisting = false)
        {
            if (Secrets == null)
            {
                Secrets = new X509Secret[1];
                Secrets[0] = SecretToAdd;
            }
            else
            {
                for (int x = 0; x<Secrets.Length; x++)
                {
                    if (Secrets[x].Key.Matches(SecretToAdd.Key))
                    {
                        if (overwriteExisting)
                        {
                            Secrets[x] = SecretToAdd;
                            return;
                        }
                        else
                        {
                            throw new X509SecretAlreadyExistsException(this, SecretToAdd);
                        }
                    }
                }

                X509Secret[] Expanded = new X509Secret[Secrets.Length + 1];
                for (int x = 0; x < Secrets.Length; x++)
                {
                    Expanded[x] = Secrets[x];
                }
                Expanded[Secrets.Length] = SecretToAdd;
                Secrets = Expanded;
            }
        }

        private string Encode()
        {
            var Serializer = new DataContractJsonSerializer(typeof(X509Alias));
            string json,
                   encoded;

            try
            {
                using (MemoryStream memStream = new MemoryStream())
                {
                    Serializer.WriteObject(memStream, this);
                    byte[] jsonBytes = memStream.ToArray();

                    json = Encoding.UTF8.GetString(jsonBytes, 0, jsonBytes.Length);

                    memStream.Close();
                }

                encoded = json.Base64Encode();
                return encoded;
            }
            catch (Exception ex)
            {
                throw new X509CryptoException($"Unable to encode X509Alias {FullName}", ex);
            }
        }

        private void DecodeFromFile(string importPath = "")
        {
            string fileToDecode = string.IsNullOrEmpty(importPath) ? StoragePath : importPath;

            try
            {
                X509Alias tmp = new X509Alias(Context);
                var Serializer = new DataContractJsonSerializer(GetType());
                string json = File.ReadAllText(fileToDecode).Base64Decode();
                using (MemoryStream MemStream = new MemoryStream(Encoding.UTF8.GetBytes(json)))
                {
                    tmp = Serializer.ReadObject(MemStream) as X509Alias;
                    MemStream.Close();
                }

                Thumbprint = tmp.Thumbprint;
                Secrets = tmp.Secrets;
            }
            catch (Exception ex)
            {
                throw new X509CryptoException($"Unable to load X509Alias from path \"{fileToDecode}\"", ex);
            }
        }

        /// <summary>
        /// Imports the X509Alias from the specified Json file
        /// Note: This method does not import the encryption certificate or its associated key pair needed to work with the X509Alias.
        /// </summary>
        /// <param name="importPath">The path where the json file is located</param>
        /// <param name="Context">The X509Context in which to load the alias</param>
        /// <param name="newName">If specified, the alias will be identified by the specified expression. Otherwise, the alias name imported from the json file will be used.</param>
        /// <returns></returns>
        public static X509Alias Import(string importPath, X509Context Context, string newName = "")
        {
            if (!File.Exists(importPath))
            {
                throw new FileNotFoundException(importPath);
            }

            try
            {
                X509Alias Alias = new X509Alias(Context);
                Alias.DecodeFromFile(importPath);

                if (!string.IsNullOrEmpty(newName))
                {
                    Alias.Name = newName;
                }
                return Alias;
            }
            catch (Exception ex)
            {
                throw new X509CryptoException($"Unable to import X509Alias from path {importPath}", ex);
            }
        }

        /// <summary>
        /// Indicates whether there is already a storage path for the specified X509Alias on the system
        /// </summary>
        /// <param name="Alias">The X509Alias for which to check for a storage path</param>
        /// <returns>true if a storage path exists for the specified X509Alias</returns>
        public static bool AliasExists(X509Alias Alias)
        {
            return File.Exists(Alias.StoragePath);
        }

        internal static Dictionary<string, X509Certificate2> GetAll(X509Context Context)
        {
            Dictionary<string, X509Certificate2> Aliases = new Dictionary<string, X509Certificate2>();
            X509Certificate2Collection CertStore = GetCertificates(Context);

            X509Alias CurrentAlias;
            foreach(string aliasName in Context.GetAliasNames())
            {
                CurrentAlias = new X509Alias(aliasName, Context);
                if (X509CryptoAgent.CertificateExists(CurrentAlias.Thumbprint, Context))
                {
                    foreach(X509Certificate2 Cert in CertStore)
                    {
                        if (Cert.Thumbprint.Matches(CurrentAlias.Thumbprint))
                        {
                            Aliases.Add(aliasName, Cert);
                            break;
                        }
                    }
                }
            }
            return Aliases;
        }

        internal static string GetOne(string thumbprint, X509Context Context)
        {
            X509Alias CurrentAlias;
            foreach(X509Alias Alias in Context.GetAliases())
            {

            }
        }

        private static X509Certificate2Collection GetCertificates(X509Context Context)
        {
            X509Store Store = new X509Store(Context.Location);
            Store.Open(OpenFlags.ReadOnly);
            return Store.Certificates;
        }
    }
}
