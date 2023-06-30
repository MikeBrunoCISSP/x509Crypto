//using System;
//using System.Runtime.Serialization;

//namespace Org.X509Crypto {
//    public enum X509CryptoSecretPrintOptions {
//        None             = 0,
//        IncludePlaintext = 1
//    }

//    [DataContract]
//    public class X509CryptoSecret {
//        /// <summary>
//        /// Default Constructor
//        /// </summary>
//        public X509CryptoSecret() { }

//        /// <summary>
//        /// X509 Secret Constructor
//        /// </summary>
//        /// <param name="alias">A <see cref="X509Alias"/> with which to encrypt a secret</param>
//        /// <param name="identifier">A secret identifier</param>
//        /// <param name="plaintextValue">The secret value in plaintext</param>
//        /// <exception cref="X509CryptoException"></exception>
//        public X509CryptoSecret(X509Alias alias, string identifier, string plaintextValue) {
//            string cipherText;

//            try {
//                Id = identifier;

//                using (var agent = new X509CryptoAgent(alias)) {
//                    cipherText = agent.EncryptText(plaintextValue);
//                }
//                Value = cipherText;
//            } catch (Exception ex) {
//                throw new X509CryptoException($"Could not encrypt new secret named '{identifier}' in alias '{alias.Name}'", ex);
//            }
//        }
//        /// <summary>
//        /// X509 Secret Constructor
//        /// </summary>
//        /// <param name="identifier">A secret identifier</param>
//        /// <param name="encryptedValue">The encrypted secret value</param>
//        public X509CryptoSecret(string identifier, string encryptedValue) {
//            Id = identifier;
//            Value = encryptedValue;
//        }

//        /// <summary>
//        /// The identifier of the secret
//        /// </summary>
//        [DataMember]
//        public string Id { get; set; }
//        /// <summary>
//        /// The encrypted value of the secret
//        /// </summary>
//        [DataMember]
//        public string Value { get; set; }

//        /// <summary>
//        /// Decrypts the secret value
//        /// </summary>
//        /// <param name="alias">A <see cref="X509Alias"/> that can decrypt the secret</param>
//        /// <returns>The secret in plaintext</returns>
//        /// <exception cref="X509CryptoException">Thrown if the secret cannot be decrypted using the provided <see cref="X509Alias"/></exception>
//        public string RevealPlaintext(X509Alias alias) {
//            try {
//                return new X509CryptoAgent(alias).DecryptText(Value);
//            } catch (Exception ex) {
//                throw new X509CryptoException($"Could not decrypt secret named '{Id}' in Alias '{alias.Name}'", ex);
//            }
//        }
//        /// <summary>
//        /// Re-encrypts a secret using the specified <see cref="X509Alias"/>.
//        /// </summary>
//        /// <param name="alias">The <see cref="X509Alias"/> that currently encrypts the secret.</param>
//        /// <param name="newThumbprint">The thumbprint of the encryption certificate to use to re-encrypt the secret.</param>
//        /// <param name="newContext">The <see cref="X509Context"/> where the new encryption certificate is stored.</param>
//        public void ReEncrypt(X509Alias alias, string newThumbprint, X509Context newContext) {
//            Value = X509CryptoUtils.ReEncryptText(alias.Thumbprint, newThumbprint, Value, alias.Context, newContext);
//        }
//        /// <summary>
//        /// Prints the secret identifier
//        /// </summary>
//        /// <param name="index">The index of the secret.</param>
//        /// <returns></returns>
//        public string PrintIdentifierOnly(int index, X509CryptSecretPrintFormat printFormat) {
//            return printFormat switch {
//                X509CryptSecretPrintFormat.Screen => $"Artifact #{index + 1}\r\nName: {Id}\r\n",
//                X509CryptSecretPrintFormat.CommaSeparated => $"{index + 1},{Id}"
//            };
//        }
//        /// <summary>
//        /// Prints the secret identifier and plaintext value.
//        /// </summary>
//        /// <param name="index">The index of the secret.</param>
//        /// <param name="Alias">A <see cref="X509Alias"/> that can decrypt the secret</param>
//        /// <returns></returns>
//        public string PrintUnsecure(int index, X509Alias Alias, X509CryptSecretPrintFormat printFormat) {
//            String plaintext = RevealPlaintext(Alias);
//            return printFormat switch {
//                X509CryptSecretPrintFormat.Screen => $"Secret #{index + 1}\r\n  Name: {Id}\r\n  Value: {plaintext}\r\n",
//                X509CryptSecretPrintFormat.CommaSeparated => $"{index + 1},{Id},'{plaintext}'"
//            };
//        }
//    }
//}
