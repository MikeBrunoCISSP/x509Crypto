using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;

namespace Org.X509Crypto
{
    [DataContract]
    internal class X509Secret
    {
        [DataMember]
        internal string Key { get; set; }

        [DataMember]
        internal string Value { get; set; }

        internal X509Secret(X509Alias Alias, string key, string value)
        {
            string cipherText;

            try
            {
                Key = key;

                using (X509CryptoAgent Agent = new X509CryptoAgent(Alias))
                {
                    cipherText = Agent.EncryptText(value);
                }
                Value = cipherText;
            }
            catch (Exception ex)
            {
                throw new X509CryptoException($"Could not encrypt new secret named \"{key}\" in alias \"{Alias.Name}\"", ex);
            }
        }

        internal X509Secret(string key, string value)
        {
            Key = key;
            Value = value;
        }

        internal string Reveal(X509Alias Alias)
        {
            try
            {
                using (X509CryptoAgent Agent = new X509CryptoAgent(Alias))
                {
                    return Agent.DecryptText(Value);
                }
            }
            catch (Exception ex)
            {
                throw new X509CryptoException($"Could not decrypt secret named \"{Key}\" in Alias \"{Alias.Name}\"", ex);
            }
        }

        internal string Dump(int index)
        {
            return $"Artifact #{index + 1}\r\nName: {Key}\r\n";
        }

        internal string Dump(int index, X509Alias Alias)
        {
            StringBuilder sb = new StringBuilder($"Secret #{index + 1}\r\nName: {Key}\r\n");
            sb.AppendLine($"Value: {Reveal(Alias)}\r\n");
            return sb.ToString();
        }

        internal string DumpCSV(int index)
        {
            return $"{index + 1},{Key}";
        }

        internal string DumpCSV(int index, X509Alias Alias)
        {
            return $"{index + 1},{Key},\"{Reveal(Alias)}\"";
        }

        internal void ReEncrypt(X509Alias Alias, string newThumbprint, X509Context newContext)
        {
            string newValue = X509Utils.ReEncryptText(Alias.Thumbprint, newThumbprint, Value, Alias.Context, newContext);
            Value = newValue;
        }
    }
}
