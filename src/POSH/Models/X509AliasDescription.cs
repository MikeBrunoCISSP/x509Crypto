using Org.X509Crypto;
using System;
using System.Security.Cryptography.X509Certificates;

namespace X509CryptoPOSH
{
    public class X509AliasDescription
    {
        public string AliasName { get; set; }
        public string Thumbprint { get; set; }
        public string Subject { get; set; }
        public DateTime Expires { get; set; }

        public X509AliasDescription(X509Alias Alias)
        {
            AliasName = Alias.Name;
            Thumbprint = Alias.Thumbprint;
            Subject = Alias.Certificate.Subject;
            Expires = Alias.Certificate.NotAfter;
        }

        public X509AliasDescription(X509Certificate2 Certificate)
        {
            AliasName = Constants.NoAliasAssigned;
            Thumbprint = Certificate.Thumbprint;
            Subject = Certificate.Subject;
            Expires = Certificate.NotAfter;
        }
    }
}
