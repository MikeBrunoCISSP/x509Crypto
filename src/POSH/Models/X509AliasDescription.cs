using System;
using Org.X509Crypto;
using Org.X509Crypto.Dto;

namespace X509CryptoPOSH {
    public class X509AliasDescription {
        public string AliasName { get; set; }
        public string Thumbprint { get; set; }
        public string Subject { get; set; }
        public DateTime Expires { get; set; }

        public X509AliasDescription(X509Alias alias) {
            AliasName = alias.Name;
            Thumbprint = alias.Thumbprint;
            CertificateDto cert = alias.GetCertificate();
            if (cert != null) {
                Subject = cert.Subject;
                Expires = cert.NotAfter;
            }
        }

        public X509AliasDescription(CertificateDto cert) {
            AliasName = Constants.NoAliasAssigned;
            Thumbprint = cert.Thumbprint;
            Subject = cert.Subject;
            Expires = cert.NotAfter;
        }
    }
}
