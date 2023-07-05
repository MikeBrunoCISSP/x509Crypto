using System.Security.Cryptography.X509Certificates;

namespace Tests {
    public class Resources {
        private X509Certificate2 cert;
        private string thumbprint;

        public byte[] CertBytes { get; set; }
        public string ExportPath { get; set; }

        public X509Certificate2 GetCert() {
            return cert ?? (cert = new X509Certificate2(CertBytes));
        }

        public string GetThumbprint() {
            return thumbprint ?? (thumbprint = GetCert().Thumbprint);
        }
    }
}
