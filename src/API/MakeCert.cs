using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Security;

namespace Org.X509Crypto {
    public partial class X509Context {
        private static SecureRandom secureRandom = new SecureRandom();

        public void MakeCert(string name, int keyLength, int yearsValid, out string thumbprint) {
            try {
                using var rsa = RSA.Create(keyLength);
                var request = new CertificateRequest($"CN={name}", rsa, HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
                X509Certificate2 cert = request.CreateSelfSigned(DateTime.Now, DateTime.Now.AddYears(yearsValid));
                using var store = new X509Store(Location);
                store.Add(cert);
                thumbprint = cert.Thumbprint;
            } catch (Exception ex) {
                throw new Exception($"A certificate could not be added to the {Name} {nameof(X509Context)}.", ex);
            }
        }
    }
}
