using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Org.X509Crypto
{
    public partial class X509Context
    {
        private static SecureRandom secureRandom = new SecureRandom();

        /// <summary>
        /// Generates a self-signed encryption certificate
        /// </summary>
        /// <param name="name">The certificate subject</param>
        /// <param name="keyLength">The desired public key length (multiples of 1024)</param>
        /// <param name="yearsValid">The number of years after which the certificate should be considered expired</param>
        /// <param name="thumbprint">reference string which will contain the thumbprint of the generated certificate</param>
        public void MakeCertWorker(string name, int keyLength, int yearsValid, out string thumbprint)
        {
            X509Certificate2 dotNetCert = null;
            AsymmetricCipherKeyPair keyPair = GenerateRsaKeyPair(keyLength);
            string formattedName = FormatX500(name);
            X509Name issuer = new X509Name(formattedName);
            X509Name subject = new X509Name(formattedName);

            ISignatureFactory signatureFactory;
            if (keyPair.Private is ECPrivateKeyParameters)
            {
                signatureFactory = new Asn1SignatureFactory(
                    X9ObjectIdentifiers.ECDsaWithSha256.ToString(),
                    keyPair.Private);
            }
            else
            {
                signatureFactory = new Asn1SignatureFactory(
                    PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString(),
                    keyPair.Private);
            }

            var certGenerator = new X509V3CertificateGenerator();
            certGenerator.SetIssuerDN(issuer);
            certGenerator.SetSubjectDN(subject);
            certGenerator.SetSerialNumber(BigInteger.ValueOf(1));
            certGenerator.SetNotAfter(DateTime.UtcNow.AddYears(yearsValid));
            certGenerator.SetNotBefore(DateTime.UtcNow);
            certGenerator.SetPublicKey(keyPair.Public);
            certGenerator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyEncipherment));
            BouncyCastle.X509.X509Certificate cert = certGenerator.Generate(signatureFactory);

            var bouncyStore = new Pkcs12Store();
            var certEntry = new X509CertificateEntry(cert);
            string friendlyName = cert.SubjectDN.ToString();
            bouncyStore.SetCertificateEntry(friendlyName, certEntry);
            bouncyStore.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(keyPair.Private), new[] { certEntry });
            char[] pass = RandomPass();

            using (MemoryStream stream = new MemoryStream())
            {
                bouncyStore.Save(stream, pass, secureRandom);
                dotNetCert = new X509Certificate2(stream.ToArray(), new string(pass), X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
                thumbprint = dotNetCert.Thumbprint;
                stream.Close();
            }

            X509Store dotNetStore = new X509Store(Location);
            dotNetStore.Open(OpenFlags.ReadWrite);
            dotNetStore.Add(dotNetCert);

            bool added = false;
            foreach (X509Certificate2 certInStore in dotNetStore.Certificates)
            {
                if (certInStore.Thumbprint == thumbprint)
                    added = true;
            }

            if (!added)
                throw new Exception($"A certificate could not be added to the {Name} {nameof(X509Context)}.");
        }

        private static AsymmetricCipherKeyPair GenerateRsaKeyPair(int length)
        {
            var keygenParam = new KeyGenerationParameters(secureRandom, length);

            var keyGenerator = new RsaKeyPairGenerator();
            keyGenerator.Init(keygenParam);
            return keyGenerator.GenerateKeyPair();
        }

        private static string FormatX500(string name)
        {
            if (!string.Equals(@"cn=", name.Substring(0, 3), StringComparison.OrdinalIgnoreCase))
                name = string.Format(@"cn={0}", name);
            name = name.Replace(",", "\\,");
            return name;
        }

        private static char[] RandomPass()
        {
            const string chars = @"ABCDEFGHIJKLMOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()-=+";
            int length = secureRandom.Next(10, 20);
            return Enumerable.Repeat(chars, length).Select(s => s[secureRandom.Next(s.Length)]).ToArray();
        }
    }
}
