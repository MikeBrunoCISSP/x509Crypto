using System.IO;
using System.Net;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.X509Crypto;
using Org.X509Crypto.Services;

namespace Tests {
    [TestClass]
    public class CertServiceTests {
        Resources _resources;
        private readonly CertService _certService = new CertService();

        [TestMethod]
        public void TestCreateCertificate() {
            var cert = _certService.CreateX509CryptCertificate(@"CN=X509Crypto Test", X509Context.UserReadOnly);
            Assert.IsNotNull(cert);
        }

        [TestMethod]
        public void TestImportExportCertificate() {
            SecureString password = new NetworkCredential("", "test123").SecurePassword;
            _certService.ImportCertificate(_resources.CertBytes, null, X509Context.UserFull);
            byte[] certBytes = _certService.ExportBase64UnSecure(_resources.GetThumbprint(), password, X509Context.UserFull);
            var cert = new X509Certificate2(certBytes, password);
            Assert.AreEqual(_resources.GetThumbprint(), cert.Thumbprint);

        }

        [TestInitialize]
        public void testInit() {
            _resources = JsonSerializer.Deserialize<Resources>(File.ReadAllText("resources.json"));
        }
    }
}
