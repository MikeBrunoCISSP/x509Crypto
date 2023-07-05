using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.X509Crypto;
using Org.X509Crypto.Services;

namespace Tests {
    [TestClass]
    public class CertServiceTests {
        Resources resources;

        [TestMethod]
        public void TestCertServiceUser() {
            // Create a new certificate in the User store.
            var cert = CertService.CreateX509CryptCertificate(@"CN=X509Crypto Test", X509Context.UserFull);
            Assert.IsNotNull(cert);

            // Test GetAllCertificates
            using (X509Store store = new X509Store(StoreLocation.CurrentUser)) {
                store.Open(OpenFlags.ReadOnly);
                var dtos = CertService.GetAllX509CryptoCertificates(X509Context.UserFull);
                Assert.AreEqual(store.Certificates.Cast<X509Certificate2>().Count(c => c.HasPrivateKey), dtos.Count);
            }

            // Test Importing certificate back into store
            SecureString password = new NetworkCredential("", "test123").SecurePassword;
            var certBytes = cert.Certificate.Export(X509ContentType.Pkcs12, password);
            var dto = CertService.ImportCertificate(certBytes, password, X509Context.UserFull);
            Assert.IsNotNull(dto);

            // Test Find certificate
            Assert.IsNotNull(CertService.FindCertificate(cert.Thumbprint, X509Context.UserFull, true));

            // Test Exporting certificate from store
            CertService.ExportCertificate(dto, resources.ExportPath);
            var exportedCert = new X509Certificate2(resources.ExportPath);
            File.Delete(resources.ExportPath);
            Assert.AreEqual(dto.Thumbprint, exportedCert.Thumbprint);

            // Test Exporting certificate and key
            var unsecureBytes = CertService.ExportBase64UnSecure(cert.Thumbprint, password, X509Context.UserFull);
            Assert.IsNotNull(unsecureBytes);

            try {
                // Test Removing certificate from the user store.
                CertService.RemoveCertificate(cert.Thumbprint, X509Context.UserFull);
            } catch (Exception ex) {
                Assert.Fail("Failed at RemoveCertificate", ex);
            }
        }

        [TestMethod]
        public void TestCertServiceSystem() {
            if (!testAmIAdmin()) {
                return;
            }
            // Create a new certificate in the User store.
            var cert = CertService.CreateX509CryptCertificate(@"CN=X509Crypto System Test", X509Context.SystemFull);
            Assert.IsNotNull(cert);

            // Test GetAllCertificates
            using (X509Store store = new X509Store(StoreLocation.LocalMachine)) {
                store.Open(OpenFlags.ReadOnly);
                var dtos = CertService.GetAllX509CryptoCertificates(X509Context.SystemFull);
                Assert.AreEqual(store.Certificates.Cast<X509Certificate2>().Count(c => c.HasPrivateKey), dtos.Count);
            }

            // Test Importing certificate back into store
            SecureString password = new NetworkCredential("", "test123").SecurePassword;
            var certBytes = cert.Certificate.Export(X509ContentType.Pkcs12, password);
            var dto = CertService.ImportCertificate(certBytes, password, X509Context.SystemFull);
            Assert.IsNotNull(dto);

            // Test Find certificate
            Assert.IsNotNull(CertService.FindCertificate(cert.Thumbprint, X509Context.SystemFull, true));

            // Test Exporting certificate from store
            CertService.ExportCertificate(dto, resources.ExportPath);
            var exportedCert = new X509Certificate2(resources.ExportPath);
            File.Delete(resources.ExportPath);
            Assert.AreEqual(dto.Thumbprint, exportedCert.Thumbprint);

            // Test Exporting certificate and key
            var unsecureBytes = CertService.ExportBase64UnSecure(cert.Thumbprint, password, X509Context.SystemFull);
            Assert.IsNotNull(unsecureBytes);

            try {
                // Test Removing certificate from the user store.
                CertService.RemoveCertificate(cert.Thumbprint, X509Context.SystemFull);
            } catch (Exception ex) {
                Assert.Fail("Failed at RemoveCertificate", ex);
            }
        }

        [TestMethod]
        public void TestGetKeyUsageFlags() {
            Assert.AreEqual(CertService.GetKeyStorageFlags(X509Context.UserFull), X509KeyStorageFlags.Exportable | X509KeyStorageFlags.UserKeySet);
            Assert.AreEqual(CertService.GetKeyStorageFlags(X509Context.SystemFull), X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
        }

        [TestInitialize]
        public void testInit() {
            resources = JsonSerializer.Deserialize<Resources>(File.ReadAllText("resources.json"));
        }

        bool testAmIAdmin() {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent()) {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }
    }
}
