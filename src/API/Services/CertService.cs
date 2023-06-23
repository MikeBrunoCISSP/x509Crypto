using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography.X509Certificates;

namespace Org.X509Crypto.Services;
public class CertService {
    public bool CertExistsInStore(string thumbprint, StoreLocation storeLocation) {
        using X509Store store = new X509Store(storeLocation);
        store.Open(OpenFlags.ReadOnly);
        return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false).Count > 0;
    }
    public X509Certificate2 FindCertificate(string thumbprint, StoreLocation storeLocation) {
        using X509Store store = new X509Store(storeLocation);
        store.Open(OpenFlags.ReadOnly);
        return findCertificate(thumbprint, store);
    }
    public void RemoveCertificate(string thumbprint, StoreLocation storeLocation) {
        using X509Store store = new X509Store(storeLocation);
        store.Open(OpenFlags.MaxAllowed);
        X509Certificate2 certToRemove = findCertificate(thumbprint, store);
        if (certToRemove != null) {
            store.Remove(certToRemove);
        }
    }
    public void ImportCertificate(byte[] certBlob, SecureString password, StoreLocation storeLocation, X509KeyStorageFlags storageFlags) {
        var certObj = new X509Certificate2();
        certObj.Import(certBlob, password.ToUnsecureString(), storageFlags);

        using var Store = new X509Store(storeLocation);
        Store.Open(OpenFlags.MaxAllowed);
        Store.Add(certObj);
    }
    public byte[] ExportBase64UnSecure(string thumbprint, SecureString password, StoreLocation storeLocation) {
        X509Certificate2 cert = FindCertificate(thumbprint, storeLocation);
        if (cert is null) {
            throw new X509CryptoCertificateNotFoundException(thumbprint, X509Context.FromStoreLocation(storeLocation));
        }

        return cert.Export(X509ContentType.Pkcs12, password.ToUnsecureString());
    }

    public List<X509Certificate2> GetAllCertificates(StoreLocation storeLocation) {
        var payLoad = new List<X509Certificate2>();
        using var store = new X509Store(storeLocation);
        store.Open(OpenFlags.ReadOnly);
        foreach (var cert in store.Certificates) {
            if (cert.HasPrivateKey) {
                payLoad.Add(cert);
            }
        }

        return payLoad;
    }

    X509Certificate2 findCertificate(string thumbprint, X509Store openStore) {
        var searchResult = openStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
        if (searchResult.Count > 0 && searchResult[0].HasPrivateKey) {
            return searchResult[0];
        }

        return null;
    }

}
