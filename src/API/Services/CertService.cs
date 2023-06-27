using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.X509Crypto.Dto;

namespace Org.X509Crypto.Services;
public class CertService {
    public bool CertExistsInStore(string thumbprint, X509Context context) {
        using X509Store store = new X509Store(getStoreLocationFromContext(context.ContextType));
        store.Open(OpenFlags.ReadOnly);
        return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false).Count > 0;
    }
    public CertificateDto FindCertificate(string thumbprint, X509Context context) {
        using X509Store store = new X509Store(getStoreLocationFromContext(context.ContextType));
        store.Open(OpenFlags.ReadOnly);
        return findCertificate(thumbprint, store);
    }
    public void RemoveCertificate(string thumbprint, X509Context context) {
        using X509Store store = new X509Store(getStoreLocationFromContext(context.ContextType));
        store.Open(OpenFlags.MaxAllowed);
        CertificateDto dto = findCertificate(thumbprint, store);
        if (dto != null) {
            store.Remove(dto.Certificate);
        }
    }
    public void ImportCertificate(byte[] certBlob, SecureString password, X509Context context) {
        var certObj = new X509Certificate2();
        certObj.Import(certBlob, password.ToUnsecureString(), GetKeyStorageFlags(context));

        using var Store = new X509Store(getStoreLocationFromContext(context.ContextType));
        Store.Open(OpenFlags.MaxAllowed);
        Store.Add(certObj);
    }

    public void ExportCertificate(CertificateDto cert, String path) {
        if (File.Exists(path)) {
            File.Delete(path);
        }

        StringBuilder sb = new StringBuilder(Constants.BeginBase64Certificate);
        sb.AppendLine(Convert.ToBase64String(cert.Certificate.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
        sb.AppendLine(Constants.EndBase64Certificate);
        File.WriteAllText(path, sb.ToString());
    }

    public byte[] ExportBase64UnSecure(string thumbprint, SecureString password, X509Context context) {
        CertificateDto dto = FindCertificate(thumbprint, context);
        if (dto is null) {
            throw new X509CryptoCertificateNotFoundException(thumbprint, context);
        }

        return dto.Certificate.Export(X509ContentType.Pkcs12, password.ToUnsecureString());
    }

    public List<CertificateDto> GetAllCertificates(X509Context context) {
        var payLoad = new List<CertificateDto>();
        using var store = new X509Store(getStoreLocationFromContext(context.ContextType));
        store.Open(OpenFlags.ReadOnly);
        foreach (var cert in store.Certificates) {
            if (cert.HasPrivateKey) {
                payLoad.Add(new CertificateDto(cert));
            }
        }

        return payLoad;
    }
    public CertificateDto CreateX509CryptCertificate(int keyLength, string name, int yearsValid, X509Context context) {
        using var rsa = RSA.Create(keyLength);
        var request = new CertificateRequest($"CN={name}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        X509Certificate2 cert = request.CreateSelfSigned(DateTime.Now, DateTime.Now.AddYears(yearsValid));
        using var store = new X509Store(getStoreLocationFromContext(context.ContextType));
        store.Add(cert);
        return new CertificateDto(cert);
    }
    public X509KeyStorageFlags GetKeyStorageFlags(X509Context context) {
        return X509KeyStorageFlags.Exportable | (context.IsSystemContext()
            ? X509KeyStorageFlags.MachineKeySet
            : X509KeyStorageFlags.UserKeySet);
    }

    CertificateDto findCertificate(string thumbprint, X509Store openStore) {
        var searchResult = openStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
        if (searchResult.Count > 0
            && searchResult[0].HasPrivateKey
            && searchResult[0].PublicKey.Oid.Value.Equals(AlgorithmOid.RSA)) {
            return new CertificateDto(searchResult[0]);
        }

        return null;
    }
    StoreLocation getStoreLocationFromContext(X509CryptoContextType contextType) {
        return contextType switch {
            X509CryptoContextType.UserFull => StoreLocation.CurrentUser,
            X509CryptoContextType.UserReadOnly => StoreLocation.CurrentUser,
            X509CryptoContextType.SystemFull => StoreLocation.LocalMachine,
            X509CryptoContextType.SystemReadOnly => StoreLocation.LocalMachine
        };
    }
}
