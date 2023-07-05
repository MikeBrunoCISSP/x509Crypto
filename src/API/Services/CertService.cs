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
    public static bool TestCertExists(string thumbprint, X509Context context) {
        using X509Store store = new X509Store(getStoreLocationFromContext(context.ContextFlags));
        store.Open(OpenFlags.ReadOnly);
        return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false).Count > 0;
    }
    public static CertificateDto FindCertificate(string thumbprint, X509Context context, bool nullSafe) {
        using X509Store store = new X509Store(getStoreLocationFromContext(context.ContextFlags));
        store.Open(OpenFlags.ReadOnly);
        return findCertificate(thumbprint, store, nullSafe);
    }
    public static void RemoveCertificate(string thumbprint, X509Context context) {
        using X509Store store = new X509Store(getStoreLocationFromContext(context.ContextFlags));
        store.Open(OpenFlags.MaxAllowed);
        CertificateDto dto = findCertificate(thumbprint, store, true);
        if (dto != null) {
            store.Remove(dto.Certificate);
        }
    }
    public static CertificateDto ImportCertificate(byte[] certBlob, SecureString password, X509Context context) {
        var certObj = new X509Certificate2();
        certObj.Import(certBlob, password.ToUnsecureString(), GetKeyStorageFlags(context));

        using var Store = new X509Store(getStoreLocationFromContext(context.ContextFlags));
        Store.Open(OpenFlags.MaxAllowed);
        Store.Add(certObj);
        return CertificateDto.FromX509Certificate2(certObj);
    }

    public static void ExportCertificate(CertificateDto cert, String path) {
        if (File.Exists(path)) {
            File.Delete(path);
        }

        StringBuilder sb = new StringBuilder("-----BEGIN CERTIFICATE-----\r\n");
        sb.AppendLine(Convert.ToBase64String(cert.Certificate.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
        sb.AppendLine("-----END CERTIFICATE-----");
        File.WriteAllText(path, sb.ToString());
    }

    public static byte[] ExportBase64UnSecure(string thumbprint, SecureString password, X509Context context) {
        CertificateDto dto = FindCertificate(thumbprint, context, false);
        return dto.Certificate.Export(X509ContentType.Pkcs12, password.ToUnsecureString());
    }

    public static List<CertificateDto> GetAllX509CryptoCertificates(X509Context context) {
        var payLoad = new List<CertificateDto>();
        using var store = new X509Store(getStoreLocationFromContext(context.ContextFlags));
        store.Open(OpenFlags.ReadOnly);
        foreach (var cert in store.Certificates) {
            if (cert.HasPrivateKey) {
                payLoad.Add(CertificateDto.FromX509Certificate2(cert));
            }
        }

        return payLoad;
    }

    public static CertificateDto CreateX509CryptCertificate(string name, X509Context context, int keyLength = 2048, int yearsValid = 3) {
        X509KeyStorageFlags storageFlags = X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable;
        if (context == X509Context.SystemFull) {
            storageFlags |= X509KeyStorageFlags.MachineKeySet;
        }
        using var rsa = RSA.Create(keyLength);
        var request = new CertificateRequest($"CN={name}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 ephemeral = request.CreateSelfSigned(DateTime.Now, DateTime.Now.AddYears(yearsValid));
        X509Certificate2 cert = new X509Certificate2(ephemeral.Export(X509ContentType.Pkcs12), string.Empty, storageFlags);

        using var store = new X509Store(getStoreLocationFromContext(context.ContextFlags));
        store.Open(OpenFlags.MaxAllowed);
        store.Add(cert);
        return CertificateDto.FromX509Certificate2(cert);
    }

    public static X509KeyStorageFlags GetKeyStorageFlags(X509Context context) {
        return X509KeyStorageFlags.Exportable | (context.IsSystemContext()
            ? X509KeyStorageFlags.MachineKeySet
            : X509KeyStorageFlags.UserKeySet);
    }

    static CertificateDto findCertificate(string thumbprint, X509Store openStore, bool nullSafe) {
        var searchResult = openStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
        if (searchResult.Count > 0
            && searchResult[0].HasPrivateKey
            && searchResult[0].PublicKey.Oid.Value.Equals(AlgorithmOid.RSA)) {
            return CertificateDto.FromX509Certificate2(searchResult[0]);
        }

        if (nullSafe) {
            return null;
        }

        throw new X509CryptoCertificateNotFoundException(thumbprint, openStore);
    }
    static StoreLocation getStoreLocationFromContext(X509CryptoContextFlags contextFlags) {
        return (contextFlags & X509CryptoContextFlags.User) == X509CryptoContextFlags.User
            ? StoreLocation.CurrentUser
            : StoreLocation.LocalMachine;
    }
}
