using System.Collections.Generic;
using System.Security;
using Org.X509Crypto.Services;

namespace Org.X509Crypto.Dto;

public class X509CryptoAliasDto {
    static readonly CertService _certService = new();

    public string Name { get; set; }
    public X509CryptoContextType ContextType { get; set; }
    public string Thumbprint { get; set; }
    public byte[] EncodedCert { get; set; }
    public Dictionary<string, string> Secrets { get; set; } = new();

    public X509Alias Decode(SecureString password = null) {
        var payLoad = new X509Alias {
            Name = Name,
            Thumbprint = Thumbprint,
            Context = X509Context.Select(ContextType),
            Secrets = Secrets
        };
        if (password != null && EncodedCert != null) {
            payLoad.ImportCert(EncodedCert, password);
        }

        return payLoad;
    }

    public static X509CryptoAliasDto FromX509Alias(X509Alias alias, SecureString password) {
        var payLoad = new X509CryptoAliasDto {
            Name = alias.Name,
            Thumbprint = alias.Thumbprint,
            ContextType = alias.Context.ContextType,
            Secrets = alias.Secrets
        };
        payLoad.EncodedCert = alias.EncodeCert(password);

        return payLoad;
    }
    public static X509CryptoAliasDto FromX509Alias(X509Alias alias) {
        return new X509CryptoAliasDto {
            Name = alias.Name,
            Thumbprint = alias.Thumbprint,
            ContextType = alias.Context.ContextType,
            Secrets = alias.Secrets
        };
    }
}
