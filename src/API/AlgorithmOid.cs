using System.Security.Cryptography;

namespace Org.X509Crypto;
public class AlgorithmOid {
    public const string RSA             = "1.2.840.113549.1.1.1";
    public const string ECC             = "1.2.840.10045.2.1";

    // ECC named curves
    public const string SecP160R1       = "1.3.132.0.8";
    public const string SecP160K1       = "1.3.132.0.9";
    public const string SecP256K1       = "1.3.132.0.10";
    public const string SecP160R2       = "1.3.132.0.30";
    public const string SecP192K1       = "1.3.132.0.31";
    public const string SecP224K1       = "1.3.132.0.32";
    public const string NistP224        = "1.3.132.0.33";
    public const string ECDSA_P384      = "1.3.132.0.34";
    public const string ECDSA_P521      = "1.3.132.0.35";
    public const string ECDSA_P256      = "1.2.840.10045.3.1.7";
}

public class EccCurveOid {
    public static readonly Oid SecP160R1  = new Oid("1.3.132.0.8");
    public static readonly Oid SecP160K1  = new Oid("1.3.132.0.9");
    public static readonly Oid SecP256K1  = new Oid("1.3.132.0.10");
    public static readonly Oid SecP160R2  = new Oid("1.3.132.0.30");
    public static readonly Oid SecP192K1  = new Oid("1.3.132.0.31");
    public static readonly Oid SecP224K1  = new Oid("1.3.132.0.32");
    public static readonly Oid NistP224   = new Oid("1.3.132.0.33");
    public static readonly Oid ECDSA_P384 = new Oid("1.3.132.0.34");
    public static readonly Oid ECDSA_P521 = new Oid("1.3.132.0.35");
    public static readonly Oid ECDSA_P256 = new Oid("1.2.840.10045.3.1.7");
}
