namespace Org.X509Crypto.Dto;
public class EncryptedSecretDto {
    public byte[] InitializationVector { get; set; }
    public byte[] EncryptedKey { get; set; }
    public byte[] Data { get; set; }
}
