using System.Runtime.Serialization;

namespace Org.X509Crypto.Dto;
[DataContract]
public class EncryptedFileDto {
    [DataMember]
    public string OriginalFileName { get; set; }
    [DataMember]
    public string OriginalExtension { get; set; }
    [DataMember]
    public EncryptedSecretDto EncryptedContents { get; set; }
}
