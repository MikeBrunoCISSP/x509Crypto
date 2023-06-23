namespace Org.X509Crypto;

/// <summary>
/// Specifies a format in which to output the decrypted secrets from a <see cref="X509Alias"/>
/// </summary>
public enum SecretDumpFormat {
    /// <summary>
    /// Text
    /// </summary>
    Text = 0,
    /// <summary>
    /// Comma-delimited
    /// </summary>
    CommaSeparated = 1,
    /// <summary>
    /// Dictionary
    /// </summary>
    Dictionary = 2
}