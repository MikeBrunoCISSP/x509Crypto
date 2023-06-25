namespace Org.X509Crypto;

/// <summary>
/// X509ContextType
/// </summary>
public enum X509CryptoContextType {
    /// <summary>
    /// User read-only.
    /// </summary>
    UserReadOnly = 0,
    /// <summary>
    /// User full-control
    /// </summary>
    UserFull = 1,
    /// <summary>
    /// System read-only
    /// </summary>
    SystemReadOnly = 2,
    /// <summary>
    /// System full-control
    /// </summary>
    SystemFull = 3
}