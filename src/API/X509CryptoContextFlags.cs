using System;

namespace Org.X509Crypto;

/// <summary>
/// X509ContextType
/// </summary>
[Flags]
public enum X509CryptoContextFlags {
    /// <summary>
    /// None.
    /// </summary>
    None         = 0,
    /// <summary>
    /// User context.
    /// </summary>
    User         = 0x1,
    /// <summary>
    /// System context
    /// </summary>
    System       = 0x2,
    /// <summary>
    /// Context open with full control
    /// </summary>
    WriteAccess  = 0x100
}