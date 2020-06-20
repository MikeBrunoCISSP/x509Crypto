using System.Collections.Generic;
using Org.X509Crypto;

namespace X509CryptoExe
{
    internal class ValidSelection
    {
        internal string Name { get; private set; }
        internal string Description { get; private set; }
        internal int IntValue { get; private set; } = 0;

        internal static ValidSelection UserContext = new ValidSelection()
        {
            Name = X509Context.UserReadOnly.Name,
            Description = @"The context of the current (or currently impersonated) user"
        };

        internal static ValidSelection SystemContext = new ValidSelection()
        {
            Name = X509Context.SystemReadOnly.Name,
            Description = @"The context of the local system"
        };

        internal static ValidSelection ListAliases = new ValidSelection()
        {
            Name = ListType.Aliases,
            Description = @"Lists available X509Aliases in the selected X509Context"
        };

        internal static ValidSelection ListCerts = new ValidSelection()
        {
            Name = ListType.Certs,
            Description = @"Lists available encryption certificates in the selected X509Context"
        };

        internal static ValidSelection SmallKey = new ValidSelection()
        {
            Name = KeySize.Small,
            Description = @"1024-bit public key - High performance, but low security",
            IntValue = 1024
        };

        internal static ValidSelection MediumKey = new ValidSelection()
        {
            Name = KeySize.Medium,
            Description = @"2048-bit public key - Medium performance, medium security",
            IntValue = 2048
        };

        internal static ValidSelection LargeKey = new ValidSelection()
        {
            Name = KeySize.Large,
            Description = @"4096-bit public key - Slower performance, high security",
            IntValue = 4096
        };

        internal static List<ValidSelection> Contexts = new List<ValidSelection>() { UserContext, SystemContext };
        internal static List<ValidSelection> ListTypes = new List<ValidSelection>() { ListAliases, ListCerts };
        internal static List<ValidSelection> KeySizes = new List<ValidSelection>() { SmallKey, MediumKey, LargeKey };
    }
}
