using System.Collections.Generic;
using Org.X509Crypto;

namespace X509CryptoExe
{
    internal class ValidSelection
    {
        internal string Name { get; private set; }
        internal string Description { get; private set; }

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

        internal static List<ValidSelection> Contexts = new List<ValidSelection>() { UserContext, SystemContext };
        internal static List<ValidSelection> ListTypes = new List<ValidSelection>() { ListAliases, ListCerts };
    }
}
