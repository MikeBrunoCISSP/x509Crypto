using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace X509CryptoPOSH
{
    static class Constants
    {
        internal const string NoAliasAssigned = @"Non Assigned";
        internal const bool DoNotIncludeIfCertNotFound = false;
        internal const string Affirm = @"YES";
        internal const int WipeRepititions = 5;
        internal const int MinimumPasswordLength = 8;
    }

    static class PoshSyntax
    {
        internal const string True = "$True";
    }

    static class PrivilegeLevel
    {
        internal const string Read = nameof(Read);
        internal const string Change = nameof(Change);
    }
}
