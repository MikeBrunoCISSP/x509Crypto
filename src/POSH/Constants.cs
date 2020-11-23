﻿using System;
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
    }

    static class PrivilegeLevel
    {
        internal const string Read = nameof(Read);
        internal const string Change = nameof(Change);
    }
}
