using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.X509Crypto
{
    public static class FileExtensions
    {
        public const string X509Alias = @".xca";
        public const string Csv = @".csv";
        public const string Json = @".json";
        public const string Ciphertext = @".ctx";
        public const string Plaintext = @".ptx";
        public const string Txt = @".txt";
        public const string Pfx = @".pfx";
        public const string Md = @".md";
    }

    internal static class Constants
    {
        internal const bool ProbeMode = true;
        internal const bool LeaveStreamOpen = true;
        internal const string DateFormat = @"dd-MMM-yyyy";
        internal const string Dashes = @"----------";
        internal const string IISGroup = @"IIS_IUSRS";
        internal const string MachineKeyPath = @"Microsoft\Crypto\RSA\MachineKeys";
        internal const string Group = @"Group";
        internal const string AppDirectory = @"X509Crypto";
        internal const string UserDirectoryPlaceholder = @"[USER]";
        internal const string BeginBase64Certificate = @"-----BEGIN CERTIFICATE-----";
        internal const string EndBase64Certificate = @"-----END CERTIFICATE-----";
        internal const string NoAliasAssigned = @"None assigned";
        internal const string Affirm = @"YES";
        internal const int MinimumPasswordLength = 8;
    }

    internal static class CryptoConstants
    {
        internal const int AESBlockSize = 128;
        internal const int AESKeySize = AESBlockSize * 2;

        internal const int AESBytes = 4;
        internal const int AESReadCount = AESBytes - 1;
        internal const int AESWords = AESBytes * 2;
    }

    internal static class CSVHeader
    {
        internal const string WithSecrets = @"Index,Artifact Name,Artifact Value";
        internal const string WithoutSecrets = @"Index,Artifact Name";
    }

    internal static class Padding
    {
        internal const int Thumbprint = 40;
        internal const int Expires = 12;
        internal const int Assigned_Alias = 15;
        internal const int Alias = 15;
    }

    internal static class ListCertFormat
    {
        private static readonly string Thumbprint = nameof(Thumbprint).LeftAlign(Padding.Thumbprint);
        private static readonly string Assigned_Alias = nameof(Assigned_Alias).LeftAlign(Padding.Assigned_Alias);
        private static readonly string Expires = nameof(Expires).LeftAlign(Padding.Expires);
        internal static readonly string HeaderRow = $"{Thumbprint}   {Assigned_Alias}   {Expires}\r\n{Thumbprint.Dashes().LeftAlign(Padding.Thumbprint)}   {Assigned_Alias.Dashes().LeftAlign(Padding.Assigned_Alias)}   {Expires.Dashes().LeftAlign(Padding.Expires)}";
    }

    internal static class ListAliasFormat
    {
        private static readonly string Alias = @"Alias Name".LeftAlign(Padding.Alias);
        private static readonly string Thumbprint = nameof(Thumbprint).LeftAlign(Padding.Thumbprint);
        private static readonly string Expires = nameof(Expires).LeftAlign(Padding.Expires);
        internal static readonly string HeaderRow = $"{Alias}   {Thumbprint}   {Expires}\r\n{Alias.Dashes().LeftAlign(Padding.Alias)}   {Thumbprint.Dashes().LeftAlign(Padding.Thumbprint)}   {Expires.Dashes().LeftAlign(Padding.Expires)}";
    }

    internal static class X509ContextName
    {
        internal const string User = @"user";
        internal const string CurrentUser = @"currentuser";

        internal const string System = @"system";
        internal const string LocalSystem = @"localsystem";
    }

    internal static class AllowSecretOverwrite
    {
        internal const bool Yes = true;
        internal const bool No = false;
    }

    internal static class RegexPattern
    {
        internal const string OnlyMatchHexidecimal = "^[0-9A-Fa-f]+$";
    }
}
