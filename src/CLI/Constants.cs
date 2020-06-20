using Org.X509Crypto;
using System.Reflection;
using System.Text.RegularExpressions;

namespace X509CryptoExe
{
    internal static class Constants
    {
        internal static string AssemblyTitle = Assembly.GetExecutingAssembly().GetName().Name;
        internal static string AssemblyFile = $"{AssemblyTitle}.exe";
        internal static string CLIPrompt = $"\r\n{AssemblyTitle}>";
        internal const int MaxDescriptionLength = 65;
        internal const string Affirm = @"YES";
        internal const string CommandLineRegexPattern = @"[\""].+?[\""]|[^ ]+";
        internal const int LOGON32_PROVIDER_DEFAULT = 0;
        internal const bool ProbeMode = true;
        internal const int BaseIndent = 3;
        internal const int DefaultKeyLength = 2048;
        internal const int DefaultYearsValid = 10;
        internal const bool ConfirmPasswordsMatch = true;
    }

    internal static class UsageIndent
    {
        internal const int Parameter = 0;
        internal const int Mode = 1;
        internal const int Verb = 0;
    }

    internal static class RegexPattern
    {
        internal static Regex CommandLine = new Regex(@"[\""].+?[\""]|[^ ]+");
        internal static Regex DigitsOnly = new Regex(@"^\d+$");
    }

    internal static class LoginType
    {
        internal const int LOGON32_LOGON_INTERACTIVE = 2;
        internal const int LOGON32_LOGON_NETWORK = 3;
        internal const int LOGON32_LOGON_BATCH = 4;
        internal const int LOGON32_LOGON_SERVICE = 5;
        internal const int LOGON32_LOGON_UNLOCK = 7;
        internal const int LOGON32_LOGON_NETWORK_CLEARTEXT = 8;
        internal const int LOGON32_LOGON_CREDENTIALS = 9;
    }

    internal static class AllowExistingAlias
    {
        internal const bool Yes = false;
        internal const bool No = true;
    }

    internal static class AllowFileOverwrite
    {
        internal const bool Yes = true;
        internal const bool No = false;
    }

    internal static class AllowSecretOverwrite
    {
        internal const bool Yes = true;
        internal const bool No = false;
    }

    internal static class FileExtensions
    {
        internal const string ExportAlias = @".json";
        internal const string Ciphertext = @".ctx";
        internal const string Plaintext = @".ptx";
        internal const string Csv = @".csv";
        internal const string Txt = @".txt";
        internal const string Pfx = @".pfx";
    }

    internal static class CommandName
    {
        internal const string Encrypt = nameof(Encrypt);
        internal const string Decrypt = nameof(Decrypt);
        internal const string ReEncrypt = nameof(ReEncrypt);
        internal const string AddAlias = nameof(AddAlias);
        internal const string UpdateAlias = nameof(UpdateAlias);
        internal const string RemoveAlias = nameof(RemoveAlias);
        internal const string ImportAlias = nameof(ImportAlias);
        internal const string ExportAlias = nameof(ExportAlias);
        internal const string DumpAlias = nameof(DumpAlias);
        internal const string InstallCert = nameof(InstallCert);
        internal const string MakeCert = nameof(MakeCert);
        internal const string ExportCert = nameof(ExportCert);
        internal const string List = nameof(List);
        internal const string Impersonate = nameof(Impersonate);
        internal const string Help = nameof(Help);
        internal const string CLI = nameof(CLI);
        internal const string Exit = nameof(Exit);
    }

    internal static class CipherMode
    {
        internal const string Text = @"text";
        internal const string File = @"file";
    }

    internal static class ParameterName
    {
        internal const string Thumbprint = @"thumb";
        internal const string NewThumbprint = @"newthumb";

        internal const string Alias = @"alias";
        internal const string OldAlias = @"oldalias";
        internal const string NewAlias = @"newalias";

        internal const string Context = @"context";
        internal const string OldContext = @"oldcontext";
        internal const string NewContext = @"newcontext";

        internal const string Secret = @"secret";
        internal const string Name = @"name";
        internal const string Wipe = @"wipe";
        internal const string In = @"in";
        internal const string Out = @"out";
        internal const string Clipboard = @"clipboard";
        internal const string Screen = @"screen";
        internal const string ListType = @"type";
        internal const string OverwriteExisting = @"overwrite";
        internal const string ImpUser = @"user";
        internal const string EndImp = @"end";
        internal const string Reveal = @"reveal";

        internal const string KeySize = @"keysize";
        internal const string YearsValid = @"years";
    }

    internal static class ListType
    {
        internal const string Certs = @"cert";
        internal const string Aliases = @"alias";
    }

    internal static class KeySize
    {
        internal const string Small = @"small";
        internal const string Medium = @"medium";
        internal const string Large = @"large";
    }

    internal static class KeyLength
    {
        internal const int Small = 1024;
        internal const int Medium = 2048;
        internal const int Large = 4096;
    }

    internal static class Samples
    {
        internal const string Mode = @" [MODE]";
        internal const string PathOnly = @"PATH";
        internal static string PathOr = $"{PathOnly} |{ParameterName.Clipboard} | {ParameterName.Screen}";
        internal const string Thumbprint = @"cert thumbprint";
        internal const string Name = @"NAME";
        internal const string Secret = @"IDENTIFIER";
        internal static string Context = $"{X509Context.UserReadOnly.Name} | {X509Context.SystemReadOnly.Name}";
        internal const string YesOrNo = @"Y | N";
        internal const string TimesToWrite = @"Times to write";
        internal const string User = @"USER ACCOUNT";
        internal const string Plaintext = @"text";
        internal const string Ciphertext = @"ciphertext";
        internal const string KeySize = @"size";
        internal const string Years = @"years";
    }

    internal static class UsageExpression
    {
        internal const string AdminRights = @"Local administrative rights may be required";
        internal const string AvailableCommands = @"Available Commands:";
        internal const string AvailableModes = @"Available Modes:";
        internal const string Prefix = "Usage:\r\n";
        internal const string ValidEntries = @"Valid Entries: ";
        internal const string ParameterOptional = @"(Optional) ";
        internal const string NotEnoughArguments = @"Not enough arguments.";
        internal const string UnrecognizedExpression = @"Unrecognized expression: {0}";
        internal const string RequiredParameters = "\r\nRequired Parameters:";
        internal const string OptionalParameters = "\r\n\r\nOptional Parameters:";
        internal const string DefaultSelection = @"Default selection is: ";

        internal static string Clipboard = $"Use \"{ParameterName.Clipboard}\" to write the output to the system clipboard instead";
    }
}
