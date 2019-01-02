using System;
using System.IO;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using x509Crypto;

namespace x509CryptoExe
{
    public enum Mode
    {
        EncryptText=0,
        DecryptText = 1,
        EncryptFile=2,
        DecryptFile = 3,
        ReEncryptText = 4,
        ReEncryptFile = 5,
        CreateCert = 6,
        ImportCert = 7,
        ExportPFX = 8,
        ExportCert = 9,
        List = 10,
        Help = 11,
        Unknown = -1
    }

    public enum ContentType
    {
        Text = 0,
        File = 1,
        Unknown = -1
    }
   
    internal static class Constants
    {
        //Assembly Name
        internal static string ASSEMBLY_NAME = Assembly.GetExecutingAssembly().GetName().Name + @".exe";

        //Usage Types
        internal const bool IS_COMMANDS = true;
        internal const bool IS_PARAMETERS = false;

        //Universal Parameters
        internal const string PARAM_THUMB = @"-thumb";
        internal const string PARAM_CERTSTORE = @"-store";
        internal const string PARAM_IN = @"-in";
        internal const string PARAM_OUT = @"-out";

        //Main Mode Names
        internal const string MAIN_MODE_ENCRYPT   = @"encrypt";
        internal const string MAIN_MODE_DECRYPT   = @"decrypt";
        internal const string MAIN_MODE_REENCRYPT = @"reencrypt";
        internal const string MAIN_MODE_IMPORT    = @"import";
        internal const string MAIN_MODE_EXPORT    = @"export";
        internal const string MAIN_MODE_MAKECERT  = @"cert";
        internal const string MAIN_MODE_LIST      = @"list";
        internal static readonly string[] MAIN_MODE_HELP = { @"help", @"-help", @"--help", @"?", @"-?", @"--?", @"h", @"-h", @"--h" };

        //Crypto Actions
        internal const string CRYPTO_ACTION_ENCRYPT = @"encrypt";
        internal const string CRYPTO_ACTION_DECRYPT = @"decrypt";
        internal const string CRYPTO_ACTION_REENCRYPT = @"reencrypt";

        //Crypto Placeholders
        internal const string PLACEHOLDER_CRYPTO_COMMAND = @"[CRYPTO_COMMAND]";
        internal const string PLACEHOLDER_CRYPTO_ACTION = @"[CRYPTO_ACTION]";

        internal const string PLACEHOLDER_CRYPTO_PLAINTEXT_CIPHERTEXT = @"[ITEM]";
        internal const string CRYPTO_PLAINTEXT = @"plaintext";
        internal const string CRYPTO_CIPHERTEXT = @"ciphertext";

        internal const string PLACEHOLDER_CRYPTO_EXPRESSION_FILE = @"[TYPE]";
        internal const string CRYPTO_EXPRESSION = @"expression";
        internal const string CRYPTO_FILE = @"file";

        //Crypto Modes
        internal const string CRYPTO_MODE_TEXT = @"-text";
        internal const string CRYPTO_MODE_FILE = @"-file";

        //Crypto Parameters
        internal const string PLACEHOLDER_CRYPTO_INPUT_TYPE_PARAM = @"[INPUT_TYPE]";
        internal const string CRYPTO_PARAM_OLDTHUMB = @"-oldthumb";
        internal const string CRYPTO_PARAM_NEWTHUMB = @"-newthumb";
        internal const string CRYPTO_PARAM_OLDCERTSTORE = @"-oldstore";
        internal const string CRYPTO_PARAM_NEWCERTSTORE = @"-newstore";
        internal const string CRYPTO_CLIPBOARD = @"clipboard";
        internal static readonly string[] CRYPTO_PARAM_WIPE = { @"-w", @"-wipe" };

        //Cert Parameters
        internal const string CERT_PARAM_EXPIRED = @"-expired";
        internal static readonly string[] CERT_PARAM_VERBOSE = { @"-verbose", @"-debug" };
        internal static readonly string[] CERT_PARAM_WORKING_DIR = { @"-workingdir", @"-dir", @"-working" };
        internal static readonly string[] CERT_PARAM_PASSWORD = { @"-pass", @"-password", @"-pw" };

        //Usage Standards
        internal const string USAGE_HEADING = @"Usage: ";
        internal const string USAGE_INDENT = "\r\n             ";

        //Certificate Stores
        internal const string PLACEHOLDER_CERT_OLD_NEW_CURRENT = @"[OLD/NEW]";
        internal const string OLD_CERT = @"old";
        internal const string NEW_CERT = @"new";
        internal const string CURRENT_CERT = "";

        internal static readonly string STORE_LOCATION_USAGE = string.Format("(Optional) the certificate store name where the {0} encryption certificate is located.", PLACEHOLDER_CERT_OLD_NEW_CURRENT) +
                                                               string.Format("{0}The following values are valid for this setting:", USAGE_INDENT) +
                                                               string.Format("{0}* {1}", USAGE_INDENT, CertStore.CurrentUser.Name) +
                                                               string.Format("{0}* {1}", USAGE_INDENT, CertStore.LocalMachine.Name) +
                                                               string.Format("{0} Default is {1}0", USAGE_INDENT, CertStore.CurrentUser.Name);
    }

    class Config
    {
        #region Main Usage

        private static string SYNTAX_MAIN = string.Format("{0}{1} [COMMAND]", Constants.USAGE_HEADING, Constants.ASSEMBLY_NAME);
        private static Dictionary<string, string> MainModes = new Dictionary<string, string>
        {
            {Constants.MAIN_MODE_ENCRYPT, @"Encrypts the specified plaintext expression or file" },
            {Constants.MAIN_MODE_DECRYPT, @"Decrypts the specified ciphertext expression or file" },
            {Constants.MAIN_MODE_REENCRYPT, @"Encrypts the specified ciphertext expression or file using a different certificate" },
            {Constants.MAIN_MODE_IMPORT, @"Imports a certificate and key pair from the specified PKCS#12 (.pfx) file" },
            {Constants.MAIN_MODE_EXPORT, @"Exports a specified key pair and/or certificate from a specified certificate store" },
            {Constants.MAIN_MODE_LIST, @"Lists the available encryption certificates in the specified certificate store" }
        };
        private static readonly string USAGE_MAIN = GetUsage(SYNTAX_MAIN, MainModes, Constants.IS_COMMANDS);

        #endregion

        #region Crypto Usages

        private static string crypto_description_template = Constants.PLACEHOLDER_CRYPTO_ACTION + " the specified " + Constants.PLACEHOLDER_CRYPTO_PLAINTEXT_CIPHERTEXT + " {0}";
        private static readonly string SYNTAX_CRYPTO = string.Format("{0} [{1}|{2}]", Constants.PLACEHOLDER_CRYPTO_COMMAND, Constants.CRYPTO_MODE_TEXT, Constants.CRYPTO_MODE_FILE);
        private static Dictionary<string, string> CryptoModesMain = new Dictionary<string, string>
        {
            {Constants.CRYPTO_MODE_TEXT, string.Format(crypto_description_template, Constants.CRYPTO_EXPRESSION) },
            {Constants.CRYPTO_MODE_FILE, string.Format(crypto_description_template, Constants.CRYPTO_FILE) }
        };
        private static readonly string USAGE_CRYPTO_ENCRYPT = GetUsage(SYNTAX_CRYPTO.Replace(Constants.PLACEHOLDER_CRYPTO_COMMAND, Constants.MAIN_MODE_ENCRYPT), CryptoModesMain, Constants.IS_COMMANDS).Replace(Constants.PLACEHOLDER_CRYPTO_ACTION, Constants.CRYPTO_ACTION_ENCRYPT)
                                                                                                                                                                                                        .Replace(Constants.PLACEHOLDER_CRYPTO_PLAINTEXT_CIPHERTEXT, Constants.CRYPTO_PLAINTEXT);

        private static readonly string USAGE_CRYPTO_DECRYPT = GetUsage(SYNTAX_CRYPTO.Replace(Constants.PLACEHOLDER_CRYPTO_COMMAND, Constants.MAIN_MODE_DECRYPT), CryptoModesMain, Constants.IS_COMMANDS).Replace(Constants.PLACEHOLDER_CRYPTO_ACTION, Constants.CRYPTO_ACTION_DECRYPT)
                                                                                                                                                                                                .Replace(Constants.PLACEHOLDER_CRYPTO_PLAINTEXT_CIPHERTEXT, Constants.CRYPTO_CIPHERTEXT);

        private static readonly string USAGE_CRYPTO_REENCRYPT = GetUsage(SYNTAX_CRYPTO.Replace(Constants.PLACEHOLDER_CRYPTO_COMMAND, Constants.MAIN_MODE_REENCRYPT), CryptoModesMain, Constants.IS_COMMANDS).Replace(Constants.PLACEHOLDER_CRYPTO_ACTION, Constants.CRYPTO_ACTION_REENCRYPT)
                                                                                                                                                                                                .Replace(Constants.PLACEHOLDER_CRYPTO_PLAINTEXT_CIPHERTEXT, Constants.CRYPTO_CIPHERTEXT);

        #endregion

        #region Static Methods

        private static string GetUsage(string syntax, Dictionary<string,string> items, bool isCommands)
        {
            int length = GetPadding(items);

            string usage = string.Format("{0}{1} {2}\r\n  {3}:",
                                         Constants.USAGE_HEADING, Constants.ASSEMBLY_NAME, syntax,
                                         isCommands ? @"Available Commands" : @"Accepted Parameters");

            foreach (KeyValuePair<string, string> command in items)
                usage += (command.Key == string.Empty) ? Constants.USAGE_INDENT + command.Value : string.Format("\r\n   {0}: {1}", command.Key.PadRight(length), command.Value);

            usage += "\r\n";

            return usage;
        }

        private static int GetPadding(Dictionary<string,string> items)
        {
            int padding = 0;

            foreach(KeyValuePair<string, string> command in items)
            {
                if (command.Value != string.Empty)
                {
                    if (command.Key.Length > padding)
                        padding = command.Key.Length;
                }
            }

            return padding;
        }

        #endregion
    }

}
