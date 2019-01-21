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

    class Config
    {
        #region Constants

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
        internal const string DESC_OUT_FILE = @"(Optional) THe fully-qualified file path where you would like the output written";
        internal const string PATH = @"path";
        internal const string PASSWORD = @"password";
        internal const string CERT_THUMBPRINT = @"cert thumbprint";
        internal const string CERT_STORE = @"cert store";

        //Main Mode Names
        internal const string MAIN_MODE_ENCRYPT = @"encrypt";
        internal const string MAIN_MODE_DECRYPT = @"decrypt";
        internal const string MAIN_MODE_REENCRYPT = @"reencrypt";
        internal const string MAIN_MODE_IMPORT = @"import";
        internal const string MAIN_MODE_EXPORT = @"export";
        internal const string MAIN_MODE_MAKECERT = @"cert";
        internal const string MAIN_MODE_LIST = @"list";
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

        internal const string PLACEHOLDER_CRYPTO_PARAM_WIPE = @"[WIPE_PARAM]";
        internal const string PLACEHOLDER_CRYPTO_USAGE_WIPE = @"[WIPE_USAGE]";
        private static readonly string CRYPTO_WIPE_USAGE = string.Format(@"(Optional) remove residual {0} from disk", CRYPTO_PLAINTEXT);

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
        internal static readonly string CLIPBOARD_USAGE = string.Format("{0}Use \"{1}\" to write the output to the system clipboard", USAGE_INDENT, CRYPTO_CLIPBOARD);

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
        internal const string OLD_CERT = @"old ";
        internal const string NEW_CERT = @"new ";
        internal const string CURRENT_CERT = "";

        internal static readonly string STORE_LOCATION_USAGE = string.Format("(Optional) the certificate store name where the {0}encryption certificate is located.", PLACEHOLDER_CERT_OLD_NEW_CURRENT) +
                                                               string.Format("{0}The following values are valid for this setting:", USAGE_INDENT) +
                                                               string.Format("{0}* {1}", USAGE_INDENT, CertStore.CurrentUser.Name) +
                                                               string.Format("{0}* {1}", USAGE_INDENT, CertStore.LocalMachine.Name) +
                                                               string.Format("{0} Default is {1}0", USAGE_INDENT, CertStore.CurrentUser.Name);
        private static readonly string DESC_STORE_LOCATION = STORE_LOCATION_USAGE.Replace(PLACEHOLDER_CERT_OLD_NEW_CURRENT, string.Empty);

        #endregion

        #region Main Usage

        private static string SYNTAX_MAIN = string.Format("{0}{1} [COMMAND]", USAGE_HEADING, ASSEMBLY_NAME);
        private static Dictionary<string, string> MainModes = new Dictionary<string, string>
        {
            {MAIN_MODE_ENCRYPT, @"Encrypts the specified plaintext expression or file" },
            {MAIN_MODE_DECRYPT, @"Decrypts the specified ciphertext expression or file" },
            {MAIN_MODE_REENCRYPT, @"Encrypts the specified ciphertext expression or file using a different certificate" },
            {MAIN_MODE_IMPORT, @"Imports a certificate and key pair from the specified PKCS#12 (.pfx) file" },
            {MAIN_MODE_EXPORT, @"Exports a specified key pair and/or certificate from a specified certificate store" },
            {MAIN_MODE_LIST, @"Lists the available encryption certificates in the specified certificate store" }
        };
        private static readonly string USAGE_MAIN = GetUsage(SYNTAX_MAIN, MainModes, IS_COMMANDS);

        #endregion

        #region Crypto Main Usage

        private static string crypto_description_template = PLACEHOLDER_CRYPTO_ACTION + " the specified " + PLACEHOLDER_CRYPTO_PLAINTEXT_CIPHERTEXT + " {0}";
        private static readonly string SYNTAX_CRYPTO = string.Format("{0} [{1}|{2}]", PLACEHOLDER_CRYPTO_COMMAND, CRYPTO_MODE_TEXT, CRYPTO_MODE_FILE);
        private static Dictionary<string, string> CryptoModesMain = new Dictionary<string, string>
        {
            {CRYPTO_MODE_TEXT, string.Format(crypto_description_template, CRYPTO_EXPRESSION) },
            {CRYPTO_MODE_FILE, string.Format(crypto_description_template, CRYPTO_FILE) }
        };
        private static readonly string USAGE_CRYPTO_ENCRYPT = GetUsage(SYNTAX_CRYPTO.Replace(PLACEHOLDER_CRYPTO_COMMAND, MAIN_MODE_ENCRYPT), CryptoModesMain, IS_COMMANDS).Replace(PLACEHOLDER_CRYPTO_ACTION, CRYPTO_ACTION_ENCRYPT)
                                                                                                                                                                                                        .Replace(PLACEHOLDER_CRYPTO_PLAINTEXT_CIPHERTEXT, CRYPTO_PLAINTEXT);

        private static readonly string USAGE_CRYPTO_DECRYPT = GetUsage(SYNTAX_CRYPTO.Replace(PLACEHOLDER_CRYPTO_COMMAND, MAIN_MODE_DECRYPT), CryptoModesMain, IS_COMMANDS).Replace(PLACEHOLDER_CRYPTO_ACTION, CRYPTO_ACTION_DECRYPT)
                                                                                                                                                                                                .Replace(PLACEHOLDER_CRYPTO_PLAINTEXT_CIPHERTEXT, CRYPTO_CIPHERTEXT);

        private static readonly string USAGE_CRYPTO_REENCRYPT = GetUsage(SYNTAX_CRYPTO.Replace(PLACEHOLDER_CRYPTO_COMMAND, MAIN_MODE_REENCRYPT), CryptoModesMain, IS_COMMANDS).Replace(PLACEHOLDER_CRYPTO_ACTION, CRYPTO_ACTION_REENCRYPT)
                                                                                                                                                                                                .Replace(PLACEHOLDER_CRYPTO_PLAINTEXT_CIPHERTEXT, CRYPTO_CIPHERTEXT);

        #endregion

        #region Crypto Text Usage Messages

        private static readonly string SYNTAX_CRYPTO_TEXT = string.Format("{0} {1} {2} [cert thumbprint] {3} [{4}] {{ {5} [cert store] {6} [path] }}",
                                                                          PLACEHOLDER_CRYPTO_COMMAND, CRYPTO_MODE_TEXT, PARAM_THUMB,
                                                                          PARAM_IN, PLACEHOLDER_CRYPTO_PLAINTEXT_CIPHERTEXT,
                                                                          PARAM_CERTSTORE, PARAM_OUT);
        private static Dictionary<string, string> CryptoModesText = new Dictionary<string, string>
        {
            {PARAM_THUMB, @"The thumbprint of the encryption certificate" },
            {PARAM_IN, string.Format("the {0} {1} you wish to {2}", PLACEHOLDER_CRYPTO_PLAINTEXT_CIPHERTEXT, PLACEHOLDER_CRYPTO_EXPRESSION_FILE, PLACEHOLDER_CRYPTO_ACTION) },
            {PARAM_CERTSTORE, STORE_LOCATION_USAGE.Replace(PLACEHOLDER_CERT_OLD_NEW_CURRENT, CURRENT_CERT) },
            {PARAM_OUT, DESC_OUT_FILE + CLIPBOARD_USAGE}
        };
        private static readonly string USAGE_CRYPTO_ENCRYPT_TEXT = GetUsage(SYNTAX_CRYPTO_TEXT.Replace(PLACEHOLDER_CRYPTO_COMMAND, MAIN_MODE_ENCRYPT), CryptoModesText, IS_PARAMETERS).Replace(PLACEHOLDER_CRYPTO_PLAINTEXT_CIPHERTEXT, CRYPTO_PLAINTEXT)
                                                                                                                                                                                      .Replace(PLACEHOLDER_CRYPTO_EXPRESSION_FILE, CRYPTO_EXPRESSION)
                                                                                                                                                                                      .Replace(PLACEHOLDER_CRYPTO_ACTION, CRYPTO_ACTION_ENCRYPT);

        private static readonly string USAGE_CRYPTO_DECRYPT_TEXT = GetUsage(SYNTAX_CRYPTO_TEXT.Replace(PLACEHOLDER_CRYPTO_COMMAND, MAIN_MODE_DECRYPT), CryptoModesText, IS_PARAMETERS).Replace(PLACEHOLDER_CRYPTO_PLAINTEXT_CIPHERTEXT, CRYPTO_CIPHERTEXT)
                                                                                                                                                                                      .Replace(PLACEHOLDER_CRYPTO_EXPRESSION_FILE, CRYPTO_EXPRESSION)
                                                                                                                                                                                      .Replace(PLACEHOLDER_CRYPTO_ACTION, CRYPTO_ACTION_DECRYPT);

        #endregion

        #region Crypto File Usage Messages

        private static readonly string SYNTAX_CRYPTO_FILE = string.Format("{0} {1} {2} [cert thumbprint] {3} [{4}] {{ {5} [cert store] {6} [path] {7}}}",
                                                                          PLACEHOLDER_CRYPTO_COMMAND, CRYPTO_MODE_FILE, PARAM_THUMB,
                                                                          PARAM_IN, PLACEHOLDER_CRYPTO_PLAINTEXT_CIPHERTEXT,
                                                                          PARAM_CERTSTORE, PARAM_OUT, CRYPTO_PARAM_WIPE[0]);
        private static Dictionary<string, string> cryptoModesFile = new Dictionary<string, string>
        {
            {PARAM_THUMB, @"The thumbprint of the encryption certificate" },
            {PARAM_IN, string.Format("the {0} {1} you wish to {2}", PLACEHOLDER_CRYPTO_PLAINTEXT_CIPHERTEXT, PLACEHOLDER_CRYPTO_EXPRESSION_FILE, PLACEHOLDER_CRYPTO_ACTION) },
            {PARAM_CERTSTORE, STORE_LOCATION_USAGE.Replace(PLACEHOLDER_CERT_OLD_NEW_CURRENT, CURRENT_CERT) },
            {PARAM_OUT, DESC_OUT_FILE },
            {PLACEHOLDER_CRYPTO_PARAM_WIPE, PLACEHOLDER_CRYPTO_USAGE_WIPE }
        };
        private static readonly string USAGE_CRYPTO_ENCRYPT_FILE = GetUsage(SYNTAX_CRYPTO_FILE.Replace(PLACEHOLDER_CRYPTO_COMMAND, MAIN_MODE_ENCRYPT), cryptoModesFile, IS_PARAMETERS).Replace(PLACEHOLDER_CRYPTO_PLAINTEXT_CIPHERTEXT, CRYPTO_PLAINTEXT)
                                                                                                                                                                                      .Replace(PLACEHOLDER_CRYPTO_EXPRESSION_FILE, CRYPTO_FILE)
                                                                                                                                                                                      .Replace(PLACEHOLDER_CRYPTO_ACTION, CRYPTO_ACTION_ENCRYPT)
                                                                                                                                                                                      .Replace(PLACEHOLDER_CRYPTO_PARAM_WIPE, CRYPTO_PARAM_WIPE[0])
                                                                                                                                                                                      .Replace(PLACEHOLDER_CRYPTO_USAGE_WIPE, CRYPTO_WIPE_USAGE);
        private static readonly string USAGE_CRYPTO_DECRYPT_FILE = GetUsage(SYNTAX_CRYPTO_FILE.Replace(PLACEHOLDER_CRYPTO_COMMAND, MAIN_MODE_ENCRYPT), cryptoModesFile, IS_PARAMETERS).Replace(PLACEHOLDER_CRYPTO_PLAINTEXT_CIPHERTEXT, CRYPTO_CIPHERTEXT)
                                                                                                                                                                                      .Replace(PLACEHOLDER_CRYPTO_EXPRESSION_FILE, CRYPTO_FILE)
                                                                                                                                                                                      .Replace(PLACEHOLDER_CRYPTO_ACTION, CRYPTO_ACTION_DECRYPT)
                                                                                                                                                                                      .Replace(PLACEHOLDER_CRYPTO_PARAM_WIPE, string.Empty)
                                                                                                                                                                                      .Replace(PLACEHOLDER_CRYPTO_USAGE_WIPE, string.Empty);

        #endregion

        #region Re-Encrypt Usages

        const string DESC_OLD_THUMB = @"The thumbprint of the current certificate used for encryption";
        const string DESC_NEW_THUMB = @"The thumbprint of the replacement certificate";
        private static readonly string DESC_OLD_CERTSTORE = STORE_LOCATION_USAGE.Replace(PLACEHOLDER_CERT_OLD_NEW_CURRENT, OLD_CERT);
        private static readonly string DESC_NEW_CERTSTORE = STORE_LOCATION_USAGE.Replace(PLACEHOLDER_CERT_OLD_NEW_CURRENT, NEW_CERT);

        private static readonly string SYNTAX_RECRYPTO_MAIN = string.Format("{0} {1} {2} {3} {4} [old cert thumbprint] {5} [new cert thumbprint] {{{6} [old cert store] {7} [new cert store] {8} [path{{0}}]}}",
                                                                    MAIN_MODE_REENCRYPT, CRYPTO_MODE_TEXT, PARAM_IN, CRYPTO_CIPHERTEXT, CRYPTO_PARAM_OLDTHUMB, CRYPTO_PARAM_NEWTHUMB, CRYPTO_PARAM_OLDCERTSTORE, CRYPTO_PARAM_NEWCERTSTORE, PARAM_OUT);

        //RE-CRYPTO TEXT USAGE
        private static readonly string SYNTAX_RECRYPTO_TEXT = string.Format(SYNTAX_RECRYPTO_MAIN, string.Format(@"|{0}", CRYPTO_CLIPBOARD));
        private static Dictionary<string, string> reCryptoModeText = new Dictionary<string, string>
        {
            {CRYPTO_PARAM_OLDTHUMB, DESC_OLD_THUMB },
            {CRYPTO_PARAM_NEWTHUMB, DESC_NEW_THUMB },
            {PARAM_IN, @"the ciphertext expression you wish to re-encrypt" },
            {CRYPTO_PARAM_OLDCERTSTORE, DESC_OLD_CERTSTORE },
            {CRYPTO_PARAM_NEWCERTSTORE, DESC_NEW_CERTSTORE },
            {PARAM_OUT, DESC_OUT_FILE + CLIPBOARD_USAGE}
        };
        private static readonly string USAGE_CRYPTO_REENCRYPT_TEXT = GetUsage(SYNTAX_RECRYPTO_TEXT, reCryptoModeText, IS_PARAMETERS);

        //RE-CRYPTO FILE USAGE
        private static readonly string SYNTAX_RECRYPTO_FILE = string.Format(SYNTAX_RECRYPTO_MAIN, string.Empty);
        private static Dictionary<string, string> reCryptoModeFile = new Dictionary<string, string>
        {
            {CRYPTO_PARAM_OLDTHUMB, DESC_OLD_THUMB },
            {CRYPTO_PARAM_NEWTHUMB, DESC_NEW_THUMB },
            {PARAM_IN, @"the fully-qualified path to the ciphertext file you wish to re-encrypt" },
            {CRYPTO_PARAM_OLDCERTSTORE, DESC_OLD_CERTSTORE },
            {CRYPTO_PARAM_NEWCERTSTORE, DESC_NEW_CERTSTORE }
        };
        private static readonly string USAGE_CRYPTO_REENCRYPT_FILE = GetUsage(SYNTAX_RECRYPTO_FILE, reCryptoModeFile, IS_PARAMETERS);

        #endregion

        #region Cert Usages

        //LIST USAGE
        private static readonly string SYNTAX_CERT_LIST = string.Format(@"{0} {{{1} [certificate store]", MAIN_MODE_LIST, PARAM_CERTSTORE);
        private static Dictionary<string, string> certModeList = new Dictionary<string, string>
        {
            {PARAM_CERTSTORE, DESC_STORE_LOCATION },
            {CERT_PARAM_EXPIRED, @"(Optional) include expired certificates in output" }
        };
        private static readonly string USAGE_CERT_LIST = GetUsage(SYNTAX_CERT_LIST, certModeList, IS_PARAMETERS);

        //IMPORT USAGE
        private static readonly string SYNTAX_CERT_IMPORT = string.Format(@"{0} {1} [{2}] {3} [{4}] {{{5} [{6}]")

        #endregion

        #region Static Methods

        private static string GetUsage(string syntax, Dictionary<string,string> items, bool isCommands)
        {
            int length = GetPadding(items);

            string usage = string.Format("{0}{1} {2}\r\n  {3}:",
                                         USAGE_HEADING, ASSEMBLY_NAME, syntax,
                                         isCommands ? @"Available Commands" : @"Accepted Parameters");

            foreach (KeyValuePair<string, string> command in items)
            {
                if (!string.IsNullOrEmpty(command.Key) & !string.IsNullOrEmpty(command.Value))
                    usage += (command.Key == string.Empty) ? USAGE_INDENT + command.Value : string.Format("\r\n   {0}: {1}", command.Key.PadRight(length), command.Value);
            }

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
