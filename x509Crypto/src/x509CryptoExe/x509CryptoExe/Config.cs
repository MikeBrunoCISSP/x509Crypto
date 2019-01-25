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
using System.Security.AccessControl;

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
        internal static readonly string OLD_CERT_THUMBPRINT = string.Format("@old {0}", CERT_THUMBPRINT);
        internal static readonly string NEW_CERT_THUMBPRINT = string.Format(@"new {0}", CERT_THUMBPRINT);

        internal const string CERT_STORE = @"cert store";
        internal static readonly string OLD_CERT_STORE = string.Format("@old {0}", CERT_STORE);
        internal static readonly string NEW_CERT_STORE = string.Format(@"new {0}", CERT_STORE);

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

        internal const string SETTING_CRYPTO_CLIPBOARD = @"clipboard";
        internal static readonly string CLIPBOARD_USAGE = string.Format("{0}Use \"{1}\" to write the output to the system clipboard", USAGE_INDENT, SETTING_CRYPTO_CLIPBOARD);

        internal static readonly string[] CRYPTO_PARAM_WIPE = { @"-w", @"-wipe" };

        //Crypto File Extensions
        internal const string CRYPTO_ENCRYPTED_FILE_EXT = @".ctx";
        internal const string CRYPTO_DECRYPTED_FILE_EXT = @".ptx";

        //Cert Parameters
        internal const string CERT_MODE_EXPORT_CERT = @"-nokey";
        internal const string CERT_MODE_EXPORT_KEY = @"-key";
        internal const string CERT_MODE_EXPORT_CERT_EXT = @".cer";
        internal const string CERT_MODE_EXPORT_KEY_EXT = @".pfx";
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

        //Make Cert Constants
        internal const string DEFAULT_WORKING_DIRECTORY = @"C:\temp";

        internal static readonly string STORE_LOCATION_USAGE = string.Format("(Optional) the certificate store name where the {0}encryption certificate is located.", PLACEHOLDER_CERT_OLD_NEW_CURRENT) +
                                                               string.Format("{0}The following values are valid for this setting:", USAGE_INDENT) +
                                                               string.Format("{0}* {1}", USAGE_INDENT, CertStore.CurrentUser.Name) +
                                                               string.Format("{0}* {1}", USAGE_INDENT, CertStore.LocalMachine.Name) +
                                                               string.Format("{0} Default is {1}0", USAGE_INDENT, CertStore.CurrentUser.Name);
        private static readonly string DESC_STORE_LOCATION = STORE_LOCATION_USAGE.Replace(PLACEHOLDER_CERT_OLD_NEW_CURRENT, string.Empty);

        #endregion

        #region Mode Settings

        private static readonly string[] SETTING_GENERAL_STORE = { @"-store", @"-certstore", @"-certificatestore", @"-keystore" };
        private static readonly string[] SETTING_GENERAL_TRUE = { @"true", @"yes", @"y" };
        private static readonly string[] SETTING_GENERAL_FALSE = { @"false", @"no", @"n" };
        private static readonly string[] SETTING_GENERAL_IN = { @"-in", @"-infile", @"-input", @"-inputfile" };
        private static readonly string[] SETTING_GENERAL_OUT = { @"-out", @"-outfile", @"-output", @"outputfile" };
        private static readonly string[] SETTING_GENERAL_PASSWORD = { @"-pass", @"-pfxpass", @"-password", @"-pfxpassword", @"pw" };
        private static readonly string[] SETTING_GENERAL_VERBOSE = { @"-debug", @"-debugmode", @"-d", @"-verbose", @"-verbosemode", @"-v" };

        private static readonly string[] SETTING_CRYPTO_THUMBPRINT = { @"-thumb", @"-thumbprint" };
        private static readonly string[] SETTING_CRYPTO_PLAINTEXT = { @"-pt", @"-plaintext" };
        private static readonly string[] SETTING_CRYPTO_CIPHERTEXT = { @"-ct", @"-ciphertext" };
        private static readonly string[] SETTING_CRYPTO_WIPE = { @"-wipe", @"-w", @"-delete" };

        private static readonly string[] SETTING_RECRYPTO_THUMBPRINT_OLD = { @"-oldthumb", @"-oldthumbprint" };
        private static readonly string[] SETTING_RECRYPTO_THUMBPRINT_NEW = { @"-newthumb", @"-newthumbprint" };
        private static readonly string[] SETTING_RECRYPTO_STORE_OLD = { @"-oldstore", @"-oldcertstore", @"-oldcertificatestore" };
        private static readonly string[] SETTING_RECRYPTO_STORE_NEW = { @"-newstore", @"-newcertstore", @"-newcertificatestore" };

        private static readonly string[] SETTING_MAKECERT_WORKING_DIR = { @"-workingdir", @"-path", @"-dir" };
        private static readonly string[] SETTING_LIST_INCLUDE_EXPIRED = { @"-expired", @"-includeexpired" };

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

        private static readonly string SYNTAX_CRYPTO_TEXT = string.Format("{0} {1} {2} [{3}] {4} [{5}] {{ {6} [{7}] {8} [{9}] }}",
                                                                          PLACEHOLDER_CRYPTO_COMMAND, CRYPTO_MODE_TEXT, PARAM_THUMB, CERT_THUMBPRINT,
                                                                          PARAM_IN, PLACEHOLDER_CRYPTO_PLAINTEXT_CIPHERTEXT,
                                                                          PARAM_CERTSTORE, CERT_STORE, PARAM_OUT, PATH);
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

        private static readonly string SYNTAX_CRYPTO_FILE = string.Format("{0} {1} {2} [{3}] {4} [{5}] {{ {6} [{7}] {8} [{9}] {10}}}",
                                                                          PLACEHOLDER_CRYPTO_COMMAND, CRYPTO_MODE_FILE, PARAM_THUMB, CERT_THUMBPRINT,
                                                                          PARAM_IN, PLACEHOLDER_CRYPTO_PLAINTEXT_CIPHERTEXT,
                                                                          PARAM_CERTSTORE, CERT_STORE, PARAM_OUT, PATH, CRYPTO_PARAM_WIPE[0]);
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

        private static readonly string SYNTAX_RECRYPTO_MAIN = string.Format("{0} {1} {2} {3} {4} [{5}] {6} [{7}] {{{8} [{9}] {10} [{11}] {12} [{13}{{0}}]}}",
                                                                    MAIN_MODE_REENCRYPT, CRYPTO_MODE_TEXT, PARAM_IN, CRYPTO_CIPHERTEXT, CRYPTO_PARAM_OLDTHUMB, OLD_CERT_THUMBPRINT, CRYPTO_PARAM_NEWTHUMB, OLD_CERT_THUMBPRINT, CRYPTO_PARAM_OLDCERTSTORE, OLD_CERT_STORE, CRYPTO_PARAM_NEWCERTSTORE, NEW_CERT_STORE, PARAM_OUT, PATH);

        //RE-CRYPTO TEXT USAGE
        private static readonly string SYNTAX_RECRYPTO_TEXT = string.Format(SYNTAX_RECRYPTO_MAIN, string.Format(@"|{0}", SETTING_CRYPTO_CLIPBOARD));
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
        private static readonly string SYNTAX_CERT_LIST = string.Format(@"{0} {{{1} [{2}]", MAIN_MODE_LIST, PARAM_CERTSTORE, CERT_STORE);
        private static Dictionary<string, string> certModeList = new Dictionary<string, string>
        {
            {PARAM_CERTSTORE, DESC_STORE_LOCATION },
            {CERT_PARAM_EXPIRED, @"(Optional) include expired certificates in output" }
        };
        private static readonly string USAGE_CERT_LIST = GetUsage(SYNTAX_CERT_LIST, certModeList, IS_PARAMETERS);

        //IMPORT USAGE
        private static readonly string SYNTAX_CERT_IMPORT = string.Format(@"{0} {1} [{2}] {3} [{4}] {{{5} [{6}]", MAIN_MODE_IMPORT, PARAM_IN, PATH, CERT_PARAM_PASSWORD, PASSWORD, PARAM_CERTSTORE, CERT_STORE);
        private static Dictionary<string, string> certModeImport = new Dictionary<string, string>
        {
            {PARAM_IN, @"The fully-qualified path to the PKCS #12 (.pfx or .p12) file to be imported" },
            {CERT_PARAM_PASSWORD.First(), @"The password to unlock the PKCS #12 file" },
            {PARAM_CERTSTORE, DESC_STORE_LOCATION }
        };
        private static readonly string USAGE_CERT_IMPORT = GetUsage(SYNTAX_CERT_IMPORT, certModeImport, IS_PARAMETERS);

        //EXPORT USAGE
        private static readonly string SYNTAX_CERT_EXPORT = string.Format(@"{0} [{1}|{2}] {3} [{4}] {5} [{6}] {7} [{8}", MAIN_MODE_EXPORT, CERT_MODE_EXPORT_KEY, CERT_MODE_EXPORT_CERT, CERT_PARAM_PASSWORD, PASSWORD, PARAM_CERTSTORE, CERT_STORE, PARAM_OUT, PATH);
        private static Dictionary<string, string> certModeExport = new Dictionary<string, string>
        {
            {string.Format(@"{0}/{1}", CERT_MODE_EXPORT_KEY, CERT_MODE_EXPORT_CERT), string.Empty +
                                       USAGE_INDENT + @"(Optional) Indicates whether the private key should be exported with the cert" +
                                       USAGE_INDENT + "\r\nDefault selection is " + CERT_MODE_EXPORT_CERT},
            {CERT_PARAM_PASSWORD.First(), "password to protect the PKCS#12 file" +
                                   USAGE_INDENT + string.Format(@"(Only compatible with {0} option)", CERT_MODE_EXPORT_KEY)},
            {PARAM_CERTSTORE, DESC_STORE_LOCATION },
            {PARAM_OUT, @"The fully-qualified file path where the exported certificate/private key should be written" }
        };
        private static readonly string USAGE_CERT_EXPORT = GetUsage(SYNTAX_CERT_EXPORT, certModeExport, IS_PARAMETERS);

        #endregion

        #region Member Fields

        //Global Settings
        public string thumbprint,
                      input,
                      output,
                      pass,
                      usage;

        public CertStore storeLocation = CertStore.CurrentUser;
        public Mode mode = Mode.Unknown;
        private int offset = 0;

        public bool GotThumbprint { get; set; } = false;
        public bool GotInput { get; set; } = false;
        public bool GotOutput { get; set; } = false;
        public bool GotPass { get; set; } = false;
        public bool WriteToFile { get; set; } = false;
        public bool VerboseMode { get; set; } = false;
        public bool Valid { get; set; } = false;

        //General Crypto Settings
        public bool WipeResidualFile { get; set; } = false;
        public bool UseClipboard { get; set; } = false;

        //Encrypt Settings
        public string plainText;
        public bool GotPlainText { get; set; } = false;

        //Decrypt Settings
        public string cipherText;
        public bool GotCipherText { get; set; } = false;

        //ReEncrypt
        public string oldThumbprint;
        public CertStore oldStoreLocation = CertStore.CurrentUser;
        public bool GotOldThumbprint { get; set; } = false;
        public bool GotNewThumbprint { get; set; } = false;
        public bool GotOldLocation { get; set; } = false;

        //Make Cert
        public string workingDir = DEFAULT_WORKING_DIRECTORY;

        //List
        public bool IncludeExpired { get; set; } = false;


        #endregion

        #region Constructors

        public Config(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine(USAGE_MAIN);
                return;
            }

            if (!GetMode(args))
                return;

            if (GetOptions(args))
            {
                if (!Valid)
                    Console.WriteLine(string.Format(@"Not enough arguments\r\n\r\n{0}", usage));
            }

        }

        #endregion

        #region Member Methods

        public bool GetMode(string[] args)
        {
            string currentArg;
            usage = USAGE_MAIN;

            try
            {
                currentArg = GetArgument(args, offset);

                //Encrypt
                if (Match(currentArg, MAIN_MODE_ENCRYPT))
                {
                    usage = USAGE_CRYPTO_ENCRYPT;
                    switch (GetContentType(args[++offset]))
                    {
                        case ContentType.Text:
                            mode = Mode.EncryptText;
                            usage = USAGE_CRYPTO_ENCRYPT_TEXT;
                            return true;
                        case ContentType.File:
                            mode = Mode.EncryptFile;
                            usage = USAGE_CRYPTO_ENCRYPT_FILE;
                            return true;
                        default:
                            throw new Exception(string.Format("Unrecognized argument: \"{0}\"", args[offset]));
                    }
                }

                //Decrypt
                if (Match(currentArg, MAIN_MODE_DECRYPT))
                {
                    usage = USAGE_CRYPTO_DECRYPT;
                    switch (GetContentType(args[++offset]))
                    {
                        case ContentType.Text:
                            mode = Mode.DecryptText;
                            usage = USAGE_CRYPTO_DECRYPT_TEXT;
                            return true;
                        case ContentType.File:
                            mode = Mode.DecryptFile;
                            usage = USAGE_CRYPTO_DECRYPT_FILE;
                            return true;
                        default:
                            throw new Exception(string.Format("Unrecognized argument: \"{0}\"", args[offset]));
                    }
                }

                //ReEncrypt
                if (Match(currentArg, MAIN_MODE_REENCRYPT))
                {
                    usage = USAGE_CRYPTO_REENCRYPT;
                    switch (GetContentType(args[++offset]))
                    {
                        case ContentType.Text:
                            mode = Mode.ReEncryptText;
                            usage = USAGE_CRYPTO_REENCRYPT_TEXT;
                            return true;
                        case ContentType.File:
                            mode = Mode.ReEncryptFile;
                            usage = USAGE_CRYPTO_REENCRYPT_FILE;
                            return true;
                        default:
                            throw new Exception(string.Format("Unrecognized argument: \"{0}\"", args[offset]));
                    }
                }

                //List
                if (Match(currentArg, MAIN_MODE_LIST))
                {
                    usage = USAGE_CERT_LIST;
                    mode = Mode.List;
                    return true;
                }

                //Import
                if (Match(currentArg, MAIN_MODE_IMPORT))
                {
                    usage = USAGE_CERT_IMPORT;
                    mode = Mode.ImportCert;
                    return true;
                }

                //Export
                if (Match(currentArg, MAIN_MODE_EXPORT))
                {
                    usage = USAGE_CERT_EXPORT;
                    mode = Mode.ExportCert;
                    return true;
                }

                //Help
                if (Match(currentArg, MAIN_MODE_HELP))
                {
                    mode = Mode.Help;
                    Console.WriteLine(usage);
                    return false;
                }

                //Unrecognized Mode
                throw new Exception(string.Format("Unrecognized argument: \"{0}\"", args[offset]));
            }

            catch (Exception ex)
            {
                Console.WriteLine(string.Format("{0}\r\n\r\n{1}", ex.Message, usage));
                return false;
            }
        }

        public bool GetOptions(string[] args)
        {
            try
            {
                while (++offset < args.Length)
                {
                    //Help?
                    if (Match(args[offset], MAIN_MODE_HELP))
                    {
                        mode = Mode.Help;
                        Console.WriteLine(usage);
                        return true;
                    }

                    //Thumbprints
                    GotThumbprint = GotThumbprint || CheckSetting(args, SETTING_CRYPTO_THUMBPRINT, ref thumbprint);
                    GotOldThumbprint = GotOldThumbprint || CheckSetting(args, SETTING_RECRYPTO_THUMBPRINT_OLD, ref oldThumbprint);
                    GotNewThumbprint = GotNewThumbprint || CheckSetting(args, SETTING_RECRYPTO_THUMBPRINT_NEW, ref thumbprint);

                    //Store Location
                    CheckStore(args, SETTING_GENERAL_STORE, ref storeLocation);
                    CheckStore(args, SETTING_RECRYPTO_STORE_OLD, ref oldStoreLocation);
                    CheckStore(args, SETTING_RECRYPTO_STORE_NEW, ref storeLocation);

                    //CipherText
                    GotCipherText = GotCipherText || CheckCiphertext(args);

                    //PlainText
                    GotPlainText = GotPlainText || CheckPlainText(args);

                    //Outfile
                    GotOutput = GotOutput || CheckOutFile(args); 
                    switch(mode)
                    {
                        case Mode.ExportCert:
                            AddExtension(CERT_MODE_EXPORT_CERT_EXT, ref output);
                            break;
                        case Mode.ExportPFX:
                            AddExtension(CERT_MODE_EXPORT_KEY_EXT, ref output);
                            break;
                    }

                    //InFile
                    GotInput = GotInput || CheckInput(args);

                    //Password
                    GotPass = GotPass || CheckSetting(args, SETTING_GENERAL_PASSWORD, ref pass);

                    //Export Key?
                    if (mode == Mode.ExportCert)
                    {
                        if (Match(args[offset], CERT_MODE_EXPORT_KEY))
                            mode = Mode.ExportPFX;
                    }

                    //List include Expired?
                    IncludeExpired = IncludeExpired || Match(args[offset], SETTING_LIST_INCLUDE_EXPIRED);

                    //Wipe residual file?
                    if (mode == Mode.EncryptFile || mode == Mode.DecryptFile)
                        WipeResidualFile = WipeResidualFile || Match(args[offset], SETTING_CRYPTO_WIPE);

                    //Debug mode?
                    VerboseMode = VerboseMode || Match(args[offset], SETTING_GENERAL_VERBOSE);
                }

                //Verify certs
                if (GotThumbprint || GotNewThumbprint)
                    PeekCert(thumbprint, storeLocation);
                if (GotOldThumbprint)
                    PeekCert(oldThumbprint, oldStoreLocation);

                switch (mode)
                {
                    case Mode.DecryptFile:
                        Valid = GotThumbprint && GotInput;
                        break;
                    case Mode.DecryptText:
                        Valid = GotThumbprint && GotInput;
                        WriteToFile = GotOutput & !UseClipboard;
                        break;
                    case Mode.EncryptFile:
                        Valid = GotThumbprint && GotInput;
                        break;
                    case Mode.EncryptText:
                        Valid = GotThumbprint && GotInput;
                        WriteToFile = GotOutput & !UseClipboard;
                        break;
                    case Mode.ReEncryptFile:
                        Valid = GotOldThumbprint && GotNewThumbprint && GotInput;
                        break;
                    case Mode.ReEncryptText:
                        Valid = GotOldThumbprint && GotNewThumbprint && GotInput;
                        WriteToFile = GotOutput & !UseClipboard;
                        break;
                    case Mode.ImportCert:
                        Valid = GotThumbprint && GotPass;
                        break;
                    case Mode.ExportCert:
                        Valid = GotThumbprint && GotOutput;
                        break;
                    case Mode.ExportPFX:
                        Valid = GotThumbprint && GotOutput && GotPass;
                        break;
                    case Mode.CreateCert:
                        Valid = DirectoryWritable(workingDir);
                        break;
                    case Mode.List:
                        Valid = true;
                        break;
                }

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine(string.Format("{0}\r\n\r\n{1}", ex.Message, usage));
                return false;
            }
        }


        private ContentType GetContentType(string currentArg)
        {
            if (Match(currentArg, CRYPTO_MODE_TEXT))
                return ContentType.Text;
            if (Match(currentArg, CRYPTO_MODE_FILE))
                return ContentType.File;
            else
                return ContentType.Unknown;
        }

        private bool CheckStore(string[] args, string[] setting_type, ref CertStore certStore)
        {
            try
            {
                if (Match(args[offset], setting_type))
                {
                    certStore = CertStore.GetByName(NextArgument(args));
                    return true;
                }
                return false;
            }
            catch (IndexOutOfRangeException)
            {
                throw new Exception(@"Wrong number of arguments");
            }
        }

        private bool CheckCiphertext(string[] args)
        {
            if (CheckCryptoInput(args, SETTING_CRYPTO_CIPHERTEXT, Mode.DecryptFile, ref cipherText))
            {
                if (mode == Mode.DecryptFile)
                    output = GetPlaintextFileName(cipherText);
                return true;
            }
            else
                return false;
        }

        private bool CheckCryptoInput(string[] args, string[] setting_type, Mode fileMode, ref string field)
        {
            if (Match(args[offset], setting_type))
            {
                field = NextArgument(args);

                if (mode == fileMode)
                {
                    if (!File.Exists(field))
                        throw new FileNotFoundException(string.Format("\"{0}\": Path does not exist", field));
                }
                return true;
            }
            return false;
        }

        private bool CheckPlainText(string[] args)
        {
            if (CheckCryptoInput(args, SETTING_CRYPTO_PLAINTEXT, Mode.EncryptFile, ref plainText))
            {
                if (mode == Mode.EncryptFile)
                    output = GetCipherTextFileName(plainText);
                return true;
            }
            else
                return false;
        }

        private bool CheckOutFile(string[] args)
        {
            if (Match(args[offset], SETTING_GENERAL_OUT))
            {
                output = NextArgument(args);

                if (Match(output, SETTING_CRYPTO_CLIPBOARD))
                    UseClipboard = true;
                else
                {
                    if (!IsPathValid(output))
                        throw new Exception(string.Format("\"{0}\": path contains 1 or more invalid characters.", output));
                }
                return true;
            }

            return false;
        }

        private bool CheckInput(string[] args)
        {
            if (Match(args[offset], SETTING_GENERAL_IN))
            {
                input = NextArgument(args);

                if (mode == Mode.DecryptFile || mode == Mode.EncryptFile || mode == Mode.ReEncryptFile || mode == Mode.ImportCert)
                {
                    if (!File.Exists(input))
                        throw new Exception(string.Format("\"{0}\": file not found", input));
                }

                if (!GotOutput)
                {
                    switch (mode)
                    {
                        case Mode.EncryptFile:
                            output = GetCipherTextFileName(input);
                            GotOutput = true;
                            break;
                        case Mode.DecryptFile:
                            output = GetPlaintextFileName(input);
                            GotOutput = true;
                            break;
                    }
                }
                return true;
            }
            else
                return false;
        }

        private bool CheckSetting(string[] args, string[] setting_type, ref string setting)
        {
            if (Match(args[offset], setting_type))
            {
                setting = NextArgument(args);
                return true;
            }
            return false;
        }

        public void PeekCert(string thumbprint, CertStore storeLocation)
        {
            if (!x509CryptoAgent.thumbprintFound(thumbprint, storeLocation))
                throw new Exception(string.Format("Certificate with thumbprint \"{0}\" was not found in the {1} certificate store", thumbprint, storeLocation.Name));
        }

        private string NextArgument(string[] args)
        {
            try
            {
                return args[++offset];
            }
            catch (IndexOutOfRangeException)
            {
                throw new Exception(@"Wrong number of arguments");
            }
        }

        #endregion

        #region Static Methods

        private static bool Match(string expression, string[] patternSet)
        {
            foreach(string possibility in patternSet)
            {
                if (Match(expression, possibility))
                    return true;
            }
            return false;
        }

        private static bool Match(string expression, string pattern)
        {
            return expression.SameAs(pattern);
        }

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

        private static string GetArgument(string[] args, int offset)
        {
            try
            {
                return args[offset];
            }
            catch (IndexOutOfRangeException)
            {
                throw new Exception(@"Wrong number of arguments");
            }
        }

        private static bool IsPathValid(string path)
        {
            try
            {
                Path.GetFullPath(path);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static void AddExtension(string ext, ref string path)
        {
            if (Path.GetExtension(path).SameAs(ext))
                return;
            path = path + ext;
        }

        private static string GetCipherTextFileName(string path)
        {
            if (Path.GetExtension(path).SameAs(CRYPTO_ENCRYPTED_FILE_EXT))
                return path;
            else
                return path + CRYPTO_ENCRYPTED_FILE_EXT;
        }

        private static string GetPlaintextFileName(string path)
        {
            string ext = Path.GetExtension(path);
            if (ext.SameAs(CRYPTO_ENCRYPTED_FILE_EXT))
                return path.Remove(path.LastIndexOf(ext), ext.Length);
            else
                return path + CRYPTO_DECRYPTED_FILE_EXT;
        }

        private static bool DirectoryWritable(string path)
        {
            try
            {
                DirectorySecurity ds = Directory.GetAccessControl(path);
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
        }

        #endregion
    }

}
