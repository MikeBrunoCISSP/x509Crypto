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
   
    static class Constants
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
    }

}
