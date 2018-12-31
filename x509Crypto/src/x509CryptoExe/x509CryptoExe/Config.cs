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
