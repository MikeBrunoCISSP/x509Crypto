using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace x509Crypto
{
    public class CertStore
    {
        const string sSTORELOCATION_CURRENTUSER = @"CURRENTUSER";
        const string sSTORELOCATION_LOCALMACHINE = @"LOCALMACHINE";

        public StoreLocation Location { get; private set; }

        public string Name { get; private set; }

        private CertStore(StoreLocation location, string name)
        {
            Location = location;
            Name = name;
        }

        public static readonly CertStore CurrentUser = new CertStore(StoreLocation.CurrentUser, sSTORELOCATION_CURRENTUSER);
        public static readonly CertStore LocalMachine = new CertStore(StoreLocation.LocalMachine, sSTORELOCATION_LOCALMACHINE);

        public static CertStore GetByName(string name)
        {
            string formattedName = Regex.Replace(name, @"\s+", "").ToUpper();
            switch (formattedName)
            {
                case sSTORELOCATION_CURRENTUSER:
                    return CurrentUser;
                case sSTORELOCATION_LOCALMACHINE:
                    return LocalMachine;
                default:
                    throw new Exception(string.Format(@"{0}: Not a valid store location name. Acceptable entries for this property are {1} or {2}", name, sSTORELOCATION_CURRENTUSER, sSTORELOCATION_LOCALMACHINE));
            }
        }
    }
}
