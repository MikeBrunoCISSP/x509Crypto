using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace X509Crypto
{
    /// <summary>
    /// A convenience class to enable the unambiguous binding between the System.Security.Cryptography.X509Certificates.StoreLocation enumerable and their accompanying string representation.
    /// This class is not meant to be instantiated, but 2 static instances are available when the x509Crypto namespace is referenced.
    /// </summary>
    public class CertStore
    {
        const string sSTORELOCATION_CURRENTUSER = @"CURRENTUSER";
        const string sSTORELOCATION_LOCALMACHINE = @"LOCALMACHINE";

        /// <summary>
        /// System.Security.Cryptography.X509Certificates.StoreLocation enumerable value for a cert store
        /// </summary>
        public StoreLocation Location { get; private set; }

        /// <summary>
        /// The string representation of a cert store.
        /// </summary>
        public string Name { get; private set; }

        private CertStore(StoreLocation location, string name)
        {
            Location = location;
            Name = name;
        }

        /// <summary>
        /// Represents the System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser cert store
        /// String representation: <see cref="sSTORELOCATION_CURRENTUSER"/>
        /// </summary>
        public static readonly CertStore CurrentUser = new CertStore(StoreLocation.CurrentUser, sSTORELOCATION_CURRENTUSER);

        /// <summary>
        /// Represents the System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine cert store
        /// String representation: <see cref="sSTORELOCATION_LOCALMACHINE"/>
        /// </summary>
        public static readonly CertStore LocalMachine = new CertStore(StoreLocation.LocalMachine, sSTORELOCATION_LOCALMACHINE);

        /// <summary>
        /// Returns the respective x509Crypto.CertStore object based on its indicated string representation
        /// </summary>
        /// <param name="name">Either "<see cref="sSTORELOCATION_CURRENTUSER"/>" or "<see cref="sSTORELOCATION_LOCALMACHINE"/>"</param>
        /// <returns>x509Crypto.CertStore object if the parameter is recognized.  Otherwise, an exception is thrown</returns>
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
