using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Org.X509Crypto
{
    /// <summary>
    /// <para>This class provides an unambiguous binding between each member of the System.Security.Cryptography.X509Certificates.StoreLocation enumerable and its accompanying string representation.</para>
    /// <para>This class is not inteded to be instantiated externally.  Instead, static instances representing the CURRENTUSER and LOCALMACHINE certificate stores are provided.</para>
    /// </summary>
    public class CertStore
    {
        internal const string sSTORELOCATION_CURRENTUSER = @"CURRENTUSER";
        internal const string sSTORELOCATION_LOCALMACHINE = @"LOCALMACHINE";

        /// <summary>
        /// System.Security.Cryptography.X509Certificates.StoreLocation enumerable value for a cert store
        /// </summary>
        public StoreLocation Location { get; private set; }

        /// <summary>
        /// The string representation (name) of a cert store.
        /// </summary>
        public string Name { get; private set; }

        private CertStore(StoreLocation location, string name)
        {
            Location = location;
            Name = name;
        }

        /// <summary>
        /// <para>Represents the CurrentUser certificate store</para>
        /// <para>Enumerable Representation <see cref="Location"/>: <see cref="System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser"/></para>
        /// <para>String representation <see cref="Name"/>: "CURRENTUSER"</para>
        /// </summary>
        public static readonly CertStore CurrentUser = new CertStore(StoreLocation.CurrentUser, sSTORELOCATION_CURRENTUSER);

        /// <summary>
        /// <para>Represents the LocalMachine certificate store</para>
        /// <para>Enumerable Representation <see cref="Location"/>: <see cref="System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine"/></para>
        /// <para>String representation <see cref="Name"/>: "LOCALMACHINE"</para>
        /// </summary>
        public static readonly CertStore LocalMachine = new CertStore(StoreLocation.LocalMachine, sSTORELOCATION_LOCALMACHINE);

        /// <summary>
        /// This method is provided so that a certificate store can be specified via a string value, allowing you to specify the appropriate certificate store in your app.config/web.config file
        /// </summary>
        /// <param name="name">Either "<see cref="sSTORELOCATION_CURRENTUSER"/>" or "<see cref="sSTORELOCATION_LOCALMACHINE"/>"</param>
        /// <returns>x509Crypto.CertStore object if the name parameter is recognized as a certificate store name.  Otherwise, an exception is thrown</returns>
        /// <example>
        /// <code>
        /// // In .config appSettings: 
        /// //   &lt;add key="CertStore" value="CURRENTUSER"/&gt;
        /// //   &lt;add key="CertThumbprint" value="ccdc673c40ebb2a433300c0c8a2ba6f443da5688"/&gt;
        /// 
        /// string sCertStore = ConfigurationManager.AppSettings["CertStore"];
        /// string thumbprint = ConfigurationManager.AppSettings["CertThumbprint"];
        /// X509CryptoAgent agent = new X509CryptoAgent(thumbprint, <see cref="X509Context"/>.GetByName(sCertStore));
        /// </code>
        /// </example>
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
