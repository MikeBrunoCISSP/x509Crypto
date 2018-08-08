using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;

namespace x509Crypto
{
    public class x509Utils
    {
        #region Constants and Static Fields

        /// <summary>
        /// String representation of System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser
        /// </summary>
        public static readonly string sSTORELOCATION_CURRENTUSER = @"CURRENTUSER";

        /// <summary>
        /// String representation of System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine
        /// </summary>
        public static readonly string sSTORELOCATION_LOCALMACHINE = @"LOCALMACHINE";

        #endregion

        #region Public Methods



        #endregion

        #region Internal Methods

        internal static StoreLocation getStoreLocation(string sStoreLocation)
        {
            string sStoreLocationFixed = Regex.Replace(sStoreLocation, @"\s+", "").ToUpper();

            if (string.Equals(sStoreLocationFixed, sSTORELOCATION_CURRENTUSER, StringComparison.OrdinalIgnoreCase))
                return StoreLocation.CurrentUser;
            else
            {
                if (string.Equals(sStoreLocationFixed, sSTORELOCATION_LOCALMACHINE, StringComparison.OrdinalIgnoreCase))
                {
                    return StoreLocation.LocalMachine;
                }
                else
                    throw new Exception(string.Format("Unknown value for StoreLocation {0}. Acceptable values are {1} and {2}", sStoreLocation, sSTORELOCATION_CURRENTUSER, sSTORELOCATION_LOCALMACHINE));
            }
        }

        internal static string cleanThumbprint(string certThumbprint)
        {
            throw new NotImplementedException();
        }

        internal static void VerifyFile(string pfxPath)
        {
            throw new NotImplementedException();
        }

        #endregion
    }
}
