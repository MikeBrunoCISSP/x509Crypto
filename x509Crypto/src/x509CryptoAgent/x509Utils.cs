using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
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

        /// <summary>
        /// Loads the contents of a text file into a string expression
        /// </summary>
        /// <param name="path">The fully-qualified path to the file from which contents are being loaded</param>
        /// <returns>The contents of the specified text file as a string expression</returns>
        public static string LoadTextFromFile(string path)
        {
            string contents;

            if (!File.Exists(path))
            {
                string message = string.Format(@"Path does not exist: {0}", path);
                x509CryptoLog.Error(message, @"LoadTextFromFile");
                throw new FileNotFoundException(message);
            }

            using (FileStream inStream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                using (TextReader streamReader = new StreamReader(inStream))
                {
                    contents = streamReader.ReadToEnd();
                    streamReader.Close();
                }
                inStream.Close();
            }

            return contents;
        }


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
