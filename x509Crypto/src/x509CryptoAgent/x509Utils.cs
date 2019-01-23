using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.ComponentModel;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using System.Globalization;

namespace x509Crypto
{
    public enum CertStoreLocation
    {
        [Description(@"CURRENTUSER")]
        CurrentUser,

        [Description(@"LOCALMACHINE")]
        LocalMachine
    }

    public static class x509Utils
    {
        #region Constants and Static Fields

        /// <summary>
        /// String representation of System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser
        /// </summary>
        public static readonly string sSTORELOCATION_CURRENTUSER = CertStoreLocation.CurrentUser.GetEnumDescription();

        /// <summary>
        /// String representation of System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine
        /// </summary>
        public static readonly string sSTORELOCATION_LOCALMACHINE = CertStoreLocation.LocalMachine.GetEnumDescription();

        private static string allowedThumbprintCharsPattern = "[^a-fA-F0-9]";

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

        public static string GetEnumDescription<T>(this T e) where T : IConvertible
        {
            if (e is Enum)
            {
                Type type = e.GetType();
                Array values = System.Enum.GetValues(type);

                foreach(int val in values)
                {
                    if (val == e.ToInt32(CultureInfo.InvariantCulture))
                    {
                        var memInfo = type.GetMember(type.GetEnumName(val));
                        var descriptionAttribute = memInfo[0]
                            .GetCustomAttributes(typeof(DescriptionAttribute), false)
                            .FirstOrDefault() as DescriptionAttribute;

                        if (descriptionAttribute != null)
                        {
                            return descriptionAttribute.Description;
                        }
                    }
                }
            }

            return null;
        }

        public static CertStoreLocation GetStoreLocation(string sStoreLocation)
        {
            Array values = Enum.GetValues(typeof(CertStoreLocation));

            foreach(int val in values)
            {
                var memInfo = typeof(CertStoreLocation).GetMember(typeof(CertStoreLocation).GetEnumName(val));
                var descriptionAttribute = memInfo[0]
                    .GetCustomAttributes(typeof(DescriptionAttribute), false)
                    .FirstOrDefault() as DescriptionAttribute;

                if (string.Equals(sStoreLocation, descriptionAttribute.Description, StringComparison.OrdinalIgnoreCase))
                {
                    return (CertStoreLocation)val;
                }

            }

            throw new Exception(string.Format("{0}: Not a valid certificate store location name. Acceptable values are:\r\n1. {1}\r\n2. {2}", sStoreLocation, CertStoreLocation.CurrentUser.Name(), CertStoreLocation.LocalMachine.Name()));
        }

        public static StoreLocation GetStoreLocation(CertStoreLocation certStoreLocation)
        {
            return certStoreLocation == CertStoreLocation.CurrentUser ? StoreLocation.CurrentUser : StoreLocation.LocalMachine;
        }

        public static string FormatThumbprint(string inThumbprint)
        {
            return Regex.Replace(inThumbprint, allowedThumbprintCharsPattern, "").ToUpper();
        }
             

        #endregion

        #region Internal Methods


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
