using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;

namespace x509Crypto
{
    public static class StringExtensions
    {
        public static bool SameAs(this string expression1, string expression2)
        {
            return string.Equals(expression1.Trim(), expression2.Trim(), StringComparison.OrdinalIgnoreCase);
        }

        public static StoreLocation Location(this CertStoreLocation certStore)
        {
            switch(certStore)
            {
                case CertStoreLocation.CurrentUser:
                    return StoreLocation.CurrentUser;
                case CertStoreLocation.LocalMachine:
                    return StoreLocation.LocalMachine;
                default:
                    throw new Exception(@"Invalid CertStoreLocation");
            }
        }

        public static string Name(this CertStoreLocation certStore)
        {
            return certStore.GetEnumDescription();
        }
    }
}
