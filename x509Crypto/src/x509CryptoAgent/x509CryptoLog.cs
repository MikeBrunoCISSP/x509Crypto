using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace x509Crypto
{
    public static class x509CryptoLog
    {
        #region Public-facing

        /// <summary>
        /// Supported logging levels
        /// </summary>
        public enum Level
        {
            /// <summary>
            /// Only critical errors will be logged
            /// </summary>
            CRITICAL = 0,

            /// <summary>
            /// All errors will be logged
            /// </summary>
            ERROR = 1,

            /// <summary>
            /// All errors and warnings will be logged.
            /// </summary>
            WARNING = 2,

            /// <summary>
            /// Informational messages, errors and warnings will be logged
            /// </summary>
            INFO = 3,

            /// <summary>
            /// Verbose logging (for diagnostic purposes)
            /// </summary>
            VERBOSE = 4,

            /// <summary>
            /// Almost everything is logged (mostly for internal debugging purposes)
            /// </summary>
            MASSIVE = 5
        }

        #endregion
        internal static void massive(string v)
        {
            throw new NotImplementedException();
        }

        internal static void info(string v)
        {
            throw new NotImplementedException();
        }

        internal static void warning(string v)
        {
            throw new NotImplementedException();
        }

        internal static void exception(Level eRROR, CryptographicException ex, string v)
        {
            throw new NotImplementedException();
        }
    }
}
