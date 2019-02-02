using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace X509CryptoExe
{
    /// <summary>
    /// X509Cryto Extension class
    /// </summary>
    public static class Extensions
    {
        /// <summary>
        /// Determines if two text expressions match (case-insensitive)
        /// </summary>
        /// <param name="expression1">text expression #1</param>
        /// <param name="expression2">text expression #2</param>
        /// <returns>true or false depending on whether the text expressions match</returns>
        public static bool SameAs(this string expression1, string expression2)
        {
            return string.Equals(expression1.Trim(), expression2.Trim(), StringComparison.OrdinalIgnoreCase);
        }
    }
}
