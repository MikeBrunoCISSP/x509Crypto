using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Org.X509Crypto
{
    internal static class PrivateExtensions
    {
        internal static string LeftAlign(this string expression, int allocatedChars)
        {
            string alignedExpression = expression;

            if (expression.Length > allocatedChars)
            {
                alignedExpression = expression.Substring(0, allocatedChars);
            }
            else
            {
                if (expression.Length < allocatedChars)
                {
                    alignedExpression = expression.PadRight(allocatedChars);
                }
            }

            return alignedExpression;
        }

        internal static string Base64Encode(this string expression)
        {
            return Convert.ToBase64String(Encoding.ASCII.GetBytes(expression));
        }

        internal static string Base64Decode(this string expression)
        {
            return Encoding.ASCII.GetString(Convert.FromBase64String(expression));
        }
    }

    /// <summary>
    /// Publicly-facing Extension Methods
    /// </summary>
    public static class Extensions
    {
        private static Regex NonHex = new Regex("[^a-fA-F0-9]");
        /// <summary>
        /// Removes all non-hexidecimal characters from the specified string expression. 
        /// Useful for removing artifact characters from a certificate thumbprint that was copied from the Certificates MMC snap-in
        /// </summary>
        /// <param name="expression">string expression</param>
        /// <returns>specified string expression with any non-hexidecimal ASCII characters (a-f,A-f,0-9) removed</returns>
        public static string RemoveNonHexChars(this string expression)
        {
            return NonHex.Replace(expression, string.Empty);
        }

        /// <summary>
        /// Extension method which indicates whether a string expression is the same as this string
        /// </summary>
        /// <param name="expression">this string</param>
        /// <param name="compareExpression">string expression to be compared with this string</param>
        /// <param name="caseSensitive">Indicates whether the compare should be case sensistive or not</param>
        /// <param name="ignoreWhitespace">Indicates whether surrounding whitespace should be ignored or not</param>
        /// <returns>true if the expressions match in accordance with the indicated options</returns>
        public static bool Matches(this string expression, string compareExpression, bool caseSensitive = false, bool ignoreWhitespace = true)
        {
            if (ignoreWhitespace)
            {
                expression = expression.Trim();
                compareExpression = compareExpression.Trim();
            }
            StringComparison compareType = caseSensitive ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;
            return string.Equals(expression, compareExpression, compareType);
        }
    }
}
