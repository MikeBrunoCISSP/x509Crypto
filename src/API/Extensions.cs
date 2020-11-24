using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
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

        /// <summary>
        /// Extension method which indicates whether a string expression is found in a collection of strings
        /// </summary>
        /// <param name="Collection">this string collection</param>
        /// <param name="compareExpression">string expression to be compared with this string</param>
        /// <param name="caseSensitive">Indicates whether the compare should be case sensistive or not</param>
        /// <returns>true if any element in this collection matches the compare expression</returns>
        public static bool Contains(this IEnumerable<string> Collection, string compareExpression, bool caseSensitive = false)
        {
            return Collection.Any(p => p.Matches(compareExpression, caseSensitive: caseSensitive));
        }

        /// <summary>
        /// Determines whether two SecureString objects contain the same contents
        /// </summary>
        /// <param name="s1">A SecureString</param>
        /// <param name="s2">A SecureString to compare</param>
        /// <returns>True if the SecureString objects contain the same contents</returns>
        public static bool Matches(this SecureString s1, SecureString s2)
        {
            if (s1 == null)
            {
                throw new ArgumentNullException("s1");
            }
            if (s2 == null)
            {
                throw new ArgumentNullException("s2");
            }

            if (s1.Length != s2.Length)
            {
                return false;
            }

            IntPtr bstr1 = IntPtr.Zero;
            IntPtr bstr2 = IntPtr.Zero;

            RuntimeHelpers.PrepareConstrainedRegions();

            try
            {
                bstr1 = Marshal.SecureStringToBSTR(s1);
                bstr2 = Marshal.SecureStringToBSTR(s2);

                unsafe
                {
                    for (Char* ptr1 = (Char*)bstr1.ToPointer(), ptr2 = (Char*)bstr2.ToPointer();
                        *ptr1 != 0 && *ptr2 != 0;
                         ++ptr1, ++ptr2)
                    {
                        if (*ptr1 != *ptr2)
                        {
                            return false;
                        }
                    }
                }

                return true;
            }
            finally
            {
                if (bstr1 != IntPtr.Zero)
                {
                    Marshal.ZeroFreeBSTR(bstr1);
                }

                if (bstr2 != IntPtr.Zero)
                {
                    Marshal.ZeroFreeBSTR(bstr2);
                }
            }
        }

        /// <summary>
        /// Converts a SecureString object to a normal string expression
        /// </summary>
        /// <param name="secret">The SecureString object to be converted</param>
        /// <returns>converted string expression</returns>
        public static string Plaintext(this SecureString secret)
        {
            if (secret == null)
            {
                throw new ArgumentNullException(nameof(secret));
            }

            IntPtr unmanagedString = IntPtr.Zero;
            try
            {
                unmanagedString = Marshal.SecureStringToGlobalAllocUnicode(secret);
                return Marshal.PtrToStringUni(unmanagedString);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
            }
        }

        /// <summary>
        /// Surrounds the specified expression with double-quotes
        /// </summary>
        /// <param name="expression">the expression to be surrounded with double-quotes</param>
        /// <returns></returns>
        public static string InQuotes(this string expression)
        {
            return $"\"{expression}\"";
        }



        internal static string Dashes(this string expression)
        {
            return new string('-', expression.Length);
        }
    }
}
