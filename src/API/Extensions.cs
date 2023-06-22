using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;

namespace Org.X509Crypto {
    internal static class PrivateExtensions {

        internal static string LeftAlign(this string expression, int allocatedChars) {
            string alignedExpression = expression;

            if (expression.Length > allocatedChars) {
                alignedExpression = expression.Substring(0, allocatedChars);
            } else {
                if (expression.Length < allocatedChars) {
                    alignedExpression = expression.PadRight(allocatedChars);
                }
            }

            return alignedExpression;
        }

        internal static string Base64Encode(this string expression) {
            return Convert.ToBase64String(Encoding.ASCII.GetBytes(expression));
        }

        internal static string Base64Decode(this string expression) {
            return Encoding.ASCII.GetString(Convert.FromBase64String(expression));
        }

        internal static string GetString(this byte[] bytes) {
            return Encoding.ASCII.GetString(bytes, 0, bytes.Length);
        }

        internal static byte[] ToByteArray(this string expression) {
            return Encoding.ASCII.GetBytes(expression);
        }

        internal static string ToUnsecureString(this SecureString Expression) {
            if (Expression == null) {
                return string.Empty;
            }

            IntPtr unManagedString = IntPtr.Zero;
            try {
                unManagedString = Marshal.SecureStringToGlobalAllocUnicode(Expression);
                return Marshal.PtrToStringUni(unManagedString);
            } finally {
                Marshal.ZeroFreeGlobalAllocUnicode(unManagedString);
            }
        }
    }

    /// <summary>
    /// Publicly-facing Extension Methods
    /// </summary>
    public static class Extensions {
        private static Regex NonHex = new Regex("[^a-fA-F0-9]");
        /// <summary>
        /// Removes all non-hexidecimal characters from the specified string expression. 
        /// Useful for removing artifact characters from a certificate thumbprint that was copied from the Certificates MMC snap-in
        /// </summary>
        /// <param name="expression">string expression</param>
        /// <returns>specified string expression with any non-hexidecimal ASCII characters (a-f,A-f,0-9) removed</returns>
        public static string RemoveNonHexChars(this string expression) {
            return NonHex.Replace(expression, string.Empty);
        }

        /// <summary>
        /// Extension method which indicates whether a string expression is the same as this string
        /// </summary>
        /// <param name="expression">this string</param>
        /// <param name="compareExpression">string expression to be compared with this string</param>
        /// <param name="compareType"><see cref="StringComparison"/> type></param>
        /// <param name="ignoreWhitespace">Indicates whether surrounding whitespace should be ignored or not</param>
        /// <returns>true if the expressions match in accordance with the indicated options</returns>
        public static bool Matches(this string expression, string compareExpression, StringComparison compareType = StringComparison.InvariantCultureIgnoreCase, bool ignoreWhitespace = true) {
            if (ignoreWhitespace) {
                expression = expression.Trim();
                compareExpression = compareExpression.Trim();
            }
            return string.Equals(expression, compareExpression, compareType);
        }

        /// <summary>
        /// Extension method which indicates whether a string expression is found in a collection of strings
        /// </summary>
        /// <param name="Collection">this string collection</param>
        /// <param name="compareExpression">string expression to be compared with this string</param>
        /// <param name="caseSensitive">Indicates whether the compare should be case sensistive or not</param>
        /// <returns>true if any element in this collection matches the compare expression</returns>
        public static bool Contains(this IEnumerable<string> Collection, string compareExpression, StringComparison compareType) {
            return Collection.Any(p => p.Matches(compareExpression, compareType: compareType));
        }

        /// <summary>
        /// Determines whether two SecureString objects contain the same contents
        /// </summary>
        /// <param name="s1">A SecureString</param>
        /// <param name="s2">A SecureString to compare</param>
        /// <returns>True if the SecureString objects contain the same contents</returns>
        public static bool Matches(this SecureString s1, SecureString other) {
            return ReferenceEquals(s1, other)
                   || (other != null
                        && s1.matches(other));
        }

        static bool matches(this SecureString s1, SecureString s2) {
            if (s1.Length != s2.Length) {
                return false;
            }

            IntPtr s1ptr = IntPtr.Zero;
            IntPtr s2ptr = IntPtr.Zero;

            try {
                s1ptr = Marshal.SecureStringToBSTR(s1);
                s2ptr = Marshal.SecureStringToBSTR(s2);

                return Marshal.PtrToStringBSTR(s1ptr).Equals(Marshal.PtrToStringBSTR(s2ptr));
            } finally {
                if (s1ptr != IntPtr.Zero) {
                    Marshal.ZeroFreeBSTR(s1ptr);
                }
                if (s2ptr != IntPtr.Zero) {
                    Marshal.ZeroFreeBSTR(s2ptr);
                }
            }
        }

        /// <summary>
        /// Converts a SecureString object to a normal string expression
        /// </summary>
        /// <param name="secret">The SecureString object to be converted</param>
        /// <returns>converted string expression</returns>
        public static string ToUnSecureString(this SecureString secret) {
            if (secret == null) {
                throw new ArgumentNullException(nameof(secret));
            }

            IntPtr unmanagedString = IntPtr.Zero;
            try {
                unmanagedString = Marshal.SecureStringToGlobalAllocUnicode(secret);
                return Marshal.PtrToStringUni(unmanagedString);
            } finally {
                Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
            }
        }

        /// <summary>
        /// Returns true if this X509Context represents a local system context
        /// </summary>
        /// <param name="Context">an X509Context object</param>
        /// <returns>true if this X509Context represents a local system context</returns>
        public static bool IsSystemContext(this X509Context Context) {
            return Context == X509Context.SystemFull || Context == X509Context.SystemReadOnly;
        }

        /// <summary>
        /// Returns true if this X509Context represents a user context
        /// </summary>
        /// <param name="Context">an X509Context object</param>
        /// <returns>true if this X509Context represents a user context</returns>
        public static bool IsUserContext(this X509Context Context) {
            return Context == X509Context.UserFull || Context == X509Context.UserReadOnly;
        }



        internal static string GetDivider(this string expression, char c = '-') {
            return new string(c, expression.Length);
        }
    }
}
