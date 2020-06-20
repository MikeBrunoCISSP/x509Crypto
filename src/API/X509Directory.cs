using System;
using System.IO;

namespace Org.X509Crypto
{
    internal static class X509Directory
    {
        private static readonly string UserTemplate = Path.Combine($"C:\\Users\\{Constants.UserDirectoryPlaceholder}\\AppData\\Local", Constants.AppDirectory);

        internal static string User
        {
            get
            {
                return UserTemplate.Replace(Constants.UserDirectoryPlaceholder, Environment.UserName);
            }
        }

        internal static string ImpersonatedUser(string sAMAccountName)
        {
            return UserTemplate.Replace(Constants.UserDirectoryPlaceholder, sAMAccountName);
        }

        internal static string System = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), Constants.AppDirectory);
    }
}
