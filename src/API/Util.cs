using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace Org.X509Crypto
{
    internal static class Util
    {
        internal static bool IsAdministrator = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

        internal static void VerifyFileExists(string filePath)
        {
            if (File.Exists(filePath))
            {
                X509CryptoLog.Info($"File \"{filePath}\" exists.");
            }
            else
            {
                FileNotFoundException ex = new FileNotFoundException(@"The expected file was not created", filePath);
                X509CryptoLog.Exception(ex, Criticality.CRITICAL);
                throw ex;
            }
        }
    }
}
