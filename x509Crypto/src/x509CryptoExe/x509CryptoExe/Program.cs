using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using x509Crypto;

namespace x509CryptoExe
{
    class Program
    {
        const int RESULT_SUCCESS = 0x0;
        const int RESULT_BAD_INPUT = 0x1;
        const int RESULT_EXCEPTION = 0x2;

        private static Config config = null;

        static void Main(string[] args)
        {
        }

        [STAThread]
        static int EncryptString()
        {
            string logLabel = @"EncryptString";

            using (x509CryptoAgent agent = new x509CryptoAgent(config.thumbprint, config.storeLocation))
            {
                try
                {
                    cipherText = agent.EncryptText(config.input);

                    if (config.WriteToFile)
                        File.WriteAllText(config.output, cipherText);
                    else
                    {
                        if (config.UseClipboard)
                            Clipboard.SetText(cipherText);
                        x509CryptoLog.Info(string.Format(@"Ciphertext: {0}", config.UseClipboard ? "Written to system clipboard" : cipherText), writeToScreen: true);
                    }

                    return RESULT_SUCCESS;
                }
                catch (Exception ex)
                {
                    x509CryptoLog.Exception(ex, Criticality.CRITICAL, logLabel);
                    return RESULT_EXCEPTION;
                }
            }
        }
    }
}
