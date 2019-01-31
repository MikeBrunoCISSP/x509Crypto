using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using X509Crypto;

namespace X509CryptoExe
{
    class Program
    {
        #region Constants

        const int RESULT_SUCCESS = 0x0;
        const int RESULT_BAD_INPUT = 0x1;
        const int RESULT_EXCEPTION = 0x2;

        #endregion

        #region Static Fields

        private static Config config = null;

        #endregion

        #region Entry Point

        [STAThread]
        static int Main(string[] args)
        {
            try
            {
                config = new Config(args);
            }
            catch (Exception ex)
            {
                X509CryptoLog.Exception(ex, Criticality.CRITICAL, @"Config");
                return RESULT_EXCEPTION;
            }

            if (!config.Valid)
                return -1;

            switch(config.mode)
            {
                case Mode.EncryptText:
                    return EncryptText();
                case Mode.ReEncryptText:
                    return ReEncryptText();
                case Mode.EncryptFile:
                    return EncryptFile();
                case Mode.ReEncryptFile:
                    return ReEncryptFile();
                case Mode.DecryptText:
                    return DecryptText();
                case Mode.DecryptFile:
                    return DecryptFile();
                case Mode.ImportCert:
                    return ImportPFX();
                case Mode.ExportCert:
                    return ExportCert();
                case Mode.ExportPFX:
                    return ExportPFX();
                case Mode.List:
                    return ListCerts();
                case Mode.MakeCert:
                    return MakeCert();
                case Mode.Help:
                    return RESULT_SUCCESS;
                default:
                    return RESULT_BAD_INPUT;
            }
        }

        #endregion

        #region Execution

        [STAThread]
        static int EncryptText()
        {
            string ciphertext;

            try
            {
                ciphertext = X509Utils.EncryptText(config.thumbprint, config.input, config.storeLocation);
                Output(ciphertext);
                return RESULT_SUCCESS;
            }
            catch (Exception ex)
            {
                X509CryptoLog.Exception(ex, Criticality.CRITICAL, X509Utils.MethodName());
                return RESULT_EXCEPTION;
            }
        }

        [STAThread]
        static int ReEncryptText()
        {
            string ciphertext;

            try
            {
                ciphertext = X509Utils.ReEncryptText(config.oldThumbprint, config.thumbprint, config.input, config.oldStoreLocation, config.storeLocation);
                Output(ciphertext);
                return RESULT_SUCCESS;
            }
            catch (Exception ex)
            {
                X509CryptoLog.Exception(ex, Criticality.CRITICAL, X509Utils.MethodName());
                return RESULT_EXCEPTION;
            }
        }

        static int EncryptFile()
        {
            try
            {
                X509Utils.EncryptFile(config.thumbprint, config.input, config.storeLocation, config.output);
                if (config.WipeResidualFile)
                    X509Utils.WipeFile(config.input, 10);
                X509CryptoLog.Info(text: string.Format("The file {0} was successfully encrypted using the public key associated with certificate thumbprint {1}\r\n\r\nCiphertext file is: {2}{3}",
                                                       config.input,
                                                       config.thumbprint,
                                                       config.output,
                                                       config.WipeResidualFile ? "\r\n\r\nplaintext file was wiped from disk." : string.Empty),
                                   messageType: X509Utils.MethodName(), writeToEventLog: config.VerboseMode, writeToScreen: config.VerboseMode);

                return RESULT_SUCCESS;
            }
            catch (Exception ex)
            {
                X509CryptoLog.Exception(ex, Criticality.CRITICAL, X509Utils.MethodName());
                return RESULT_EXCEPTION;
            }
        }

        static int ReEncryptFile()
        {
            try
            {
                X509Utils.ReEncryptFile(config.oldThumbprint, config.thumbprint, config.input, config.oldStoreLocation, config.storeLocation);
                X509CryptoLog.Info(text: string.Format("The file {0} was successfully encrypted using the public key associated with certificate thumbprint {1}", 
                                                       config.input, 
                                                       config.thumbprint),
                                   messageType: X509Utils.MethodName(), writeToEventLog: config.VerboseMode, writeToScreen: config.VerboseMode);
                return RESULT_SUCCESS;
            }
            catch (Exception ex)
            {
                X509CryptoLog.Exception(ex, Criticality.CRITICAL, X509Utils.MethodName());
                return RESULT_EXCEPTION;
            }
        }

        [STAThread]
        static int DecryptText()
        {
            string plaintext;

            try
            {
                plaintext = X509Utils.DecryptText(config.thumbprint, config.input, config.storeLocation);
                Output(plaintext);
                return RESULT_SUCCESS;
            }
            catch (Exception ex)
            {
                X509CryptoLog.Exception(ex, Criticality.CRITICAL, X509Utils.MethodName());
                return RESULT_EXCEPTION;
            }
        }

        static int DecryptFile()
        {
            try
            {
                X509Utils.DecryptFile(config.thumbprint, config.input, config.output, config.storeLocation);
                if (config.WipeResidualFile)
                    DeleteFile(config.input);
                X509CryptoLog.Info(text: string.Format("The file {0} was successfully decrypted using the private key associated with certificate thumbprint {1}\r\n\r\nPlaintext file is: {2}{3}",
                                                       config.input,
                                                       config.thumbprint,
                                                       config.output,
                                                       config.WipeResidualFile ? "\r\n\r\nCiphertext file was erased from disk." : string.Empty),
                                   messageType: X509Utils.MethodName(), writeToEventLog: config.VerboseMode, writeToScreen: config.VerboseMode);

                return RESULT_SUCCESS;
            }
            catch (Exception ex)
            {
                X509CryptoLog.Exception(ex, Criticality.CRITICAL, X509Utils.MethodName());
                return RESULT_EXCEPTION;
            }
        }

        static int ImportPFX()
        {
            X509Certificate2Collection certCollection = new X509Certificate2Collection();
            X509Store keyChain;
            bool certAdded = false;

            try
            {
                certCollection.Import(config.input, config.pass, X509KeyStorageFlags.PersistKeySet);
                keyChain = new X509Store(StoreName.My, config.storeLocation.Location);
                keyChain.Open(OpenFlags.ReadWrite);
                foreach(X509Certificate2 cert in certCollection)
                {
                    if (cert.HasPrivateKey)
                    {
                        keyChain.Add(cert);
                        X509CryptoLog.Info(text: string.Format("\r\n\r\nAdded certificate.\r\nThumbprint: {0}\r\nCert Store: {1}", cert.Thumbprint, config.storeLocation.Name), 
                                           messageType: X509Utils.MethodName(), writeToEventLog: config.VerboseMode, writeToScreen: config.VerboseMode);
                        certAdded = true;
                    }
                }

                if (!certAdded)
                    throw new Exception(string.Format("\r\n\r\nPKCS#12 file \"{0}\" contains no private keys.", config.input));

                return RESULT_SUCCESS;
            }
            catch (Exception ex)
            {
                X509CryptoLog.Exception(ex, Criticality.CRITICAL, X509Utils.MethodName());
                return RESULT_EXCEPTION;
            }
        }

        static int ExportPFX()
        {
            try
            {
                X509Utils.ExportPFX(config.thumbprint, config.output, config.pass, config.storeLocation);
                X509CryptoLog.Info(text: string.Format("\r\n\r\nCertificate with thumbprint {0} along with private key was successfully exported to:\r\n{1}", config.thumbprint, config.output),
                                   messageType: X509Utils.MethodName(), writeToEventLog: config.VerboseMode, writeToScreen: config.VerboseMode);
                return RESULT_SUCCESS;
            }
            catch (Exception ex)
            {
                X509CryptoLog.Exception(ex, Criticality.CRITICAL, X509Utils.MethodName());
                return RESULT_EXCEPTION;
            }
        }

        static int ExportCert()
        {
            try
            {
                X509Utils.ExportCert(config.thumbprint, config.output, config.storeLocation);
                X509CryptoLog.Info(text: string.Format("\r\n\r\nCertificate with thumbprint {0} was successfully exported to:\r\n{1}", config.thumbprint, config.output),
                                   messageType: X509Utils.MethodName(), writeToEventLog: config.VerboseMode, writeToScreen: config.VerboseMode);
                return RESULT_SUCCESS;
            }
            catch (Exception ex)
            {
                X509CryptoLog.Exception(ex, Criticality.CRITICAL, X509Utils.MethodName());
                return RESULT_EXCEPTION;
            }
        }

        static int ListCerts()
        {
            try
            {
                string certList = X509Utils.ListCerts(config.storeLocation, config.IncludeExpired);
                X509CryptoLog.Info(text: certList, messageType: X509Utils.MethodName(), writeToEventLog: true, writeToScreen: true);
                return RESULT_SUCCESS;
            }
            catch (Exception ex)
            {
                X509CryptoLog.Exception(ex, Criticality.CRITICAL, X509Utils.MethodName());
                return RESULT_EXCEPTION;
            }
        }

        static int MakeCert()
        {
            try
            {
                string newCertThumbprint = string.Empty;
                X509Utils.MakeCert(config.MakeCert_Subject, config.MakeCert_KeyLength, config.MakeCert_YearsValid, config.storeLocation, out newCertThumbprint);
                X509CryptoLog.Info(text: string.Format("\r\n\r\nCertificate with thumbprint {0} was added to the {1} store", newCertThumbprint, config.storeLocation.Name), 
                                   messageType: X509Utils.MethodName(), writeToEventLog: true, writeToScreen: true);
                return RESULT_SUCCESS;

            }
            catch (Exception ex)
            {
                X509CryptoLog.Exception(ex, Criticality.CRITICAL, X509Utils.MethodName());
                return RESULT_EXCEPTION;
            }
        }

        #endregion

        #region Assist Methods

        [STAThread]
        static void Output(string expression)
        {
            if (config.WriteToFile)
                File.WriteAllText(config.output, expression);
            else
            {
                if (config.UseClipboard)
                    Clipboard.SetText(expression);
                X509CryptoLog.Info(string.Format(@"Result: {0}", config.UseClipboard ? "Written to system clipboard" : expression), writeToScreen: true);
            }
        }

        static void DeleteFile(string path, int triesRemaining = 3)
        {
            try
            {
                File.Delete(path);
            }
            catch (Exception ex)
            {
                if (triesRemaining < 0)
                    DeleteFile(path, --triesRemaining);
                else
                    throw ex;
            }
        }

        #endregion
    }
}
