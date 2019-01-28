using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using x509Crypto;

namespace x509CryptoExe
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

        static int Main(string[] args)
        {
            try
            {
                config = new Config(args);
            }
            catch (Exception ex)
            {
                x509CryptoLog.Exception(ex, Criticality.CRITICAL, @"Config");
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
                ciphertext = x509Utils.EncryptText(config.thumbprint, config.input, config.storeLocation);
                Output(ciphertext);
                return RESULT_SUCCESS;
            }
            catch (Exception ex)
            {
                x509CryptoLog.Exception(ex, Criticality.CRITICAL, MethodName());
                return RESULT_EXCEPTION;
            }
        }

        [STAThread]
        static int ReEncryptText()
        {
            string ciphertext;

            try
            {
                ciphertext = x509Utils.ReEncryptText(config.oldThumbprint, config.oldStoreLocation, config.thumbprint, config.storeLocation, config.input);
                Output(ciphertext);
                return RESULT_SUCCESS;
            }
            catch (Exception ex)
            {
                x509CryptoLog.Exception(ex, Criticality.CRITICAL, MethodName());
                return RESULT_EXCEPTION;
            }
        }

        static int EncryptFile()
        {
            try
            {
                x509Utils.EncryptFile(config.thumbprint, config.input, config.output, config.storeLocation);
                if (config.WipeResidualFile)
                    x509Utils.WipeFile(config.input, 10);
                x509CryptoLog.Info(text: string.Format("The file {0} was successfully encrypted using the public key associated with certificate thumbprint {1}\r\n\r\nCiphertext file is: {2}{3}",
                                                       config.input,
                                                       config.thumbprint,
                                                       config.output,
                                                       config.WipeResidualFile ? "\r\n\r\nplaintext file was wiped from disk." : string.Empty),
                                   messageType: MethodName(), writeToEventLog: true, writeToScreen: true);

                return RESULT_SUCCESS;
            }
            catch (Exception ex)
            {
                x509CryptoLog.Exception(ex, Criticality.CRITICAL, MethodName());
                return RESULT_EXCEPTION;
            }
        }

        static int ReEncryptFile()
        {
            try
            {
                x509Utils.ReEncryptFile(config.oldThumbprint, config.oldStoreLocation, config.thumbprint, config.storeLocation, config.input);
                x509CryptoLog.Info(text: string.Format("The file {0} was successfully encrypted using the public key associated with certificate thumbprint {1}", config.input, config.thumbprint), writeToEventLog: true, writeToScreen: true);
                return RESULT_SUCCESS;
            }
            catch (Exception ex)
            {
                x509CryptoLog.Exception(ex, Criticality.CRITICAL, MethodName());
                return RESULT_EXCEPTION;
            }
        }

        [STAThread]
        static int DecryptText()
        {
            string plaintext;

            try
            {
                plaintext = x509Utils.DecryptText(config.thumbprint, config.input, config.storeLocation);
                Output(plaintext);
                return RESULT_SUCCESS;
            }
            catch (Exception ex)
            {
                x509CryptoLog.Exception(ex, Criticality.CRITICAL, MethodName());
                return RESULT_EXCEPTION;
            }
        }

        static int DecryptFile()
        {
            try
            {
                x509Utils.DecryptFile(config.thumbprint, config.input, config.output, config.storeLocation);
                if (config.WipeResidualFile)
                    DeleteFile(config.input);
                x509CryptoLog.Info(text: string.Format("The file {0} was successfully decrypted using the private key associated with certificate thumbprint {1}\r\n\r\nPlaintext file is: {2}{3}",
                                                       config.input,
                                                       config.thumbprint,
                                                       config.output,
                                                       config.WipeResidualFile ? "\r\n\r\nCiphertext file was erased from disk." : string.Empty),
                                   messageType: MethodName(), writeToEventLog: true, writeToScreen: true);

                return RESULT_SUCCESS;
            }
            catch (Exception ex)
            {
                x509CryptoLog.Exception(ex, Criticality.CRITICAL, MethodName());
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
                        x509CryptoLog.Info(text: string.Format("\r\n\r\nAdded certificate.\r\nThumbprint: {0}\r\nCert Store: {1}", cert.Thumbprint, config.storeLocation.Name), messageType: MethodName(), writeToEventLog: true, writeToScreen: true);
                        certAdded = true;
                    }
                }

                if (!certAdded)
                    throw new Exception(string.Format("\r\n\r\nPKCS#12 file \"{0}\" contains no private keys.", config.input));

                return RESULT_SUCCESS;
            }
            catch (Exception ex)
            {
                x509CryptoLog.Exception(ex, Criticality.CRITICAL, MethodName());
                return RESULT_EXCEPTION;
            }
        }

        static int ExportPFX()
        {
            try
            {
                x509Utils.ExportPFX(config.thumbprint, config.storeLocation, config.output, config.pass);
                x509CryptoLog.Info(text: string.Format("\r\n\r\nCertificate with thumbprint {0} along with private key was successfully exported to:\r\n{1}", config.thumbprint, config.output),
                                   messageType: MethodName(), writeToEventLog: true, writeToScreen: true);
                return RESULT_SUCCESS;
            }
            catch (Exception ex)
            {
                x509CryptoLog.Exception(ex, Criticality.CRITICAL, MethodName());
                return RESULT_EXCEPTION;
            }
        }

        static int ExportCert()
        {
            try
            {
                x509Utils.ExportCert(config.thumbprint, config.storeLocation, config.output);
                x509CryptoLog.Info(text: string.Format("\r\n\r\nCertificate with thumbprint {0} was successfully exported to:\r\n{1}", config.thumbprint, config.output),
                                   messageType: MethodName(), writeToEventLog: true, writeToScreen: true);
                return RESULT_SUCCESS;
            }
            catch (Exception ex)
            {
                x509CryptoLog.Exception(ex, Criticality.CRITICAL, MethodName());
                return RESULT_EXCEPTION;
            }
        }

        static int ListCerts()
        {
            try
            {
                string certList = x509Utils.listCerts(config.storeLocation, config.IncludeExpired);
                x509CryptoLog.Info(text: certList, messageType: MethodName(), writeToEventLog: true, writeToScreen: true);
                return RESULT_SUCCESS;
            }
            catch (Exception ex)
            {
                x509CryptoLog.Exception(ex, Criticality.CRITICAL, MethodName());
                return RESULT_EXCEPTION;
            }
        }

        static int MakeCert()
        {
            try
            {
                string newCertThumbprint = string.Empty;
                x509Utils.MakeCert(config.MakeCert_Subject, config.MakeCert_KeyLength, config.MakeCert_YearsValid, config.storeLocation, out newCertThumbprint);
                x509CryptoLog.Info(text: string.Format(@"\r\n\r\nCertificate with thumbprint {0} was added to the {1} store", newCertThumbprint, config.storeLocation.Name), 
                                   messageType: MethodName(), writeToEventLog: true, writeToScreen: true);
                return RESULT_SUCCESS;

            }
            catch (Exception ex)
            {
                x509CryptoLog.Exception(ex, Criticality.CRITICAL, MethodName());
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
                x509CryptoLog.Info(string.Format(@"Result: {0}", config.UseClipboard ? "Written to system clipboard" : expression), writeToScreen: true);
            }
        }

        static string MethodName()
        {
            return new StackTrace(1).GetFrame(0).GetMethod().Name;
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
