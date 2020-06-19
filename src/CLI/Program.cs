using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using Org.X509Crypto;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using System.Security;
using System.Text.RegularExpressions;

namespace X509CryptoExe
{
    partial class Program
    {
        private static SecureRandom secureRandom = new SecureRandom();

        private static Mode SelectedMode;
        private static Command SelectedCommand;
        private static bool InCli = false;

        private static string Prompt
        {
            get
            {
                return $"{Constants.AssemblyTitle}{(CurrentlyImpersonating ? $" ({FullyQualifiedImpUser})" : string.Empty)}> ";
            }
        }

        [STAThread]
        static void Main(string[] args)
        {
            //Allow more than 256 characters in Console.ReadLine()
            Console.SetIn(new StreamReader(Console.OpenStandardInput(8192)));

            SelectMode(args);
            if (SelectedMode.ID == Mode.Exit.ID)
            {
                Console.ReadKey();
                return;
            }

            if (SelectedMode.ID == Mode.Cli.ID)
            {
                StartCli();
            }
            else
            {
                EnterMode();

                if (InCli)
                {
                    StartCli();
                }
            }
        }

        private static void SelectMode(string[] args)
        {
            Initialize();

            bool commandSelected = false;
            bool modeSelected = false;
            int index = 0;
            try
            {
                SelectedCommand = Command.Select(args, ref index);
                commandSelected = true;

                SelectedMode = Mode.Select(SelectedCommand, args, InCli, ref index);
                modeSelected = true;

                if (SelectedMode.NeedsParameters)
                {
                    while (index < args.Length)
                    {
                        SelectedMode.GetParameter(args, ref index);
                    }

                    if (!SelectedMode.ParametersSatisfied)
                    {
                        throw new InvalidArgumentsException();
                    }
                }
            }
            catch (Exception ex)
            {
                string usage;
                if (modeSelected)
                {
                    usage = SelectedMode.Usage(SelectedCommand.Name, InCli);
                }
                else
                {
                    usage = commandSelected ? SelectedCommand.Usage(InCli) : Action.Usage(InCli);
                }
                Console.WriteLine($"\r\n{ex.Message}\r\n\r\n{usage}\r\n\r\n");
                SelectedMode = InCli ? Mode.Cli : Mode.Exit;
            }
        }

        private static void Initialize()
        {
            Parameter.Initialize();
            Mode.Initialize();
            Command.Initialize();
        }

        private static void GetInput()
        {
            Console.Write(Prompt);
            string[] args = GetArgs(Console.ReadLine());
            SelectMode(args);
        }

        private static string[] GetArgs(string input)
        {
            string[] args =  RegexPattern.CommandLine.Matches(input)
                                .Cast<Match>()
                                .Select(m => m.Value)
                                .ToArray();

            for (int x=0; x<args.Length; x++)
            {
                if (args[x][0] == '\"' && args[x][args[x].Length - 1] == '\"')
                {
                    args[x] = args[x].Substring(1, args[x].Length - 2);
                }
            }

            return args;
        }

        private static void StartCli()
        {
            InCli = true;
            while (SelectedMode.ID != Mode.Exit.ID)
            {
                GetInput();
                if (CurrentlyImpersonating && SelectedMode.ID != Mode.Impersonate.ID)
                {
                    try
                    {
                        EnterModeImpersonated();
                    }
                    catch (Exception ex)
                    {
                        ConsoleError(@"Unable to enter the selected mode as the impersonated user", ex);
                    }
                }
                else
                {
                    EnterMode();
                }
            }
        }

        private static void EnterMode()
        {
            try
            {
                if (SelectedMode.ID == Mode.EncryptText.ID)
                {
                    EncryptText();
                    return;
                }

                if (SelectedMode.ID == Mode.EncryptFile.ID)
                {
                    EncryptFile();
                    return;
                }

                if (SelectedMode.ID == Mode.DecryptText.ID)
                {
                    DecryptText();
                    return;
                }

                if (SelectedMode.ID == Mode.DecryptFile.ID)
                {
                    DecryptFile();
                    return;
                }

                if (SelectedMode.ID == Mode.ReEncryptText.ID)
                {
                    ReEncryptText();
                    return;
                }

                if (SelectedMode.ID == Mode.ReEncryptFile.ID)
                {
                    ReEncryptFile();
                    return;
                }

                if (SelectedMode.ID == Mode.AddAlias.ID)
                {
                    AddAlias();
                    return;
                }

                if (SelectedMode.ID == Mode.UpdateAlias.ID)
                {
                    UpdateAlias();
                    return;
                }

                if (SelectedMode.ID == Mode.RemoveAlias.ID)
                {
                    RemoveAlias();
                    return;
                }

                if (SelectedMode.ID == Mode.ImportAlias.ID)
                {
                    ImportAlias();
                    return;
                }

                if (SelectedMode.ID == Mode.ExportAlias.ID)
                {
                    ExportAlias();
                    return;
                }

                if (SelectedMode.ID == Mode.DumpAlias.ID)
                {
                    DumpAlias();
                    return;
                }

                if (SelectedMode.ID == Mode.InstallCert.ID)
                {
                    InstallCert();
                    return;
                }

                if (SelectedMode.ID == Mode.MakeCert.ID)
                {
                    MakeCert();
                    return;
                }

                if (SelectedMode.ID == Mode.List.ID)
                {
                    List();
                    return;
                }

                if (SelectedMode.ID == Mode.Impersonate.ID)
                {
                    HandleImpersonate();
                    return;
                }

                if (SelectedMode.ID == Mode.Help.ID)
                {
                    Help();
                    return;
                }

                if (SelectedMode.ID == Mode.Exit.ID)
                {
                    return;
                }
            }
            catch (Exception ex)
            {
                ConsoleError(ex.Message, SelectedMode.Usage(SelectedCommand.Name, InCli));
            }
        }

        #region Mode Execution Methods

        private static void AddAlias()
        {
            try
            {
                string thumbprint = SelectedMode.GetString(Parameter.Thumbprint.ID);
                string aliasName = SelectedMode.GetString(Parameter.AliasToAdd.ID);
                X509Context Context = SelectedMode.GetContext(Parameter.Context.ID);
                X509Alias NewAlias = new X509Alias(aliasName, thumbprint, Context, AllowExistingAlias.No);
                NewAlias.Commit();
                ConsoleMessage($"New {nameof(X509Alias)} {aliasName.InQuotes()} was created in the {Context.Name} {nameof(X509Context)} using certificate with thumbprint {thumbprint.InQuotes()}");
            }
            catch (Exception ex)
            {
                throw new X509CryptoException(@"An exception occurred. The new alias could not be created.", ex);
            }
        }

        private static void RemoveAlias()
        {
            try
            {
                string aliasName = SelectedMode.GetString(Parameter.AliasToRemove.ID);
                X509Context Context = SelectedMode.GetContext(Parameter.Context.ID);

                if (WarnConfirm($"This will ERASE the {nameof(X509Alias)} {aliasName.InQuotes()} from the {Context.Name} {nameof(X509Context)} on this computer."))
                {
                    X509Alias AliasToRemove = new X509Alias(aliasName, Context);
                    AliasToRemove.Remove();
                    ConsoleMessage($"{nameof(X509Alias)} {aliasName.InQuotes()} was removed from the {Context.Name} {nameof(X509Context)}.");
                }
            }
            catch (Exception ex)
            {
                throw new X509CryptoException(@"Unable to remove the specified alias", ex);
            }
        }

        private static void UpdateAlias()
        {
            try
            {
                string aliasName = SelectedMode.GetString(Parameter.AliasToUpdate.ID);
                string newThumbprint = SelectedMode.GetString(Parameter.Thumbprint.ID);
                X509Context OldContext = SelectedMode.GetContext(Parameter.OldContext.ID);
                X509Context NewContext = SelectedMode.GetContext(Parameter.NewContext.ID, OldContext);

                if (!X509CryptoAgent.CertificateExists(newThumbprint, NewContext))
                {
                    throw new X509CryptoCertificateNotFoundException(newThumbprint, NewContext);
                }

                X509Alias Alias = new X509Alias(aliasName, OldContext);
                Alias.ReEncrypt(newThumbprint, NewContext);
                Alias.Commit();
                ConsoleMessage($"{nameof(X509Alias)} {aliasName} successfully updated. Now using encryption certificate with thumbprint {newThumbprint} from the {NewContext.Name} {nameof(X509Context)}");
            }
            catch (Exception ex)
            {
                if (ex is X509CryptoCertificateNotFoundException)
                {
                    throw;
                }
                else
                {
                    throw new X509CryptoException(@"Unable to update the specified alias", ex);
                }
            }
        }

        private static void ImportAlias()
        {
            try
            {
                string aliasName = Parameter.AliasToImport.IsDefined ? SelectedMode.GetString(Parameter.AliasToImport.ID) : string.Empty;
                string inFile = SelectedMode.GetString(Parameter.InImportAlias.ID);
                bool overwriteExisting = SelectedMode.GetBool(Parameter.OverWriteExistingAlias.ID);
                X509Context Context = SelectedMode.GetContext(Parameter.Context.ID);

                X509Alias AliasToImport = X509Alias.Import(inFile, Context, aliasName);
                if (!overwriteExisting && X509Alias.AliasExists(AliasToImport))
                {
                    throw new X509AliasAlreadyExistsException(AliasToImport);
                }
                AliasToImport.Commit();
                ConsoleMessage($"{nameof(X509Alias)} {aliasName.InQuotes()} has been successfully imported into the {Context.Name} {nameof(X509Context)} from the file {inFile.InQuotes()}");

                if (!X509CryptoAgent.CertificateExists(AliasToImport))
                {
                    ConsoleWarning($"An encryption certificate with thumbprint {AliasToImport.Thumbprint.InQuotes()} could not be found in the {Context.Name} {nameof(X509Context)}. Ensure this certificate is installed on the system before using this alias.");
                }
            }
            catch (Exception ex)
            {
                if (ex is X509AliasAlreadyExistsException)
                {
                    throw;
                }
                else
                {
                    throw new X509CryptoException(@"Unable to import the specified alias", ex);
                }
            }
        }

        private static void ExportAlias()
        {
            string aliasName = string.Empty;
            string outfile = string.Empty;

            try
            {
                aliasName = SelectedMode.GetString(Parameter.AliasToExport.ID);
                outfile = SelectedMode.GetString(Parameter.OutExportAlias.ID);
                bool overwriteExisting = SelectedMode.GetBool(Parameter.OverWriteExistingFile.ID);
                X509Context Context = SelectedMode.GetContext(Parameter.Context.ID);

                X509Alias Alias = new X509Alias(aliasName, Context);
                Alias.Export(outfile, overwriteExisting);
                ConsoleMessage($"{nameof(X509Alias)} aliasName was successfully exported to file {outfile.InQuotes()}");
            }
            catch (FileNotFoundException)
            {
                throw;
            }
            catch (X509CryptoException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new X509CryptoException($"An exception occurred when attempting to export the {nameof(X509Alias)}", ex);
            }
        }

        [STAThread]
        static void EncryptText()
        {
            bool secretAdded = false;
            string ciphertext = string.Empty;
            string outfile = string.Empty;
            string aliasName = string.Empty;
            string secretName = string.Empty;
            string plaintext = string.Empty;
            X509Context Context = null;

            try
            {
                aliasName = SelectedMode.GetString(Parameter.AliasEnc.ID);
                Context = SelectedMode.GetContext(Parameter.Context.ID);
                plaintext = SelectedMode.GetString(Parameter.InEncText.ID);
                using (X509Alias Alias = new X509Alias(aliasName, Context))
                {
                    if (Parameter.SecretEnc.IsDefined)
                    {
                        secretName = SelectedMode.GetString(Parameter.SecretEnc.ID);
                        ciphertext = Alias.EncryptText(plaintext);
                        secretAdded = AddSecret(secretName, ciphertext, Alias);
                    }
                }

                if (!secretAdded)
                {
                    WriteOutput(ciphertext, Parameter.OutEncText.ID, Samples.Ciphertext);
                }
            }
            catch (Exception ex)
            {
                throw new X509CryptoException($"An exception occurred when attempting to export the {nameof(X509Alias)}", ex);
            }
        }

        [STAThread]
        static void DecryptText()
        {
            string plaintext = string.Empty;
            string ciphertext = string.Empty;
            string outfile = string.Empty;
            string aliasName = string.Empty;
            string secretName = string.Empty;
            X509Context Context = null;

            try
            {
                if (!(Parameter.SecretDec.IsDefined ^ Parameter.InDecText.IsDefined))
                {
                    throw new X509CryptoException($"Either {Parameter.SecretDec.Name.InQuotes()} or {Parameter.InDecText.Name.InQuotes()} must be defined, but not both.");
                }

                aliasName = SelectedMode.GetString(Parameter.AliasDec.ID);
                Context = SelectedMode.GetContext(Parameter.Context.ID);
                using (X509Alias Alias = new X509Alias(aliasName, Context))
                {
                    if (Parameter.SecretDec.IsDefined)
                    {
                        secretName = SelectedMode.GetString(Parameter.SecretDec.ID);
                        plaintext = Alias.RecoverSecret(secretName);
                    }
                    else
                    {
                        ciphertext = SelectedMode.GetString(Parameter.InDecText.ID);
                        plaintext = Alias.DecryptText(ciphertext);
                    }
                }

                WriteOutput(plaintext, Parameter.OutDecText.ID, Samples.Plaintext);
            }
            catch (Exception ex)
            {
                throw new X509CryptoException(@"Unable to decrypt the specified expression or secret", ex);
            }
        }

        [STAThread]
        private static void ReEncryptText()
        {
            bool secretAdded = false;
            string oldCiphertext = string.Empty;
            string newCiphertext = string.Empty;
            string oldAliasName = string.Empty;
            string targetAliasName = string.Empty;
            string secretName = string.Empty;
            string outfile = string.Empty;
            X509Context OldContext = null;
            X509Context TargetContext = null;
            X509Alias OldAlias = null;
            X509Alias TargetAlias = null;

            try
            {
                oldAliasName = SelectedMode.GetString(Parameter.OldAlias.ID);
                targetAliasName = SelectedMode.GetString(Parameter.NewAlias.ID);
                OldContext = SelectedMode.GetContext(Parameter.OldContext.ID);
                TargetContext = SelectedMode.GetContext(Parameter.TargetContext.ID);
                OldAlias = new X509Alias(oldAliasName, OldContext);
                TargetAlias = new X509Alias(targetAliasName, TargetContext);
                newCiphertext = TargetAlias.ReEncryptSecret(secretName, OldAlias);

                if (Parameter.SecretReEnc.IsDefined)
                {
                    secretName = SelectedMode.GetString(Parameter.SecretReEnc.ID);
                    secretAdded = AddSecret(secretName, newCiphertext, TargetAlias);
                }

                if (!secretAdded)
                {
                    WriteOutput(newCiphertext, Parameter.OutEncText.ID, Samples.Ciphertext);
                }
            }
            catch (Exception ex)
            {
                ConsoleError(@"Unable to re-encrypt the specified expression", SelectedMode.Usage(SelectedCommand.Name, InCli), ex);
            }
        }

        private static void EncryptFile()
        {
            int wipeTimesToWrite = 0;
            string inFile = string.Empty;
            string outfile = string.Empty;
            string aliasName = string.Empty;
            bool overwriteExisting = false;
            X509Context Context = null;

            try
            {
                inFile = SelectedMode.GetString(Parameter.InEncFile.ID);
                if (Parameter.OutEncFile.IsDefined)
                {
                    outfile = SelectedMode.GetString(Parameter.OutEncFile.ID);
                }
                else
                {
                    outfile = $"{inFile}{FileExtensions.Ciphertext}";
                }

                overwriteExisting = SelectedMode.GetBool(Parameter.OverWriteExistingFile.ID);
                CheckForExistingFile(outfile, overwriteExisting);

                if (Parameter.Wipe.IsDefined)
                {
                    if (!WarnConfirm($"You have included the {Parameter.Wipe.Name.InQuotes()} argument. This will permanently delete the file {inFile.InQuotes()} from disk."))
                    {
                        return;
                    }
                    else
                    {
                        wipeTimesToWrite = SelectedMode.GetInt(Parameter.Wipe.ID);
                    }
                }

                aliasName = SelectedMode.GetString(Parameter.AliasEnc.ID);
                Context = SelectedMode.GetContext(Parameter.Context.ID);
                using (X509Alias Alias = new X509Alias(aliasName, Context))
                {
                    Alias.EncryptFile(inFile, outfile, wipeTimesToWrite);
                }
                StringBuilder Expression = new StringBuilder($"The file {inFile.InQuotes()} was successfully encrypted. The ciphertext file name is {outfile.InQuotes()}");
                if (Parameter.Wipe.IsDefined)
                {
                    Expression.Append($"\r\nThe plaintext file has also been erased from disk");
                }
                ConsoleMessage(Expression.ToString());
            }
            catch (Exception ex)
            {
                throw new X509CryptoException(@"Unable to encrypt the specified file", ex);
            }
        }

        private static void DecryptFile()
        {
            int wipeTimesToWrite = 0;
            bool overwriteExistingFile = false;
            string outfile = string.Empty;
            string aliasName = string.Empty;
            X509Context Context = null;
            string infile = string.Empty;

            try
            {
                aliasName = SelectedMode.GetString(Parameter.AliasDec.ID);
                Context = SelectedMode.GetContext(Parameter.Context.ID);
                infile = SelectedMode.GetString(Parameter.InDecFile.ID);
                overwriteExistingFile = SelectedMode.GetBool(Parameter.OverWriteExistingFile.ID);

                if (SelectedMode.IsParameterDefined(Parameter.OutDecFile.ID))
                {
                    outfile = SelectedMode.GetString(Parameter.OutDecFile.ID);
                }
                else
                {
                    outfile = GetPlaintextFilename(infile);
                }
                CheckForExistingFile(outfile, overwriteExistingFile);

                if (SelectedMode.IsParameterDefined(Parameter.Wipe.ID))
                {
                    if (!WarnConfirm($"You have included the {Parameter.Wipe.Name.InQuotes()} argument. This will permanently delete the file {infile.InQuotes()} from disk."))
                    {
                        return;
                    }
                    else
                    {
                        wipeTimesToWrite = SelectedMode.GetInt(Parameter.Wipe.ID);
                    }
                }

                X509Alias Alias = new X509Alias(aliasName, Context);
                Alias.DecryptFile(infile, outfile, wipeTimesToWrite);
                StringBuilder Expression = new StringBuilder($"The file {infile.InQuotes()} was successfully decrypted. The recovered file name is {outfile.InQuotes()}");
                if (Parameter.Wipe.IsDefined)
                {
                    Expression.Append($"\r\nThe ciphertext file has also been erased from disk");
                }
                ConsoleMessage(Expression.ToString());
            }
            catch (Exception ex)
            {
                throw new X509CryptoException(@"Unable to decrypt the specified file", ex);
            }
        }

        private static void ReEncryptFile()
        {
            string oldAliasName = string.Empty;
            string newAliasName = string.Empty;
            string infile = string.Empty;
            X509Alias OldAlias = null;
            X509Alias NewAlias = null;
            X509Context OldContext = null;
            X509Context NewContext = null;

            try
            {
                oldAliasName = SelectedMode.GetString(Parameter.OldAlias.ID);
                newAliasName = SelectedMode.GetString(Parameter.NewAliasReEnc.ID);
                OldContext = SelectedMode.GetContext(Parameter.OldContext.ID);
                NewContext = SelectedMode.GetContext(Parameter.NewContext.ID);
                infile = SelectedMode.GetString(Parameter.InReEncFile.ID);

                OldAlias = new X509Alias(oldAliasName, OldContext);
                NewAlias = new X509Alias(newAliasName, NewContext);
                X509Utils.ReEncryptFile(OldAlias, NewAlias, infile);

                ConsoleMessage($"The file {infile.InQuotes()} was successfully re-encrypted using the X509Crypto alias {newAliasName.InQuotes()} located in the {NewContext.Name.InQuotes()} {nameof(X509Context)}");
            }
            catch (Exception ex)
            {
                throw new X509CryptoException(@"Unable to re-encrypt the specified file", ex);
            }
        }

        [STAThread]
        private static void List()
        {
            string output = string.Empty;
            string outfile = string.Empty;
            string listType = string.Empty;
            X509Context Context = null;

            try
            {
                listType = SelectedMode.GetString(Parameter.ListType.ID);
                Context = SelectedMode.GetContext(Parameter.Context.ID);

                switch (listType)
                {
                    case ListType.Certs:
                        output = X509CryptoAgent.ListCerts(SelectedMode.GetContext(Parameter.Context.ID));
                        break;
                    case ListType.Aliases:
                        output = X509CryptoAgent.ListAliases(SelectedMode.GetContext(Parameter.Context.ID));
                        break;
                    default:
                        throw new X509CryptoException($"{listType}: Unsupported list type.");
                }
                WriteOutput(output, Parameter.OutList.ID);
            }
            catch (X509CryptoException ex)
            {
                throw ex;
            }
            catch (Exception ex)
            {
                throw new X509CryptoException(@"An exception occurred attempting to generate the list", ex);
            }
        }

        [STAThread]
        private static void DumpAlias()
        {
            string output = string.Empty;
            string aliasName = string.Empty;
            X509Context Context = null;
            bool reveal = false;

            try
            {
                aliasName = SelectedMode.GetString(Parameter.AliasToDump.ID);
                Context = SelectedMode.GetContext(Parameter.Context.ID);
                reveal = SelectedMode.GetBool(Parameter.Reveal.ID);

                using (X509Alias Alias = new X509Alias(aliasName, Context))
                {
                    output = SelectedMode.OutputType == Output.File ? Alias.DumpSecretsCSV(reveal) : Alias.DumpSecrets(reveal);
                }
                WriteOutput(output, Parameter.OutDumpAlias.ID);
            }
            catch (Exception ex)
            {
                throw new X509CryptoException($"Unable to dump the specified {nameof(X509Alias)}", ex);
            }
        }

        private static void InstallCert()
        {
            string infile = string.Empty;
            string thumbprint = string.Empty;
            X509Context Context = null;

            try
            {
                infile = SelectedMode.GetString(Parameter.InInstallCert.ID);
                Context = SelectedMode.GetContext(Parameter.Context.ID);
                SecureString PfxPassword = GetSecret($"Enter the password to unlock {Path.GetFileName(infile).InQuotes()}");
                thumbprint = X509Utils.InstallCert(infile, PfxPassword, Context);
                ConsoleMessage($"Added encryption certificate to the {Context.Name} {nameof(X509Context)}. \r\nCertificate Thumbprint: {thumbprint}");
            }
            catch (Exception ex)
            {
                throw new X509CryptoException(@"Unable to install the specified certificate", ex);
            }
        }

        private static void MakeCert()
        {
            string subject = string.Empty;
            string keySize = string.Empty;
            string thumbprint = string.Empty;
            int keyLength = Constants.DefaultKeyLength;
            int yearsValid = Constants.DefaultYearsValid;
            X509Context Context = null;

            try
            {
                Context = SelectedMode.GetContext(Parameter.Context.ID);

                if (SelectedMode.IsParameterDefined(Parameter.MakeCertSubject.ID))
                {
                    subject = SelectedMode.GetString(Parameter.MakeCertSubject.ID);
                }
                else
                {
                    subject = Context.Name.Matches(X509Context.UserReadOnly.Name) ? Environment.UserName : Environment.MachineName;
                }

                if (SelectedMode.IsParameterDefined(Parameter.MakeCertKeySize.ID))
                {
                    keySize = SelectedMode.GetString(Parameter.MakeCertKeySize.ID);
                    switch (keySize)
                    {
                        case KeySize.Small:
                            keyLength = KeyLength.Small;
                            break;
                        case KeySize.Medium:
                            keyLength = KeyLength.Medium;
                            break;
                        case KeySize.Large:
                            keyLength = KeyLength.Large;
                            break;
                        default:
                            throw new InvalidArgumentsException(Parameter.MakeCertKeySize.Name, keySize);
                    }
                }

                if (SelectedMode.IsParameterDefined(Parameter.MakeCertYearsValid.ID))
                {
                    yearsValid = SelectedMode.GetInt(Parameter.MakeCertYearsValid.ID);
                }

                MakeCertWorker(subject, keyLength, yearsValid, Context, out thumbprint);
                ConsoleMessage($"Certificate with thumbprint {thumbprint} was added to the {Context.Name} {nameof(X509Context)}");
            }
            catch (Exception ex)
            {
                ConsoleError($"An exception occurred attempting to generate a new encryption certificate", ex);
            }
        }

        private static void Help()
        {
            ConsoleMessage(Action.Usage(InCli));
        }

        #endregion

        

        private static void WriteOutput(string output, int paramID, string prefix = "")
        {
            string outfile = string.Empty;
            switch (SelectedMode.OutputType)
            {
                case Output.Clipboard:
                    Clipboard.SetText(output);
                    ConsoleMessage(@"Output written to system clipboard.");
                    break;
                case Output.File:
                    outfile = SelectedMode.GetString(paramID);
                    File.WriteAllText(outfile, output);
                    ConsoleMessage($"Output written to path: {outfile.InQuotes()}");
                    break;
                default:
                    if (string.IsNullOrEmpty(prefix))
                    {
                        ConsoleMessage(output);
                    }
                    else
                    {
                        ConsoleMessage($"\r\n{prefix}:\r\n{output}");
                    }
                    break;

            }
        }

        #region Console Output Methods

        private static void ConsoleError(string message, Exception ex = null)
        {
            StringBuilder Expression = new StringBuilder($"\r\n{message}\r\n");
            if (ex != null)
            {
                Expression.Append($"\r\nException Details: \r\n{ex.ToString()}\r\n");
            }
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(Expression.ToString());
        }

        private static void ConsoleError(string message, string usage, Exception ex = null)
        {
            ConsoleError(message, ex);

            Console.ResetColor();
            Console.WriteLine($"{usage}\r\n");
        }

        private static void ConsoleMessage(string message)
        {
            Console.WriteLine($"\r\n{message}\r\n");
        }

        private static void ConsoleWarning(string message)
        {
            Console.WriteLine($"\r\n{message}\r\n", ConsoleColor.Yellow);
        }

        private static bool WarnConfirm(string message)
        {
            string entry = string.Empty;

            Console.WriteLine($"\r\nWARNING! {message} Enter {Constants.Affirm.InQuotes()} if you wish to proceed", ConsoleColor.Yellow);
            Console.Write(@"Your entry: ");
            entry = Console.ReadLine();
            if (entry.Matches(Constants.Affirm, caseSensitive: true))
            {
                return true;
            }
            else
            {
                ConsoleMessage(@"No action was taken.");
                return false;
            }
        }

        #endregion

        #region MakeCert Support Methods

        static void MakeCertWorker(string name, int keyLength, int yearsValid, X509Context Context, out string thumbprint)
        {
            X509Certificate2 dotNetCert = null;
            AsymmetricCipherKeyPair keyPair = GenerateRsaKeyPair(keyLength);
            string formattedName = FormatX500(name);
            X509Name issuer = new X509Name(formattedName);
            X509Name subject = new X509Name(formattedName);

            ISignatureFactory signatureFactory;
            if (keyPair.Private is ECPrivateKeyParameters)
            {
                signatureFactory = new Asn1SignatureFactory(
                    X9ObjectIdentifiers.ECDsaWithSha256.ToString(),
                    keyPair.Private);
            }
            else
            {
                signatureFactory = new Asn1SignatureFactory(
                    PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString(),
                    keyPair.Private);
            }

            var certGenerator = new X509V3CertificateGenerator();
            certGenerator.SetIssuerDN(issuer);
            certGenerator.SetSubjectDN(subject);
            certGenerator.SetSerialNumber(BigInteger.ValueOf(1));
            certGenerator.SetNotAfter(DateTime.UtcNow.AddYears(yearsValid));
            certGenerator.SetNotBefore(DateTime.UtcNow);
            certGenerator.SetPublicKey(keyPair.Public);
            certGenerator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyEncipherment));
            Org.BouncyCastle.X509.X509Certificate cert = certGenerator.Generate(signatureFactory);

            var bouncyStore = new Pkcs12Store();
            var certEntry = new X509CertificateEntry(cert);
            string friendlyName = cert.SubjectDN.ToString();
            bouncyStore.SetCertificateEntry(friendlyName, certEntry);
            bouncyStore.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(keyPair.Private), new[] { certEntry });
            char[] pass = RandomPass();

            using (MemoryStream stream = new MemoryStream())
            {
                bouncyStore.Save(stream, pass, secureRandom);
                dotNetCert = new X509Certificate2(stream.ToArray(), new string(pass), X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
                thumbprint = dotNetCert.Thumbprint;
                stream.Close();
            }

            X509Store dotNetStore = new X509Store(Context.Location);
            dotNetStore.Open(OpenFlags.ReadWrite);
            dotNetStore.Add(dotNetCert);

            bool added = false;
            foreach (X509Certificate2 certInStore in dotNetStore.Certificates)
            {
                if (certInStore.Thumbprint == thumbprint)
                    added = true;
            }

            if (!added)
                throw new Exception($"A certificate could not be added to the {Context.Name} {nameof(X509Context)}.");
        }

        private static AsymmetricCipherKeyPair GenerateRsaKeyPair(int length)
        {
            var keygenParam = new KeyGenerationParameters(secureRandom, length);

            var keyGenerator = new RsaKeyPairGenerator();
            keyGenerator.Init(keygenParam);
            return keyGenerator.GenerateKeyPair();
        }

        private static string FormatX500(string name)
        {
            if (!string.Equals(@"cn=", name.Substring(0, 3), StringComparison.OrdinalIgnoreCase))
                name = string.Format(@"cn={0}", name);
            name = name.Replace(",", "\\,");
            return name;
        }

        private static char[] RandomPass()
        {
            const string chars = @"ABCDEFGHIJKLMOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()-=+";
            int length = secureRandom.Next(10, 20);
            return Enumerable.Repeat(chars, length).Select(s => s[secureRandom.Next(s.Length)]).ToArray();
        }

        #endregion

        //#region Assist Methods

        //[STAThread]
        //static void Output(string expression)
        //{
        //    if (config.WriteToFile)
        //        File.WriteAllText(config.output, expression);
        //    else
        //    {
        //        if (config.UseClipboard)
        //            Clipboard.SetText(expression);
        //        X509CryptoLog.Info(string.Format(@"Result: {0}", config.UseClipboard ? "Written to system clipboard" : expression), writeToScreen: true);
        //    }
        //}

        //static void DeleteFile(string path, int triesRemaining = 3)
        //{
        //    try
        //    {
        //        File.Delete(path);
        //    }
        //    catch (Exception ex)
        //    {
        //        if (triesRemaining < 0)
        //            DeleteFile(path, --triesRemaining);
        //        else
        //            throw ex;
        //    }
        //}

        //static void Initialize()
        //{
        //    Parameter.Initialize();
        //    Mode.Initialize();
        //    Command.Initialize();
        //}

        //#endregion
    }
}
