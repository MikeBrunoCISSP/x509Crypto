using Org.X509Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace X509CryptoExe
{
    internal enum Output
    {
        File = 0,
        Clipboard = 1,
        Screen = 2
    }

    internal class Mode
    {
        internal static List<Mode> Collection = new List<Mode>();

        private string name;
        internal string Name
        {
            get
            {
                return name.AsKey();
            }
            private set
            {
                name = value;
            }
        }

        internal int ID { get; private set; }
        internal string Description { get; private set; }
        internal bool IsDefault { get; private set; } = false;

        internal Output OutputType
        {
            get
            {
                if (UseClipboard)
                {
                    return Output.Clipboard;
                }
                if (OutToFile)
                {
                    return Output.File;
                }
                else
                {
                    return Output.Screen;
                }
            }
        }

        internal bool UseClipboard { get; set; } = false;
        private bool OutToFile { get; set; } = false;
        internal bool UnrecognizedExpressionEncountered { get; private set; } = false;

        internal List<Parameter> Parameters { get; private set; } = new List<Parameter>();

        internal bool NeedsParameters
        {
            get
            {
                return Parameters.Count > 0;
            }
        }

        internal bool ParametersSatisfied
        {
            get
            {
                if (!NeedsParameters)
                {
                    return true;
                }
                else
                {
                    return !Parameters.Any(p => !p.Satisfied);
                }
            }
        }

        public override string ToString()
        {
            return Name;
        }

        internal string ShowDescription(int padLength)
        {
            return $"{Name.AsKey()}: {Description}".Align(UsageIndent.Mode, padLength);
        }

        internal string Usage(string commandName, bool inCLI)
        {
            List<Parameter> RequiredParams;
            List<Parameter> OptionalParams;
            StringBuilder Expression = new StringBuilder(UsageExpression.Prefix);

            if (!inCLI)
            {
                Expression.Append($"{Constants.AssemblyFile} ");
            }

            Expression.Append(commandName);

            if (!IsDefault)
            {
                Expression.Append($" {Name}");
            }

            if (!IsDefault)
            {
                Expression.Append($" {Name}");
            }

            //Required Parameters
            RequiredParams = Parameters.Where(p => p.DefinitionRequired).ToList();
            if (RequiredParams.Count() > 0)
            {
                RequiredParams.ForEach(p => Expression.Append(p.CliSyntax()));
            }

            //Optional Parameters
            OptionalParams = Parameters.Where(p => !p.DefinitionRequired).ToList();
            if (OptionalParams.Count() > 0)
            {
                Expression.Append(" ");
                StringBuilder tmp = new StringBuilder(string.Empty);
                OptionalParams.ForEach(p => tmp.Append(p.CliSyntax()));
                tmp.Append(" ");
                Expression.Append(tmp.ToString().InBraces());
            }

            if (Parameters.Count > 0)
            {
                int padding = Parameters.Select(p => p.Name).GetPadding();
                Expression.Append($"\r\n{UsageExpression.RequiredParameters}");

                RequiredParams.ForEach(p => Expression.Append(p.DetailedUsage(padding)));

                if (OptionalParams.Count > 0)
                {
                    Expression.Append(UsageExpression.OptionalParameters);
                    OptionalParams.ForEach(p => Expression.Append(p.DetailedUsage(padding)));
                }
            }

            return Expression.ToString();
        }

        internal void GetParameter(string[] args, ref int index)
        {
            if (!NeedsParameters)
            {
                throw new UnrecognizedExpressionException(args[index]);
            }

            try
            {
                bool recognized = false;
                foreach (Parameter param in Parameters)
                {
                    if (param.Name.Matches(args[index]))
                    {
                        recognized = true;
                        index++;
                        param.TryDefine(args, ref index);
                        if (param.IsPath && param.IsDefined)
                        {
                            UseClipboard = UseClipboard || param.UseClipboard;
                            OutToFile = OutToFile || param.OutToFile;
                        }
                        break;
                    }
                }

                if (!recognized)
                {
                    throw new UnrecognizedExpressionException(args[index]);
                }
            }
            catch (Exception ex)
            {
                if (ex is IndexOutOfRangeException)
                {
                    throw new InvalidArgumentsException();
                }
                else
                {
                    throw ex;
                }
            }
        }

        internal string GetString(int id)
        {
            try
            {
                return Parameters.First(p => p.ID == id).TextValue;
            }
            catch (Exception)
            {
                throw new ParameterNotSupportedException(Name);
            }
        }

        internal bool GetBool(int id)
        {
            try
            {
                return Parameters.Where(p => p.IsBool)
                                 .First(p => p.ID == id).BoolValue;
            }
            catch (Exception)
            {
                throw new ParameterNotSupportedException(Name);
            }
        }

        internal int GetInt(int id)
        {
            try
            {
                return Parameters.Where(p => p.IsInt)
                                 .First(p => p.ID == id).IntValue;
            }
            catch (Exception)
            {
                throw new ParameterNotSupportedException(Name);
            }
        }

        internal bool IsParameterDefined(int id)
        {
            try
            {
                return Parameters.First(p => p.ID == id).IsDefined;
            }
            catch (Exception)
            {
                throw new ParameterNotSupportedException(Name);
            }
        }

        internal X509Context GetContext(int id, X509Context DefaultContext = null)
        {
            try
            {
                return Parameters.Where(p => p.IsDefined && p.IsContext)
                                 .First(p => p.ID == id).SelectedContext;
            }
            catch (Exception)
            {
                if (DefaultContext != null)
                {
                    return DefaultContext;
                }
                else
                {
                    throw new InvalidX509ContextNameException();
                }
            }
        }

        internal static Mode EncryptText,
                             EncryptFile,
                             DecryptText,
                             DecryptFile,
                             ReEncryptText,
                             ReEncryptFile,
                             AddAlias,
                             UpdateAlias,
                             RemoveAlias,
                             ImportAlias,
                             ExportAlias,
                             DumpAlias,
                             InstallCert,
                             MakeCert,
                             List,
                             Impersonate,
                             Help,
                             Cli,
                             Exit;

        internal static void Initialize()
        {
            Collection = new List<Mode>();
            int index = 0;

            EncryptText = new Mode()
            {
                ID = index++,
                Name = CipherMode.Text,
                Description = @"Encrypts the specified text expression",
                Parameters =
                {
                    Parameter.AliasEnc,
                    Parameter.Context,
                    Parameter.SecretEnc,
                    Parameter.InEncText,
                    Parameter.OutEncText
                }
            };
            Collection.Add(EncryptText);

            EncryptFile = new Mode()
            {
                ID = index++,
                Name = CipherMode.File,
                Description = @"Encrypts the specified file (all file formats are supported)",
                Parameters =
                {
                    Parameter.AliasEnc,
                    Parameter.Context,
                    Parameter.InEncFile,
                    Parameter.OutEncFile,
                    Parameter.Wipe,
                    Parameter.OverWriteExistingFile
                }
            };
            Collection.Add(EncryptFile);

            DecryptText = new Mode()
            {
                ID = index++,
                Name = CipherMode.Text,
                Description = @"Decrypts the specified ciphertext expression",
                Parameters =
                {
                    Parameter.AliasDec,
                    Parameter.Context,
                    Parameter.SecretDec,
                    Parameter.InDecText,
                    Parameter.OutDecText
                }
            };
            Collection.Add(DecryptText);

            DecryptFile = new Mode()
            {
                ID = index++,
                Name = CipherMode.File,
                Description = @"Decrypts the specified ciphertext file",
                Parameters =
                {
                    Parameter.AliasDec,
                    Parameter.Context,
                    Parameter.InDecFile,
                    Parameter.OutDecFile,
                    Parameter.Wipe,
                    Parameter.OverWriteExistingFile
                }
            };
            Collection.Add(DecryptFile);

            ReEncryptText = new Mode()
            {
                ID = index++,
                Name = CipherMode.Text,
                Description = @"Re-encrypts the specified ciphertext expression using a different encryption certificate",
                Parameters =
                {
                    Parameter.OldAlias,
                    Parameter.OldContext,
                    Parameter.NewAlias,
                    Parameter.TargetContext,
                    Parameter.SecretReEnc,
                    Parameter.InReEncText,
                    Parameter.OutEncText
                }
            };
            Collection.Add(ReEncryptText);

            ReEncryptFile = new Mode()
            {
                ID = index++,
                Name = CipherMode.File,
                Description = @"Re-encrypts the specified ciphertext file using a different X509Alias",
                Parameters =
                {
                    Parameter.OldAlias,
                    Parameter.OldContext,
                    Parameter.NewAliasReEnc,
                    Parameter.TargetContext,
                    Parameter.InReEncFile
                }
            };
            Collection.Add(ReEncryptFile);

            AddAlias = new Mode()
            {
                ID = index++,
                IsDefault = true,
                Description = @"Adds a new X509Alias to the specified X509Context",
                Parameters =
                {
                    Parameter.AliasToAdd,
                    Parameter.Context,
                    Parameter.Thumbprint
                }
            };
            Collection.Add(AddAlias);

            UpdateAlias = new Mode()
            {
                ID = index++,
                IsDefault = true,
                Description = @"Updates an existing X509Alias with a new encryption certificate",
                Parameters =
                {
                    Parameter.AliasToUpdate,
                    Parameter.OldContext,
                    Parameter.NewContext,
                    Parameter.Thumbprint
                }
            };
            Collection.Add(UpdateAlias);

            RemoveAlias = new Mode()
            {
                ID = index++,
                IsDefault = true,
                Description = @"Removes an X509Alias from the specified X509Context",
                Parameters =
                {
                    Parameter.AliasToRemove,
                    Parameter.Context
                }
            };
            Collection.Add(RemoveAlias);

            ImportAlias = new Mode()
            {
                ID = index++,
                IsDefault = true,
                Description = @"Imports the X509Alias contained in the specified file",
                Parameters =
                {
                    Parameter.InImportAlias,
                    Parameter.Context,
                    Parameter.AliasToImport,
                    Parameter.OverWriteExistingAlias
                }
            };
            Collection.Add(ImportAlias);

            ExportAlias = new Mode()
            {
                ID = index++,
                IsDefault = true,
                Description = @"Exports the specified X509Alias to a file. Encryption certificate and private key are not included",
                Parameters =
                {
                    Parameter.AliasToExport,
                    Parameter.Context,
                    Parameter.OutExportAlias,
                    Parameter.OverWriteExistingFile
                }
            };
            Collection.Add(ExportAlias);

            DumpAlias = new Mode()
            {
                ID = index++,
                IsDefault = true,
                Description = @"Generates a report of the secrets contained within an X509Alias",
                Parameters =
                {
                    Parameter.AliasToDump,
                    Parameter.Context,
                    Parameter.Reveal,
                    Parameter.OutDumpAlias
                }
            };
            Collection.Add(DumpAlias);

            InstallCert = new Mode()
            {
                ID = index++,
                IsDefault = true,
                Description = @"Imports the specified encryption certificate and key pair into the specified X509Context",
                Parameters =
                {
                    Parameter.InInstallCert,
                    Parameter.InstallCertContext
                }
            };
            Collection.Add(InstallCert);

            MakeCert = new Mode()
            {
                ID = index++,
                IsDefault = true,
                Description = @"Generates a new, self-signed encryption certificate",
                Parameters =
                {
                    Parameter.MakeCertSubject,
                    Parameter.MakeCertKeySize,
                    Parameter.MakeCertYearsValid,
                    Parameter.Context
                }
            };
            Collection.Add(MakeCert);

            List = new Mode()
            {
                ID = index++,
                IsDefault = true,
                Parameters =
                {
                    Parameter.Context,
                    Parameter.ListType,
                    Parameter.OutList
                }
            };
            Collection.Add(List);

            Cli = new Mode()
            {
                ID = index++,
                Description = $"Enters the persistent {Constants.AssemblyTitle} command line interface",
                IsDefault = true
            };
            Collection.Add(Cli);

            Impersonate = new Mode()
            {
                ID = index++,
                Description = $"Starts or ends the execution of subsequent {Constants.AssemblyTitle} commands as a different user account",
                IsDefault = true,
                Parameters =
                {
                    Parameter.ImpUser,
                    Parameter.EndImp
                }
            };
            Collection.Add(Impersonate);

            Help = new Mode()
            {
                ID = index++,
                Description = @"Command line syntax:"
            };
            Collection.Add(Help);

            Exit = new Mode()
            {
                ID = index++,
                Description = $"Terminates the {Constants.AssemblyTitle} program"
            };
            Collection.Add(Exit);
        }

        internal static Mode Select(Command command, string[] args, bool inCli, ref int index)
        {
            if (command.HasDefaultMode)
            {
                return command.SupportedModes.FirstOrDefault();
            }

            if (index < args.Length)
            {
                Mode mode = command.SupportedModes.Find(args[index++]);
                return mode;
            }
            else
            {
                throw new InvalidArgumentsException();
            }
        }
    }
}
