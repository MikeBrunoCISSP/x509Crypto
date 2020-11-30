using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using Org.X509Crypto;
using System.Text.RegularExpressions;

namespace X509CryptoExe
{
    internal class Parameter
    {
        internal static List<Parameter> Collection { get; private set; } = new List<Parameter>();

        private string name;

        internal int ID { get; private set; }

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

        internal string Sample { get; private set; }

        internal string TextValue { get; private set; }

        internal int IntValue { get; private set; } = 0;
        internal int MinIntValue { get; private set; } = 0;

        internal string Description { get; private set; } = string.Empty;
        internal string DefaultEntry { get; private set; } = string.Empty;
        internal string DefaultExtension { get; private set; } = string.Empty;
        internal string FileExtension { get; private set; } = string.Empty;

        internal bool BoolValue { get; private set; } = false;
        internal bool DefinitionRequired { get; private set; } = true;
        internal bool IsPath { get; private set; } = false;
        internal bool MustBeExistingPath { get; private set; } = false;
        internal bool IsBool { get; private set; } = false;
        internal bool IsInt { get; private set; } = false;
        internal bool IsContext { get; private set; } = false;
        internal bool ControlsOutput { get; private set; } = false;
        internal bool UseClipboard { get; private set; } = false;
        internal bool OutToScreen { get; private set; } = false;
        internal bool StandAlone { get; private set; } = false;
        internal bool IsThumbprint { get; private set; } = false;
        internal bool IsDefined { get; private set; } = false;

        internal bool OutToFile
        {
            get
            {
                return IsPath && !(UseClipboard || OutToScreen);
            }
        }

        internal bool HasPreferredFileExtension
        {
            get
            {
                return !string.IsNullOrEmpty(FileExtension);
            }
        }

        internal bool Satisfied
        {
            get
            {
                return IsDefined || !DefinitionRequired;
            }
        }

        private bool HasSelections
        {
            get
            {
                return SelectionSet.Count > 0;
            }
        }

        internal X509Context SelectedContext { get; private set; } = null;
        internal List<ValidSelection> SelectionSet { get; private set; } = new List<ValidSelection>();

        public override string ToString()
        {
            return Name;
        }

        internal string CliSyntax()
        {
            StringBuilder Expression = new StringBuilder($" {Name}");

            if (StandAlone)
            {
                return Expression.ToString();
            }

            if (!string.IsNullOrEmpty(Sample))
            {
                Expression.Append($" {Sample.InBrackets()}");
            }
            else
            {
                if (HasSelections)
                {
                    if (SelectionSet.Count == 1)
                    {
                        Expression.Append($" {Sample.InBrackets()}");
                    }
                    else
                    {
                        Expression.Append($" {SelectionSet.Select(p => p.Name).BarDelimited().InBrackets()}");
                    }
                }
                else
                {
                    Expression.Append($" {Sample.InBrackets()}");
                }
            }

            return Expression.ToString();
        }

        internal string DetailedUsage(int padding)
        {
            int justification = padding + 2;
            string paddedName = Name.PadLeft(padding);
            List<string> Lines = Description.SplitByLength(Constants.MaxDescriptionLength);
            bool firstAdded = false;
            StringBuilder Expression = new StringBuilder("\r\n");

            foreach(string line in Lines)
            {
                if (!firstAdded)
                {
                    Expression.Append($"{paddedName}: {line}\r\n");
                    firstAdded = true;
                }
                else
                {
                    Expression.Append($"{new string(' ', justification)}{line}\r\n");
                }
            }

            if (HasSelections)
            {
                int selectionJustification = SelectionSet.Select(p => p.Name).GetPadding() + padding + 2;
                Expression.Append($"\r\n{new string(' ', justification)}{UsageExpression.ValidEntries}");
                SelectionSet.ForEach(p => Expression.Append($"{p.Name} - {p.Description}".Align(UsageIndent.Parameter, selectionJustification, p.Name.Length)));
                Expression.Append("\r\n");
            }

            if (!string.IsNullOrEmpty(DefaultEntry))
            {
                Expression.Append($"{UsageExpression.DefaultSelection}{DefaultEntry}".Align(UsageIndent.Parameter, padding));
            }
            return Expression.ToString();
        }

        internal string Markdown
        {
            get
            {
                return $"|{Name}|{(DefinitionRequired ? MarkdownExpression.Required : $"Not {MarkdownExpression.Required}")}|{Description}|";
            }
        }

        internal void TryDefine(string[] args, ref int index)
        {
            if (StandAlone)
            {
                IsDefined = true;
                return;
            }

            string entry;

            try
            {
                entry = args[index++];
            }
            catch (IndexOutOfRangeException)
            {
                throw new InvalidArgumentsException();
            }

            if (IsBool)
            {
                BoolValue = ToBool(entry);
                TextValue = entry;
                IsDefined = true;
                return;
            }

            if (IsInt)
            {
                IntValue = ToInt(entry);
                TextValue = entry;
                IsDefined = true;
                return;
            }

            if (SelectionSet.Count >= 1)
            {
                if (!SelectionSet.Contains(entry))
                {
                    throw new InvalidArgumentsException(Name, entry, SelectionSet);
                }
            }
            else
            {
                if (IsPath)
                {
                    if (ControlsOutput)
                    {
                        if (entry.Matches(ParameterName.Clipboard))
                        {
                            UseClipboard = true;
                            IsDefined = true;
                            return;
                        }

                        if (entry.Matches(ParameterName.Screen))
                        {
                            OutToScreen = true;
                            IsDefined = true;
                            return;
                        }
                    }
                    CheckPathFormat(entry);
                    if (MustBeExistingPath)
                    {
                        CheckPathExists(entry);
                    }
                    else
                    {
                        if (HasPreferredFileExtension && !Path.HasExtension(entry))
                        {
                            entry += FileExtension;
                        }
                    }
                }
            }

            if (IsThumbprint)
            {
                entry = entry.RemoveNonHexChars();
            }

            if (IsContext)
            {
                SelectedContext = X509Context.Select(entry, false);
            }

            TextValue = entry;
            IsDefined = true;
        }

        private bool ToBool(string expression)
        {
            switch (expression.ToUpper())
            {
                case @"TRUE":
                    return true;
                case @"T":
                    return true;
                case @"YES":
                    return true;
                case @"Y":
                    return true;
                case @"FALSE":
                    return false;
                case @"F":
                    return false;
                case @"NO":
                    return false;
                case @"N":
                    return false;
                default:
                    throw new InvalidArgumentsException(Name, expression);
            }
        }

        private int ToInt(string expression)
        {
            int value;
            if (!RegexPattern.DigitsOnly.IsMatch(expression))
            {
                throw new InvalidArgumentsException(Name, expression);
            }
            else
            {
                value = Convert.ToInt32(expression);
                if (value < MinIntValue)
                {
                    throw new InvalidArgumentsException(Name, MinIntValue);
                }
                else
                {
                    return value;
                }
            }
        }

        private void CheckPathFormat(string expression)
        {
            try
            {
                Path.GetFullPath(expression);
            }
            catch
            {
                throw new InvalidArgumentsException(Name, expression);
            }
        }

        private void CheckPathExists(string expression, bool checkPathSyntax = false)
        {
            if (checkPathSyntax)
            {
                CheckPathFormat(expression);
            }
            if (!File.Exists(expression))
            {
                throw new InvalidArgumentsException($"The path entered for {Name} (\"{expression}\") does not exist");
            }
        }

        internal static void DefineAll(ref Mode mode, string[] args, ref int index)
        {
            if (!mode.NeedsParameters)
            {
                throw new InvalidArgumentsException(string.Format(UsageExpression.UnrecognizedExpression, args[index]));
            }

            foreach (Parameter param in mode.Parameters)
            {
                if (param.Name.Matches(args[index]))
                {
                    index++;
                    param.TryDefine(args, ref index);
                    return;
                }
            }

            throw new InvalidArgumentsException(string.Format(UsageExpression.UnrecognizedExpression, args[index]));
        }

        internal static Parameter Thumbprint,
                                  ThumbprintToExport,
                                  AliasName,
                                  AliasEnc,
                                  AliasDec,
                                  AliasToAdd,
                                  AliasToUpdate,
                                  AliasToRemove,
                                  AliasToExport,
                                  AliasToImport,
                                  AliasToDump,
                                  AliasToInstall,
                                  AliasExportCert,
                                  OldAlias,
                                  NewAlias,
                                  NewAliasReEnc,
                                  Context,
                                  OldContext,
                                  NewContext,
                                  TargetContext,
                                  InstallCertContext,
                                  ListType,
                                  SecretEnc,
                                  SecretReEnc,
                                  SecretDec,
                                  InEncText,
                                  InEncFile,
                                  InDecText,
                                  InDecFile,
                                  InReEncText,
                                  InReEncFile,
                                  InImportAlias,
                                  InInstallCert,
                                  Out,
                                  OutFile,
                                  OutEncText,
                                  OutEncFile,
                                  OutReEncFile,
                                  OutDecText,
                                  OutDecFile,
                                  OutList,
                                  OutExportAlias,
                                  OutExportCert,
                                  OutDumpAlias,
                                  OutMakeDoc,
                                  Wipe,
                                  Reveal,
                                  ImpUser,
                                  EndImp,
                                  OverWriteExistingFile,
                                  OverWriteExistingAlias,
                                  MakeCertKeySize,
                                  MakeCertSubject,
                                  MakeCertYearsValid;

        internal static void Initialize()
        {
            Collection = new List<Parameter>();
            int index = 0;

            Thumbprint = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Thumbprint,
                Sample = Samples.Thumbprint,
                Description = @"The thumbprint of the encryption certificate",
                IsThumbprint = true
            };
            Collection.Add(Thumbprint);

            AliasName = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Alias,
                Sample = Samples.Name,
                Description = @"The desired name for the X509Alias to be created (must be unique within the X509Context)"
            };
            Collection.Add(AliasName);

            AliasEnc = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Alias,
                Sample = Samples.Name,
                Description = @"The X509Alias to use for encryption"
            };
            Collection.Add(AliasEnc);

            AliasDec = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Alias,
                Sample = Samples.Name,
                Description = @"The X509Alias to use for decryption"
            };
            Collection.Add(AliasDec);

            AliasToAdd = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Name,
                Sample = Samples.Name,
                Description = @"The desired name for the X509Alias to be created. Must be unique within the chosen X509Context"
            };
            Collection.Add(AliasToAdd);

            AliasToUpdate = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Name,
                Sample = Samples.Name,
                Description = @"The name of the X509Alias to be updated"
            };
            Collection.Add(AliasToUpdate);

            AliasToRemove = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Name,
                Sample = Samples.Name,
                Description = @"The name of the X509Alias to be removed"
            };
            Collection.Add(AliasToRemove);

            AliasToExport = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Name,
                Sample = Samples.Name,
                Description = @"The name of the X509Alias to be exported"
            };
            Collection.Add(AliasToExport);

            AliasToImport = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Name,
                Sample = Samples.Name,
                Description = @"The desired name for the X509Alias (if not specified, the alias indicated in the source file will be used)",
                DefinitionRequired = false
            };
            Collection.Add(AliasToImport);

            AliasToInstall = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Alias,
                Sample = Samples.Name,
                Description = $"The desired name for the {nameof(X509Alias)} (if you wish to use this encryption certificate in an {nameof(X509Alias)})",
                DefinitionRequired = false
            };
            Collection.Add(AliasToInstall);

            AliasToDump = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Name,
                Sample = Samples.Name,
                Description = @"The name of the X509Alias from which to list existing secrets"
            };
            Collection.Add(AliasToDump);

            OldAlias = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Alias,
                Sample = Samples.Name,
                Description = @"Specifies the X509Alias currently used for encryption"
            };
            Collection.Add(OldAlias);

            NewAlias = new Parameter()
            {
                ID = index++,
                Name = ParameterName.NewAlias,
                Sample = Samples.Name,
                Description = @"The X509Alias to be created (If not specified, the current alias will be used)",
                DefinitionRequired = false
            };
            Collection.Add(NewAlias);

            NewAliasReEnc = new Parameter()
            {
                ID = index++,
                Name = ParameterName.NewAlias,
                Sample = Samples.Name,
                Description = @"The target X509Alias to be used for encryption going forward"
            };
            Collection.Add(NewAliasReEnc);

            Context = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Context,
                Sample = Samples.Context,
                Description = @"The X509Context where cryptographic operations occur",
                SelectionSet = ValidSelection.Contexts,
                IsContext = true
            };
            Collection.Add(Context);

            OldContext = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Context,
                Sample = Samples.Context,
                Description = @"The X509Context where the X509Alias currently exists",
                SelectionSet = ValidSelection.Contexts,
                IsContext = true
            };
            Collection.Add(OldContext);

            NewContext = new Parameter()
            {
                ID = index++,
                Name = ParameterName.NewContext,
                Sample = Samples.Context,
                Description = $"The X509Context where the new X509Alias should be created. If not specified, the selection for {ParameterName.Context} will be used",
                SelectionSet = ValidSelection.Contexts,
                IsContext = true,
                DefinitionRequired = false
            };
            Collection.Add(NewContext);

            TargetContext = new Parameter()
            {
                ID = index++,
                Name = ParameterName.NewContext,
                Sample = Samples.Context,
                Description = $"The X509Context where the target X509Alias exists. If not specified, the selection for {ParameterName.Context} will be used",
                SelectionSet = ValidSelection.Contexts,
                IsContext = true,
                DefinitionRequired = false
            };
            Collection.Add(TargetContext);

            InstallCertContext = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Context,
                Sample = Samples.Context,
                Description = @"The X509Context where the specified encryption certificate should be installed",
                SelectionSet = ValidSelection.Contexts,
                IsContext = true
            };
            Collection.Add(InstallCertContext);

            ListType = new Parameter()
            {
                ID = index++,
                Name = ParameterName.ListType,
                Description = @"Indicates whether to display a list of X509Aliases or available encryption certificates present in the specified X509Context",
                SelectionSet = ValidSelection.ListTypes
            };
            Collection.Add(ListType);

            SecretEnc = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Secret,
                Sample = Samples.Secret,
                Description = @"A unique identifier used to identify a ciphertext expression and recover the corresponding plaintext expression from the specified X509Alias",
                DefinitionRequired = false
            };
            Collection.Add(SecretEnc);

            SecretReEnc = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Secret,
                Sample = Samples.Secret,
                Description = @"A unique identifier used to identify a ciphertext expression and recover the corresponding plaintext expression from the destination X509Alias",
                DefinitionRequired = false
            };
            Collection.Add(SecretReEnc);

            SecretDec = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Secret,
                Sample = Samples.Secret,
                Description = @"A unique identifier used to identify a ciphertext expression and recover the corresponding plaintext expression from the specified X509Alias",
                DefinitionRequired = false
            };
            Collection.Add(SecretDec);

            Wipe = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Wipe,
                Sample = Samples.TimesToWrite,
                IsInt = true,
                MinIntValue = 1,
                Description = @"Removes residual data from disk after cryptographic operations have completed. The more times to write, the better the data destruction, but the performance impact will be higher",
                DefinitionRequired = false
            };
            Collection.Add(Wipe);

            Reveal = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Reveal,
                Sample = Samples.YesOrNo,
                IsBool = true,
                DefaultEntry = @"No",
                Description = @"Indicates whether the values of the secrets contained within the X509Alias should be revealed in the command output",
                DefinitionRequired = false
            };
            Collection.Add(Reveal);

            ImpUser = new Parameter()
            {
                ID = index++,
                Name = ParameterName.ImpUser,
                Sample = Samples.User,
                Description = "The domain user in which to impersonate (either \"[USERNAME]\" or \"[DOMAIN]\\[USERNAME]\")",
                DefaultEntry = string.Empty,
                DefinitionRequired = false
            };
            Collection.Add(ImpUser);

            EndImp = new Parameter()
            {
                ID = index++,
                Name = ParameterName.EndImp,
                Description = @"Ends an impersonation session (if impersonation is currently occurring)",
                StandAlone = true,
                DefinitionRequired = false
            };
            Collection.Add(EndImp);

            InEncText = new Parameter()
            {
                ID = index++,
                Name = ParameterName.In,
                Sample = Samples.Plaintext,
                Description = @"The text expression to be encrypted"
            };
            Collection.Add(InEncText);

            InReEncText = new Parameter()
            {
                ID = index++,
                Name = ParameterName.In,
                Sample = Samples.Ciphertext,
                Description = @"The ciphertext expression to be re-encrypted",
                DefinitionRequired = false
            };
            Collection.Add(InReEncText);

            InEncFile = new Parameter()
            {
                ID = index++,
                Name = ParameterName.In,
                IsPath = true,
                MustBeExistingPath = true,
                Sample = Samples.PathOnly,
                Description = @"The path of the file to be encrypted"
            };
            Collection.Add(InEncFile);

            InReEncFile = new Parameter()
            {
                ID = index++,
                Name = ParameterName.In,
                Sample = Samples.PathOnly,
                Description = @"The path of the ciphertext file to be re-encrypted"
            };
            Collection.Add(InReEncFile);

            InDecText = new Parameter()
            {
                ID = index++,
                Name = ParameterName.In,
                Sample = Samples.Ciphertext,
                Description = @"The ciphertext expression to be decrypted",
                DefinitionRequired = false
            };
            Collection.Add(InDecText);

            InDecFile = new Parameter()
            {
                ID = index++,
                Name = ParameterName.In,
                IsPath = true,
                MustBeExistingPath = true,
                Sample = Samples.PathOnly,
                Description = @"The path to the ciphertext file to be decrypted"
            };
            Collection.Add(InDecFile);

            InImportAlias = new Parameter()
            {
                ID = index++,
                Name = ParameterName.In,
                Sample = Samples.PathOnly,
                Description = @"The path to the file containing the X509Alias to be imported",
                IsPath = true,
                MustBeExistingPath = true
            };
            Collection.Add(InImportAlias);

            InInstallCert = new Parameter()
            {
                ID = index++,
                Name = ParameterName.In,
                Sample = Samples.PathOnly,
                Description = @"The path to the PKCS#12 (typically .pfx or .p12) file which contains the encryption certificate and associated private key to be installed",
                IsPath = true,
                MustBeExistingPath = true
            };
            Collection.Add(InInstallCert);

            Out = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Out,
                Description = $"The output file path. {UsageExpression.Clipboard}",
                DefaultEntry = string.Empty,
                DefinitionRequired = false,
                IsPath = true,
                ControlsOutput = true
            };
            Collection.Add(Out);

            OutFile = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Out,
                Description = $"The output file path",
                IsPath = true
            };
            Collection.Add(OutFile);

            OutEncText = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Out,
                Sample = Samples.PathOr,
                Description = $"The path of the file to write the ciphertext. {UsageExpression.Clipboard}",
                IsPath = true,
                ControlsOutput = true,
                DefinitionRequired = false
            };
            Collection.Add(OutEncText);

            OutEncFile = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Out,
                Sample = Samples.PathOnly,
                Description = $"The path of the file to write the ciphertext. If not defined, the input file path will be used, adding a \"{FileExtensions.Ciphertext}\" extention",
                IsPath = true,
                DefinitionRequired = false
            };
            Collection.Add(OutEncFile);

            OutReEncFile = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Out,
                Sample = Samples.PathOnly,
                Description = $"The path of the file to be re-encrypted. If not defined, the existing ciphertext file will be overwritten",
                IsPath = true,
                DefinitionRequired = false
            };
            Collection.Add(OutReEncFile);

            OutDecText = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Out,
                Sample = Samples.PathOr,
                Description = $"The path of the file to write the plaintext. {UsageExpression.Clipboard}",
                IsPath = true,
                ControlsOutput = true
            };
            Collection.Add(OutDecText);

            OutDecFile = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Out,
                Sample = Samples.PathOnly,
                Description = $"The path of the file to write the recovered plaintext file",
                IsPath = true,
                ControlsOutput = true,
                DefinitionRequired = false
            };
            Collection.Add(OutDecFile);

            OutExportAlias = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Out,
                Sample = Samples.PathOnly,
                Description = $"The file path to write the exported X509Alias.",
                IsPath = true,
                ControlsOutput = true,
                FileExtension = FileExtensions.X509Alias
            };
            Collection.Add(OutExportAlias);

            OutDumpAlias = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Out,
                Sample = Samples.PathOr,
                Description = $"The file path to write the X509Alias details. {UsageExpression.Clipboard}",
                IsPath = true,
                ControlsOutput = true,
                FileExtension = FileExtensions.Csv
            };
            Collection.Add(OutDumpAlias);

            OutMakeDoc = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Out,
                Sample = Samples.PathOnly,
                Description = @"The file path to write the Markdown document",
                IsPath = true,
                FileExtension = FileExtensions.Md
            };
            Collection.Add(OutMakeDoc);

            OutList = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Out,
                Sample = Samples.PathOr,
                Description = $"The file path to write the output. {UsageExpression.Clipboard}",
                IsPath = true,
                ControlsOutput = true,
                FileExtension = FileExtensions.Txt,
                DefinitionRequired = false
            };
            Collection.Add(OutList);

            OverWriteExistingFile = new Parameter()
            {
                ID = index++,
                Name = ParameterName.OverwriteExisting,
                Sample = Samples.YesOrNo,
                Description = @"Indicates whether the specified file should be overwritten if it already exists.",
                IsBool = true,
                DefaultEntry = @"No",
                DefinitionRequired = false
            };
            Collection.Add(OverWriteExistingFile);

            OverWriteExistingAlias = new Parameter()
            {
                ID = index++,
                Name = ParameterName.OverwriteExisting,
                Sample = Samples.YesOrNo,
                Description = @"Indicates whether an existing X509Alias (having the same name as the imported alias) may be overwritten",
                IsBool = true,
                DefaultEntry = @"No",
                DefinitionRequired = false
            };
            Collection.Add(OverWriteExistingAlias);

            MakeCertKeySize = new Parameter()
            {
                ID = index++,
                Name = ParameterName.KeySize,
                Sample = Samples.KeySize,
                Description = @"Indicates the length of the key pair which will be generated. The larger the key, the higher the security, but performance may be slower",
                DefaultEntry = ValidSelection.MediumKey.Name,
                DefinitionRequired = false
            };
            Collection.Add(MakeCertKeySize);

            MakeCertSubject = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Name,
                Sample = Samples.Name,
                Description = @"Indicates the identity of the person or device this certificate will be issued to. If not indicated, the logged in username or the device name will be used",
                DefinitionRequired = false
            };
            Collection.Add(MakeCertSubject);

            MakeCertYearsValid = new Parameter()
            {
                ID = index++,
                Name = ParameterName.YearsValid,
                Sample = Samples.Years,
                Description = @"Indicates the validity period of the encryption certificate. Once the certificate expires, it can no longer be used to encrypt new secrets.",
                DefaultEntry = Constants.DefaultYearsValid.ToString(),
                IsInt = true,
                DefinitionRequired = false
            };
            Collection.Add(MakeCertYearsValid);

            OutExportCert = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Out,
                Sample = Samples.PathOnly,
                Description = @"The path where the PKCS#12 certificate and key pair bundle file should be written",
                IsPath = true
            };
            Collection.Add(OutExportCert);

            AliasExportCert = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Alias,
                Sample = Samples.Name,
                Description = $"The {nameof(X509Alias)} from which to export the encryption certificate and key pair (cannot be used with {ParameterName.Thumbprint})",
                DefinitionRequired = false
            };
            Collection.Add(AliasExportCert);

            ThumbprintToExport = new Parameter()
            {
                ID = index++,
                Name = ParameterName.Thumbprint,
                Sample = Samples.Thumbprint,
                Description = $"The thumbprint of the encryption certificate to export (cannot be used with {ParameterName.Alias})",
                DefinitionRequired = false,
                IsThumbprint = true
            };
            Collection.Add(ThumbprintToExport);
        }
    }
}
