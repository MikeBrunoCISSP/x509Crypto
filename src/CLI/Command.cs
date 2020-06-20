using Org.X509Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace X509CryptoExe
{
    internal class Command
    {
        internal static List<Command> Collection;

        internal int ID { get; private set; }
        internal string Name { get; private set; }
        internal string Description { get; private set; }
        internal List<Mode> SupportedModes { get; private set; } = new List<Mode>();
        internal Mode SelectedMode { get; private set; } = null;
        internal bool HasDefaultMode { get; private set; } = false;

        public override string ToString()
        {
            return Name;
        }

        internal string ShowDescription(int padLength)
        {
            int justification = padLength + 2;
            string paddedName = Name.PadLeft(padLength);
            List<string> Lines = Description.SplitByLength(Constants.MaxDescriptionLength);
            bool firstAdded = false;
            StringBuilder Expression = new StringBuilder("\r\n");

            foreach(string line in Lines)
            {
                if (!firstAdded)
                {
                    Expression.Append($"{paddedName}: {line}");
                    firstAdded = true;
                }
                else
                {
                    Expression.Append($"\r\n{new string(' ', justification)}{line}");
                }
            }

            return Expression.ToString();
        }

        internal string UsageDetail()
        {
            StringBuilder Expression = new StringBuilder($"\r\n{Description}");

            if (HasDefaultMode)
            {
                Expression.Append($"{Samples.Mode}\r\n{UsageExpression.AvailableModes}:");
                SupportedModes.ForEach(p => Expression.Append(p.ShowDescription(SupportedModes.Select(q => q.Name).GetPadding())));
            }

            return Expression.ToString();
        }

        internal string Usage(bool inCLI = false)
        {
            StringBuilder Expression = new StringBuilder(UsageExpression.Prefix);

            if (!inCLI)
            {
                Expression.Append($"{Constants.AssemblyFile} ");
            }

            Expression.Append(Name);

            if (SupportedModes.Count() > 0)
            {
                Expression.Append($" {SupportedModes.Select(p => p.Name).BarDelimited().InBrackets()}");
            }

            Expression.Append(UsageDetail());
            Expression.AppendLine();
            return Expression.ToString();
        }

        internal void GetMode(string[] args, ref int index)
        {
            if (HasDefaultMode)
            {
                SelectedMode = SupportedModes.First();
                return;
            }

            SelectedMode = SupportedModes.Find(args[index++]);
        }

        internal static Command Encrypt,
                                Decrypt,
                                ReEncrypt,
                                AddAlias,
                                UpdateAlias,
                                RemoveAlias,
                                ImportAlias,
                                ExportAlias,
                                DumpAlias,
                                InstallCert,
                                MakeCert,
                                ExportCert,
                                List,
                                Cli,
                                Impersonate,
                                Help,
                                Exit;

        internal static void Initialize()
        {
            Collection = new List<Command>();
            int index = 0;

            Encrypt = new Command()
            {
                ID = index++,
                Name = CommandName.Encrypt,
                Description = @"Encrypts the specified plaintext expression or file",
                SupportedModes =
                {
                    Mode.EncryptText,
                    Mode.EncryptFile
                }
            };
            Collection.Add(Encrypt);

            Decrypt = new Command()
            {
                ID = index++,
                Name = CommandName.Decrypt,
                Description = @"Decrypts the specified ciphtertext expression or file",
                SupportedModes =
                {
                    Mode.DecryptText,
                    Mode.DecryptFile
                }
            };
            Collection.Add(Decrypt);

            ReEncrypt = new Command()
            {
                ID = index++,
                Name = CommandName.ReEncrypt,
                Description = @"Encrypts the specified ciphertext expression or file using a different encryption certificate",
                SupportedModes =
                {
                    Mode.ReEncryptText,
                    Mode.ReEncryptFile
                }
            };
            Collection.Add(ReEncrypt);

            AddAlias = new Command()
            {
                ID = index++,
                Name = CommandName.AddAlias,
                HasDefaultMode = true,
                Description = @"Creates a new X509Alias",
                SupportedModes =
                {
                    Mode.AddAlias
                }
            };
            Collection.Add(AddAlias);

            UpdateAlias = new Command()
            {
                ID = index++,
                Name = CommandName.UpdateAlias,
                HasDefaultMode = true,
                Description = @"Updates an X509Alias to use a different encryption certificate",
                SupportedModes =
                {
                    Mode.UpdateAlias
                }
            };
            Collection.Add(UpdateAlias);

            RemoveAlias = new Command()
            {
                Name = CommandName.RemoveAlias,
                Description = @"Removes an X509Alias from the specified X509Context",
                HasDefaultMode = true,
                SupportedModes =
                {
                    Mode.RemoveAlias
                }
            };
            Collection.Add(RemoveAlias);

            ImportAlias = new Command()
            {
                Name = CommandName.ImportAlias,
                Description = @"Imports an X509Alias from the specified file",
                HasDefaultMode = true,
                SupportedModes =
                {
                    Mode.ImportAlias
                }
            };
            Collection.Add(ImportAlias);

            ExportAlias = new Command()
            {
                Name = CommandName.ExportAlias,
                Description = @"Exports the specified X509Alias to a file",
                HasDefaultMode = true,
                SupportedModes =
                {
                    Mode.ExportAlias
                }
            };
            Collection.Add(ExportAlias);

            DumpAlias = new Command()
            {
                Name = CommandName.DumpAlias,
                Description = @"Lists the secret identiers (and values if desired) contained within the specified X509Alias",
                HasDefaultMode = true,
                SupportedModes =
                {
                    Mode.DumpAlias
                }
            };
            Collection.Add(DumpAlias);

            InstallCert = new Command()
            {
                Name = CommandName.InstallCert,
                Description = @"Installs an encryption certificate and associated key pair from a PKCS#12 (typically .pfx or .p12) file into the specified X509Context",
                HasDefaultMode = true,
                SupportedModes =
                {
                    Mode.InstallCert
                }
            };
            Collection.Add(InstallCert);

            MakeCert = new Command()
            {
                Name = CommandName.MakeCert,
                Description = $"Creates and installs a new, self-signed encryption certificate in the specified {nameof(X509Context)}",
                HasDefaultMode = true,
                SupportedModes =
                {
                    Mode.MakeCert
                }
            };
            Collection.Add(MakeCert);

            ExportCert = new Command()
            {
                Name = CommandName.ExportCert,
                Description = @"Exports the specified certificate and key pair to a PKCS#12 file",
                HasDefaultMode = true,
                SupportedModes =
                {
                    Mode.ExportCert
                }
            };
            Collection.Add(ExportCert);

            List = new Command()
            {
                Name = CommandName.List,
                Description = @"Lists the X509Alias' and/or encryption certificates available in the specified context",
                HasDefaultMode = true,
                SupportedModes =
                {
                    Mode.List
                }
            };
            Collection.Add(List);

            Impersonate = new Command()
            {
                Name = CommandName.Impersonate,
                Description = $"Starts or stops executing subsequent {Constants.AssemblyTitle} commands as a different user account",
                HasDefaultMode = true,
                SupportedModes =
                {
                    Mode.Impersonate
                }
            };
            Collection.Add(Impersonate);

            Help = new Command()
            {
                Name = CommandName.Help,
                Description = @"Displays this help message",
                HasDefaultMode = true,
                SupportedModes =
                {
                    Mode.Help
                }
            };
            Collection.Add(Help);

            Exit = new Command()
            {
                Name = CommandName.Exit,
                Description = $"Exits the {Constants.AssemblyTitle} program",
                HasDefaultMode = true,
                SupportedModes =
                {
                    Mode.Exit
                }
            };
            Collection.Add(Exit);

            Cli = new Command()
            {
                Name = CommandName.CLI,
                HasDefaultMode = true,
                SupportedModes =
                {
                    Mode.Cli
                }
            };
        }

        internal static Command Select(string[] args, ref int index)
        {
            if (args.Length < 1)
            {
                return Cli;
            }

            Command SelectedCommand;

            try
            {
                SelectedCommand = Collection.Find(args[index++]);
                return SelectedCommand;
            }
            catch (Exception)
            {
                throw new UnrecognizedExpressionException(args[index - 1]);
            }
        }
    }
}
