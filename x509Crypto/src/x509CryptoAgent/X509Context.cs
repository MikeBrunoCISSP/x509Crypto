using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.AccessControl;
using System.Collections.Generic;

namespace Org.X509Crypto
{
    /// <summary>
    /// Defines the CAPI store, file system location and name for an X509Cryto encryption context
    /// </summary>
    public class X509Context
    {
        private static bool systemAppDirectoryCreated = false;

        internal enum Indexer
        {
            UserReadOnly = 0,
            UserFull = 1,
            SystemReadOnly = 2,
            SystemFull = 3
        }

        internal Indexer Index { get; private set; }

        /// <summary>
        /// The CAPI store where an encryption certificate and key pair are contained
        /// </summary>
        public StoreLocation Location { get; private set; }

        /// <summary>
        /// The human-readable name of the context
        /// </summary>
        public string Name { get; private set; }

        internal bool Writeable;

        /// <summary>
        /// The path where X509Alias files created in the context are stored.
        /// For "User" it is "C:\Users\\[sAMAccountName]\AppData\Local\X509Crypto"
        /// For "System" it is "C:\ProgramData\X509Crypto"
        /// </summary>
        public string StorageDirectory
        {
            get
            {
                switch (Index)
                {
                    case Indexer.UserReadOnly:
                        return X509Directory.User;
                    case Indexer.UserFull:
                        if (!Directory.Exists(X509Directory.User))
                        {
                            try
                            {
                                Directory.CreateDirectory(X509Directory.User);
                            }
                            catch (UnauthorizedAccessException)
                            {
                                throw new X509DirectoryRightsException(Name, X509Directory.User, true);
                            }
                        }
                        return X509Directory.User;
                    case Indexer.SystemReadOnly:
                        return X509Directory.System;
                    case Indexer.SystemFull:
                        if (!systemAppDirectoryCreated)
                        {
                            try
                            {
                                CreateSystemAppDirectory();
                            }
                            catch (UnauthorizedAccessException)
                            {
                                throw new X509DirectoryRightsException(Name, X509Directory.System, true);
                            }
                        }
                        return X509Directory.System;
                    default:
                        //This case will never be reached.
                        return string.Empty;
                }
            }
        }

        /// <summary>
        /// Provides read-only access to the context of the currently logged in (or impersonated) user.
        /// </summary>
        public static readonly X509Context UserReadOnly = new X509Context
        {
            Index = Indexer.UserReadOnly,
            Location = StoreLocation.CurrentUser,
            Name = X509ContextName.User,
            Writeable = false
        };

        /// <summary>
        /// Provides read/write access to the context of the currently logged in (or impersonated) user.
        /// </summary>
        public static readonly X509Context UserFull = new X509Context
        {
            Index = Indexer.UserFull,
            Location = StoreLocation.CurrentUser,
            Name = X509ContextName.User,
            Writeable = true
        };

        /// <summary>
        /// Provides read-only access to the context of the currently logged in (or impersonated) user.
        /// </summary>
        public static readonly X509Context SystemReadOnly = new X509Context
        {
            Index = Indexer.SystemReadOnly,
            Location = StoreLocation.LocalMachine,
            Name = X509ContextName.System,
            Writeable = false
        };

        /// <summary>
        /// Provides read/write access to the context of the currently logged in (or impersonated) user.
        /// </summary>
        public static readonly X509Context SystemFull = new X509Context
        {
            Index = Indexer.SystemFull,
            Location = StoreLocation.LocalMachine,
            Name = X509ContextName.System,
            Writeable = true
        };

        internal static readonly IEnumerable<X509Context> SupportedContexts = new X509Context[] { UserReadOnly, UserFull, SystemReadOnly, SystemFull };

        public static X509Context Select(string name, bool writeable)
        {
            X509Context SelectedContext;

            try
            {
                SelectedContext = SupportedContexts.Where(p => p.Writeable == writeable).First(p => p.Name.Matches(name));
                return SelectedContext;
            }
            catch
            {
                throw new X509ContextNotSupported(name);
            }
        }

        internal List<string> GetAliasNames()
        {
            var AliasNames = new List<string>();

            if (!Directory.Exists(StorageDirectory))
            {
                return AliasNames;
            }

            foreach (string file in Directory.GetFiles(StorageDirectory))
            {
                AliasNames.Add(Path.GetFileNameWithoutExtension(file));
            }
            return AliasNames;
        }

        internal List<X509Alias> GetAliases()
        {
            List<X509Alias> Aliases = new List<X509Alias>();
            List<string> AliasNames = GetAliasNames();

            foreach(string name in AliasNames)
            {
                try
                {
                    X509Alias Alias = new X509Alias(name, this);
                    Aliases.Add(Alias);
                }
                catch
                {
                    //Do not incude invalid aliases
                }
            }

            return Aliases;
        }

        private void CreateSystemAppDirectory()
        {
            if (!Directory.Exists(X509Directory.System))
            {
                Directory.CreateDirectory(X509Directory.System);
            }

            systemAppDirectoryCreated = true;

            if (X509Utils.IISGroupExists())
            {
                AssignIISRights();
            }
        }

        private void AssignIISRights()
        {
            try
            {
                DirectoryInfo dirInfo = new DirectoryInfo(X509Directory.System);
                DirectorySecurity dirSec = dirInfo.GetAccessControl();
                dirSec.AddAccessRule(new FileSystemAccessRule(Constants.IISGroup, FileSystemRights.Read, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                dirInfo.SetAccessControl(dirSec);
            }
            catch
            {
                X509CryptoLog.Warning($"Unable to assign access rights for the IIS IUSRS group to {X509Directory.System}");
            }
        }

        public static void CreateImpersonatedUserAppDirectory(string sAMAccountName)
        {
            string impUserAppDir = X509Directory.ImpersonatedUser(sAMAccountName);
            if (!Directory.Exists(impUserAppDir))
            {
                Directory.CreateDirectory(impUserAppDir);
                DirectoryInfo DirInfo = new DirectoryInfo(impUserAppDir);
                DirectorySecurity DirSec = DirInfo.GetAccessControl();
                DirSec.AddAccessRule(new FileSystemAccessRule(sAMAccountName, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                DirInfo.SetAccessControl(DirSec);
            }
        }
    }
}
