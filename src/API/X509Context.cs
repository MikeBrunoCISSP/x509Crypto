using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using Org.X509Crypto.Dto;
using Org.X509Crypto.Services;

namespace Org.X509Crypto {
    /// <summary>
    /// Defines the CAPI store, file system location and name for an X509Cryto encryption context
    /// </summary>
    public class X509Context {
        private static readonly CertService _certService = new();

        private static bool systemContextInitialized;

        private bool isWritable;

        /// <summary>
        /// The human-readable name of the context
        /// </summary>
        public string Name { get; private set; }
        /// <summary>
        /// The <see cref="X509Alias"/>s available in this context.</c>
        /// </summary>
        public List<string> Aliases { get; private set; } = new();
        /// <summary>
        /// The X509Context type.
        /// </summary>
        public X509CryptoContextType ContextType { get; private set; }

        #region Supported Contexts

        /// <summary>
        /// Provides read-only access to the context of the currently logged in (or impersonated) user.
        /// </summary>
        public static readonly X509Context UserReadOnly = new() {
            ContextType = X509CryptoContextType.UserReadOnly,
            Name = X509ContextName.User,
            Aliases = new List<string>() { X509ContextName.User, X509ContextName.CurrentUser },
            isWritable = false
        };

        /// <summary>
        /// Provides read/write access to the context of the currently logged in (or impersonated) user.
        /// </summary>
        public static readonly X509Context UserFull = new() {
            ContextType = X509CryptoContextType.UserFull,
            Name = X509ContextName.User,
            Aliases = new List<string>() { X509ContextName.User, X509ContextName.CurrentUser },
            isWritable = true
        };

        /// <summary>
        /// Provides read-only access to the context of the currently logged in (or impersonated) user.
        /// </summary>
        public static readonly X509Context SystemReadOnly = new X509Context {
            ContextType = X509CryptoContextType.SystemReadOnly,
            Name = X509ContextName.System,
            Aliases = new List<string>() { X509ContextName.System, X509ContextName.LocalSystem },
            isWritable = false
        };

        /// <summary>
        /// Provides read/write access to the context of the currently logged in (or impersonated) user.
        /// </summary>
        public static readonly X509Context SystemFull = new X509Context {
            ContextType = X509CryptoContextType.SystemFull,
            Name = X509ContextName.System,
            Aliases = new List<string>() { X509ContextName.System, X509ContextName.LocalSystem },
            isWritable = true
        };

        /// <summary>
        /// The collection of supported X509Contexts
        /// </summary>
        public static readonly IEnumerable<X509Context> SupportedContexts = new[] { UserReadOnly, UserFull, SystemReadOnly, SystemFull };

        #endregion

        /// <summary>
        /// Creates a new X509Alias pointing to this X509Context.
        /// </summary>
        /// <returns></returns>
        public X509Alias CreateX509Alias() {
            return new X509Alias() {
                Context = this
            };
        }

        public override bool Equals(object obj) {
            return obj is X509Context other && other.ContextType == ContextType;
        }

        public override int GetHashCode() {
            return ContextType.GetHashCode();
        }

        /// <summary>
        /// The path where X509Alias files created in the context are stored.
        /// For "User" it is "C:\Users\\[sAMAccountName]\AppData\Local\X509Crypto"
        /// For "System" it is "C:\ProgramData\X509Crypto"
        /// </summary>
        public string GetStorageDirectory() {
            switch (ContextType) {
                case X509CryptoContextType.UserReadOnly:
                    return X509Directory.User;
                case X509CryptoContextType.UserFull:
                    if (!Directory.Exists(X509Directory.User)) {
                        try {
                            Directory.CreateDirectory(X509Directory.User);
                        } catch (UnauthorizedAccessException) {
                            throw new X509DirectoryRightsException(Name, X509Directory.User, true);
                        }
                    }

                    return X509Directory.User;
                case X509CryptoContextType.SystemReadOnly:
                    return X509Directory.System;
                case X509CryptoContextType.SystemFull:
                    try {
                        initializeSystemContext();
                    } catch (UnauthorizedAccessException) {
                        throw new X509DirectoryRightsException(Name, X509Directory.System, true);
                    }

                    return X509Directory.System;
                default:
                    //This case will never be reached.
                    return string.Empty;
            }
        }
        /// <summary>
        /// Returns a list of X509Alias names available in the current X509Context.
        /// </summary>
        /// <returns></returns>
        public List<string> GetAliasNames() {
            return Directory.Exists(GetStorageDirectory())
                ? Directory.GetFiles(GetStorageDirectory()).Select(Path.GetFileNameWithoutExtension).ToList()
                : new List<string>();
        }
        /// <summary>
        /// Returns the collection of all <see cref="X509Alias"/>es found in this context
        /// </summary>
        /// <returns>the collection of all <see cref="X509Alias"/>es found in this context</returns>
        public List<X509Alias> GetAliases(bool includeIfCertNotFound = true) {
            return GetAliasNames().Select(name => X509Alias.Load(name, this))
                                  .Where(alias => includeIfCertNotFound || alias.GetCertificate() != null).ToList();
        }
        /// <summary>
        /// Creates a certificate and adds it to the X509Context
        /// </summary>
        /// <param name="name">The certificate subject</param>
        /// <param name="keyLength">The public key length</param>
        /// <param name="yearsValid">The number of years valid.</param>
        /// <param name="thumbprint">The thumbprint of the generated certificate</param>
        /// <exception cref="Exception"></exception>
        public void MakeCert(string name, int keyLength, int yearsValid, out string thumbprint) {
            try {
                CertificateDto dto = _certService.CreateX509CryptCertificate(name, this, keyLength, yearsValid);
                thumbprint = dto.Thumbprint;
            } catch (Exception ex) {
                throw new Exception($"A certificate could not be added to the {Name} {nameof(X509Context)}.", ex);
            }
        }

        private void initializeSystemContext() {
            if (systemContextInitialized) {
                return;
            }

            createSystemAppDirectory();
            assignIISRights();
            systemContextInitialized = true;
        }
        private void createSystemAppDirectory() {
            if (!Directory.Exists(X509Directory.System)) {
                Directory.CreateDirectory(X509Directory.System);
            }
        }

        private void assignIISRights() {
            if (!X509CryptoUtils.IISGroupExists()) {
                return;
            }
            try {
                DirectoryInfo dirInfo = new DirectoryInfo(X509Directory.System);
                DirectorySecurity dirSec = dirInfo.GetAccessControl();
                dirSec.AddAccessRule(new FileSystemAccessRule(Constants.IISGroup, FileSystemRights.Read, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                dirInfo.SetAccessControl(dirSec);
            } catch {
                //Gave it a college try
            }
        }

        /// <summary>
        /// Returns an X509Context object based on the indicated expression
        /// </summary>
        /// <param name="name">The name of the desired X509Context</param>
        /// <returns>An X509Context object</returns>
        /// <exception cref="X509ContextNotSupported"></exception>
        public static X509Context Select(string name) {
            try {
                return SupportedContexts.First(p => p.isWritable && p.Aliases.Contains(name, StringComparison.OrdinalIgnoreCase));
            } catch {
                throw new X509ContextNotSupported(name);
            }
        }
        /// <summary>
        /// Returns an X509CryptoContext based on the indicated type.
        /// </summary>
        /// <param name="contextType">The X509CryptoContextType</param>
        /// <returns></returns>
        public static X509Context Select(X509CryptoContextType contextType) => SupportedContexts.First(p => p.ContextType == contextType);
        /// <summary>
        /// Creates the directory for an impersonated user where X509Alias files will be stored for later retrieval
        /// </summary>
        /// <param name="sAMAccountName">The username of the impersonated user</param>
        public static void CreateImpersonatedUserAppDirectory(string sAMAccountName) {
            string impUserAppDir = X509Directory.GetImpersonatedUserHomeDirectory(sAMAccountName);
            if (!Directory.Exists(impUserAppDir)) {
                Directory.CreateDirectory(impUserAppDir);
                DirectoryInfo DirInfo = new DirectoryInfo(impUserAppDir);
                DirectorySecurity DirSec = DirInfo.GetAccessControl();
                DirSec.AddAccessRule(new FileSystemAccessRule(sAMAccountName, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                DirInfo.SetAccessControl(DirSec);
            }
        }
    }
}
