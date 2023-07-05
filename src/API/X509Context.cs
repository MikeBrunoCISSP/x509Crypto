using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Org.X509Crypto.Dto;
using Org.X509Crypto.Services;

namespace Org.X509Crypto {
    /// <summary>
    /// Defines the CAPI store, file system location and name for an X509Cryto encryption context
    /// </summary>
    public class X509Context {
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
        public X509CryptoContextFlags ContextFlags { get; private set; }

        internal X509CryptoContextDirectory ContextDirectory { get; set; }

        #region Supported Contexts

        /// <summary>
        /// Provides read-only access to the context of the currently logged in (or impersonated) user.
        /// </summary>
        public static readonly X509Context UserReadOnly = new() {
            ContextFlags = X509CryptoContextFlags.User,
            Name = X509ContextName.User,
            Aliases = new List<string>() { X509ContextName.User, X509ContextName.CurrentUser },
            ContextDirectory = new X509CryptoContextDirectory(X509CryptoContextFlags.User)
        };

        /// <summary>
        /// Provides read/write access to the context of the currently logged in (or impersonated) user.
        /// </summary>
        public static readonly X509Context UserFull = new() {
            ContextFlags = X509CryptoContextFlags.User | X509CryptoContextFlags.WriteAccess,
            Name = X509ContextName.User,
            Aliases = new List<string>() { X509ContextName.User, X509ContextName.CurrentUser },
            ContextDirectory = new X509CryptoContextDirectory(X509CryptoContextFlags.User | X509CryptoContextFlags.WriteAccess)
        };

        /// <summary>
        /// Provides read-only access to the context of the currently logged in (or impersonated) user.
        /// </summary>
        public static readonly X509Context SystemReadOnly = new() {
            ContextFlags = X509CryptoContextFlags.System,
            Name = X509ContextName.System,
            Aliases = new List<string>() { X509ContextName.System, X509ContextName.LocalSystem },
            ContextDirectory = new X509CryptoContextDirectory(X509CryptoContextFlags.System)
        };

        /// <summary>
        /// Provides read/write access to the context of the currently logged in (or impersonated) user.
        /// </summary>
        public static readonly X509Context SystemFull = new() {
            ContextFlags = X509CryptoContextFlags.System | X509CryptoContextFlags.WriteAccess,
            Name = X509ContextName.System,
            Aliases = new List<string>() { X509ContextName.System, X509ContextName.LocalSystem },
            ContextDirectory = new X509CryptoContextDirectory(X509CryptoContextFlags.System | X509CryptoContextFlags.WriteAccess)

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
            return new X509Alias {
                Context = this
            };
        }

        public override bool Equals(object obj) {
            return obj is X509Context other && other.ContextFlags == ContextFlags;
        }

        public override int GetHashCode() {
            return ContextFlags.GetHashCode();
        }

        /// <summary>
        /// Returns a list of X509Alias names available in the current X509Context.
        /// </summary>
        /// <returns></returns>
        public List<string> GetAliasNames() {
            return Directory.Exists(ContextDirectory.DirPath)
                ? Directory.GetFiles(ContextDirectory.DirPath).Select(Path.GetFileNameWithoutExtension).ToList()
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
                CertificateDto dto = CertService.CreateX509CryptCertificate(name, this, keyLength, yearsValid);
                thumbprint = dto.Thumbprint;
            } catch (Exception ex) {
                throw new Exception($"A certificate could not be added to the {Name} {nameof(X509Context)}.", ex);
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
                return SupportedContexts.First(p =>
                    (p.ContextFlags & X509CryptoContextFlags.WriteAccess) == X509CryptoContextFlags.WriteAccess
                    && p.Aliases.Contains(name, StringComparison.OrdinalIgnoreCase));
            } catch {
                throw new X509ContextNotSupported(name);
            }
        }
        /// <summary>
        /// Returns an X509CryptoContext based on the indicated type.
        /// </summary>
        /// <param name="contextFlags">The X509CryptoContextType</param>
        /// <returns></returns>
        public static X509Context Select(X509CryptoContextFlags contextFlags) => SupportedContexts.First(p => p.ContextFlags == contextFlags);
    }
}
