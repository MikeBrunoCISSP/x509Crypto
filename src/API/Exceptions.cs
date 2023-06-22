using System;

namespace Org.X509Crypto {
    /// <summary>
    /// Thrown when a presumed existing X509Alias is referenced from a specified X509Context, but the X509Alias is not found.
    /// </summary>
    public class X509AliasNotFoundException : Exception {
        public X509AliasNotFoundException(X509Alias Alias)
            : base($"No {nameof(X509Alias)} by the name {Alias.Name} exists in the {Alias.Context.Name} context") { }

        internal X509AliasNotFoundException(string thumbprint, X509Context Context)
            : base($"No {nameof(X509Alias)} exists in the {Context.Name} {nameof(X509Context)} containing an encryption certificate with thumbprint '{thumbprint}'") { }
    }

    /// <summary>
    /// Thrown when an X509Alias is attempted to be committed, but it already exists in the target X509Context.
    /// </summary>
    public class X509AliasAlreadyExistsException : Exception {
        /// <summary>
        /// Instantiates an X509AliasAlreadyExistsException
        /// </summary>
        /// <param name="Alias">The X509Alias that already exists</param>
        public X509AliasAlreadyExistsException(X509Alias Alias)
            : base($"An X509Alias named \"{Alias.Name}\" already exists in the {Alias.Context.Name} context.") { }
    }

    /// <summary>
    /// Thrown if an X509Secret is attempted to be added to an X509Alias, and the alias already contains a secret with the same name.
    /// </summary>
    public class X509SecretAlreadyExistsException : Exception {
        internal X509SecretAlreadyExistsException(X509Alias Alias, X509Secret Secret)
            : base($"An X509Secret with identifier \"{Secret.Key}\" already exists in the \"{Alias.Name}\" alias.") { }
    }

    /// <summary>
    /// Thrown when there is no suitable encryption certificate found in the specified X509Context with the specified thumbprint value
    /// </summary>
    public class X509CryptoCertificateNotFoundException : Exception {
        /// <summary>
        /// Instantiates an X509CryptoCertificateNotFoundException
        /// </summary>
        /// <param name="thumbprint">The thumbprint of the certificate which could not be located in the specified X509Context</param>
        /// <param name="Context">The X509Context which was checked for the encryption certificate</param>
        public X509CryptoCertificateNotFoundException(string thumbprint, X509Context Context)
            : base($"A certificate with thumbprint \"{thumbprint}\" was not found in the \"{Context.Name}\" context.") { }
    }

    /// <summary>
    /// Thrown when an unrecognized expression is passed to X509Context.Select()
    /// </summary>
    public class X509ContextNotSupported : Exception {
        internal X509ContextNotSupported(string contextName)
            : base($"\"{contextName}\": Unsupported X509Context name. Valid entries are \"{X509ContextName.User}\" and \"{X509ContextName.System}\".") { }
    }

    /// <summary>
    /// Thrown if a thumbprint or artifact name is not found in the specified X509Alias
    /// </summary>
    public class X509AliasAttributeNotFoundException : Exception {
        internal X509AliasAttributeNotFoundException(string identifier, string aliasName)
            : base($"Attribute \"{identifier}\" not found in alias \"{aliasName}\"") { }
    }

    /// <summary>
    /// Thrown if the current thread does not have write permissions to the specified directory
    /// </summary>
    public class X509DirectoryRightsException : Exception {
        internal X509DirectoryRightsException(string contextName, string directory, bool writeAccessRequested)
            : base($"Insufficient rights to {(writeAccessRequested ? @"write to" : @"read from")} the {contextName} directory ({directory})") { }
    }

    /// <summary>
    /// Thrown to indicate an otherwise unclassified exception
    /// </summary>
    public class X509CryptoException : Exception {
        /// <summary>
        /// Throws an exception with the indicated message
        /// </summary>
        /// <param name="message">The message to display in the exception</param>
        public X509CryptoException(string message)
            : base(message) { }

        /// <summary>
        /// Throws an exception with the indicated message and includes an inner exception
        /// </summary>
        /// <param name="message">The message to display in the exception</param>
        /// <param name="innerException">The exception that actually occurred to prompt this exception</param>
        public X509CryptoException(string message, Exception innerException)
            : base(message, innerException) { }
    }
}
