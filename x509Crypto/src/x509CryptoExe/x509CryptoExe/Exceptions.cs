using System;
using System.Collections.Generic;
using Org.X509Crypto;

namespace X509CryptoExe
{
    internal class UnrecognizedExpressionException : Exception
    {
        internal UnrecognizedExpressionException(string expression)
            : base($"Unrecognized expression: {expression}")
        { }
    }

    internal class InvalidX509ContextNameException : Exception
    {
        internal InvalidX509ContextNameException(string expression)
            : base($"{expression} is not a {nameof(X509Context)} parameter")
        { }
    }

    internal class InvalidParameterException : Exception
    {
        internal InvalidParameterException(string paramName, string modeName)
            : base($"Paramter {paramName} is not supported by mode {modeName}")
        { }
    }

    internal class InvalidArgumentsException : Exception
    {
        internal InvalidArgumentsException()
            : base($"Wrong number of arguments")
        { }

        internal InvalidArgumentsException(string message)
            : base(message)
        { }

        internal InvalidArgumentsException(string parameterName, string entry)
            : base($"\"{entry}\": not a valid entry for {parameterName}")
        { }

        internal InvalidArgumentsException(string parameterName, int minValue)
            : base($"The value for {parameterName} must be numerical and must be equal to or greater than {minValue}")
        { }

        internal InvalidArgumentsException(string parameterName, string entry, List<ValidSelection> SelectionSet)
            : base($"Unrecognized entry for {parameterName}: \"{entry}\"{SelectionSet.Display()}")
        { }

        internal InvalidArgumentsException(Exception ex)
            : base(@"An exception occurred parsing the command", ex)
        { }
    }
}
