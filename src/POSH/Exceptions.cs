using System;

namespace X509CryptoPOSH {
    public class InvalidParametersException : Exception {
        public InvalidParametersException(string paramName1, string paramName2)
            : base($"Either the '{paramName1}' or the '{paramName2}' must be specified, but not both") { }
    }
}
