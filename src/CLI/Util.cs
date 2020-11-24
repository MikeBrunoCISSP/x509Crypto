//using System;
//using System.Collections.Generic;
//using System.IO;
//using Org.X509Crypto;

//namespace X509CryptoExe
//{
//    partial class Program
//    {
//        private static bool AddSecret(string secretName, string ciphertext, X509Alias Alias)
//        {
//            bool secretAdded = false;
//            KeyValuePair<string, string> tuple = new KeyValuePair<string, string>(secretName, ciphertext);
//            try
//            {
//                Alias.AddSecret(tuple, AllowSecretOverwrite.No);
//                secretAdded = true;
//            }
//            catch (X509SecretAlreadyExistsException ex)
//            {
//                if (Util.WarnConfirm(ex.Message, Constants.Affirm))
//                {
//                    Alias.AddSecret(tuple, AllowSecretOverwrite.Yes);
//                    secretAdded = true;
//                }
//            }

//            if (secretAdded)
//            {
//                Alias.Commit();
//                ConsoleMessage($"Secret {secretName} has been added to {nameof(X509Alias)} {Alias.Name} in the {Alias.Context.Name} {nameof(X509Context)}");
//            }

//            return secretAdded;
//        }
//    }
//}
