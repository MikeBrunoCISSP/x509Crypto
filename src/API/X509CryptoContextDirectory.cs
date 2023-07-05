using System;
using System.IO;

namespace Org.X509Crypto;

class X509CryptoContextDirectory {
    private const string USER_DIR_PLACEHOLDER = "[USER]";
    private const string APP_DIR_NAME         = "x509crypto";

    private static readonly string _userDirTemplate = @$"C:\Users\{USER_DIR_PLACEHOLDER}\AppData\Local\{APP_DIR_NAME}";

    internal X509CryptoContextDirectory(X509CryptoContextFlags contextFlags) {
        DirPath = contextFlags.HasFlag(X509CryptoContextFlags.User)
            ? _userDirTemplate.Replace(USER_DIR_PLACEHOLDER, Environment.UserName)
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), APP_DIR_NAME);

        if (contextFlags.HasFlag(X509CryptoContextFlags.WriteAccess)) {
            Directory.CreateDirectory(DirPath);
        }
    }

    internal string DirPath { get; set; }
}