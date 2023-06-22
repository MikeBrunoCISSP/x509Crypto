using System;
using System.ComponentModel;
using System.Linq;
using System.Security;
using System.Security.Permissions;
using System.Runtime.InteropServices;
using Org.X509Crypto;
using SimpleImpersonation;

namespace X509CryptoExe
{
    [PermissionSet(SecurityAction.Demand, Name = "FullTrust")]
    partial class Program
    {
        [DllImport("advapi32.dll")]
        public static extern int LogonUser(string lpszUserName, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, ref IntPtr phToken);

        [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LoadUserProfile(IntPtr hToken, ref ProfileInfo lpProfileInfo);

        [StructLayout(LayoutKind.Sequential)]
        public struct ProfileInfo
        {
            public int dwSize;
            public int dwFlags;
            public string lpUserName;
            public string lpProfilePath;
            public string lpDefaultPath;
            public string lpServerName;
            public string lpPolicyPath;
            public IntPtr hProfile;
        }

        private static string ImpUser = string.Empty;
        private static string ImpDomain = string.Empty;

        private static SecureString ImpSecret = new SecureString();
        private static UserCredentials Credentials = null;
        private static bool CurrentlyImpersonating = false;

        private static IntPtr Token = IntPtr.Zero;

        private static string FullyQualifiedImpUser
        {
            get
            {
                return $"{ImpDomain}\\{ImpUser}";
            }
        }

        private static void EnterModeImpersonated()
        {
            bool loadSuccess;
            int errCode;

            try
            {
                X509Context.CreateImpersonatedUserAppDirectory(ImpUser);

                #region Load User Profile

                //Get a token for the impersonated user
                LogonUser(ImpUser, ImpDomain, ImpSecret.ToUnSecureString(), LoginType.LOGON32_LOGON_BATCH, Constants.LOGON32_PROVIDER_DEFAULT, ref Token);

                //Load the impersonated user profile
                ProfileInfo profileInfo = new ProfileInfo();
                profileInfo.dwSize = Marshal.SizeOf(profileInfo);
                profileInfo.lpUserName = ImpUser;
                profileInfo.dwFlags = 1;
                loadSuccess = LoadUserProfile(Token, ref profileInfo);

                if (!loadSuccess)
                {
                    errCode = Marshal.GetLastWin32Error();
                    Win32Exception wex = new Win32Exception(errCode);
                    throw new LoadUserProfileFailedException(FullyQualifiedImpUser, errCode, wex);
                }

                if (profileInfo.hProfile == IntPtr.Zero)
                {
                    errCode = Marshal.GetLastWin32Error();
                    Win32Exception wex = new Win32Exception(errCode);
                    throw new LoadUserProfileFailedException(FullyQualifiedImpUser, errCode, wex);
                }

                #endregion

                Impersonation.RunAsUser(Credentials, LogonType.Batch, () =>
                {
                    EnterMode();
                });
            }
            catch (Win32Exception wex)
            {
                throw new LoadUserProfileFailedException(FullyQualifiedImpUser, wex);
            }
            catch (Exception ex)
            {
                throw new LoadUserProfileFailedException(FullyQualifiedImpUser, ex);
            }
        }

        private static bool EnableImpersonation(string userInfo)
        {
            if (userInfo.Contains('\\'))
            {
                string[] parts = userInfo.Split('\\');
                ImpUser = parts[1];
                ImpDomain = parts[0];
            }
            else
            {
                ImpUser = userInfo;
                ImpDomain = Environment.UserDomainName;
            }

            ImpSecret = Util.GetPassword($"Enter the password for {FullyQualifiedImpUser}", 0);

            if (TryImpersonate())
            {
                CurrentlyImpersonating = true;
            }
            else
            {
                DisableImpersonation();
            }

            return CurrentlyImpersonating;
        }

        private static void DisableImpersonation()
        {
            ImpSecret.Dispose();
            Credentials = null;
            Token = IntPtr.Zero;
            ImpUser = string.Empty;
            ImpDomain = string.Empty;
            CurrentlyImpersonating = false;
        }

        private static void HandleImpersonate()
        {
            if (!(Parameter.ImpUser.IsDefined ^ Parameter.EndImp.IsDefined))
            {
                throw new InvalidArgumentsException($"Either \"{Parameter.ImpUser.Name}\" or \"{Parameter.EndImp.Name}\" must be defined.");
            }

            switch (InCli)
            {
                case true:
                    if (Parameter.EndImp.IsDefined)
                    {
                        if (CurrentlyImpersonating)
                        {
                            DisableImpersonation();
                        }
                        else
                        {
                            throw new InvalidArgumentsException(@"You are currently not impersonating another user.");
                        }
                        return;
                    }
                    if (Parameter.ImpUser.IsDefined)
                    {
                        if (!CurrentlyImpersonating)
                        {
                            EnableImpersonation(Parameter.ImpUser.TextValue);
                        }
                        else
                        {
                            throw new InvalidArgumentsException($"You are already impersonating account {FullyQualifiedImpUser}. Please use \"{Parameter.EndImp.Name}\" to end the current impersonation session");
                        }
                    }
                    break;

                case false:
                    if (Parameter.EndImp.IsDefined)
                    {
                        throw new InvalidArgumentsException(@"You are currently not impersonating another user.");
                    }

                    if (Parameter.ImpUser.IsDefined)
                    {
                        EnableImpersonation(Parameter.ImpUser.TextValue);
                    }
                    InCli = true;
                    break;
            }
        }

        private static bool TryImpersonate()
        {
            string impersonatedUser = string.Empty;

            try
            {
                Credentials = new UserCredentials(ImpDomain, ImpUser, ImpSecret);
                Impersonation.RunAsUser(Credentials, LogonType.Batch, () =>
                {
                    impersonatedUser = Environment.UserName;
                });
                return impersonatedUser.Matches(ImpUser);
            }
            catch (Exception ex)
            {
                throw new LoadUserProfileFailedException(FullyQualifiedImpUser, ex);
            }
        }
    }
}
