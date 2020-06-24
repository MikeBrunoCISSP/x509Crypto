using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace X509CryptoExe
{
    internal class Action
    {
        internal Command RequestedCommand { get; private set; }
        internal bool UseClipboard { get; private set; }
        internal bool IsValid { get; private set; }

        internal Action(string[] args, bool inCli)
        {
            int index = 0;

            //Get the Command
            try
            {
                RequestedCommand = Command.Select(args, ref index);
            }
            catch (Exception ex)
            {
                ShowUsage(ex.Message, Usage(inCli));
                return;
            }

            //Get the Mode
            try
            {
                RequestedCommand.GetMode(args, ref index);
            }
            catch (Exception ex)
            {
                string message = string.Empty;
                if (ex is IndexOutOfRangeException)
                {
                    message = UsageExpression.NotEnoughArguments;
                }
                else
                {
                    message = ex.Message;
                }

                ShowUsage(message, RequestedCommand.Usage(inCli));
                return;
            }

            //Get Parameters
            try
            {
                while (index < args.Length)
                {
                    RequestedCommand.SelectedMode.GetParameter(args, ref index);
                }
                UseClipboard = RequestedCommand.SelectedMode.UseClipboard;
            }
            catch (Exception ex)
            {
                ShowUsage(ex.Message, RequestedCommand.SelectedMode.Usage(RequestedCommand.Name, inCli));
                return;
            }

            if (RequestedCommand.SelectedMode.Parameters.Where(p => p.DefinitionRequired)
                                                        .Select(p => p.IsDefined).And())
            {
                IsValid = true;
            }
            else
            {
                ShowUsage(UsageExpression.NotEnoughArguments, RequestedCommand.SelectedMode.Usage(RequestedCommand.Name, inCli));
            }
        }

        internal static string Usage(bool inCli)
        {
            List<string> CommandNames = Command.Collection.Where(p => p.IncludeInHelp)
                                                          .Select(p => p.Name).ToList();
            int padding = CommandNames.GetPadding();

            StringBuilder Expression = new StringBuilder(UsageExpression.Prefix);

            if (!inCli)
            {
                Expression.Append($"{Constants.AssemblyFile} {CommandNames.BarDelimited()}\r\n\r\n{UsageExpression.AvailableCommands}");
            }

            foreach(Command command in Command.Collection.Where(p => p.IncludeInHelp))
            {
                Expression.Append(command.ShowDescription(padding));
            }

            Expression.Append("\r\n");
            return Expression.ToString();
        }

        internal static void ShowUsage(string message, string usage)
        {
            Console.WriteLine($"{message}\r\n\r\n{usage}");
        }
    }
}
