using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace x509Crypto
{

    /// <summary>
    /// Supported logging levels
    /// </summary>
    public enum Criticality
    {
        /// <summary>
        /// Only critical errors will be logged
        /// </summary>
        CRITICAL = 0,

        /// <summary>
        /// All errors will be logged
        /// </summary>
        ERROR = 1,

        /// <summary>
        /// All errors and warnings will be logged.
        /// </summary>
        WARNING = 2,

        /// <summary>
        /// Informational messages, errors and warnings will be logged
        /// </summary>
        INFO = 3,

        /// <summary>
        /// Verbose logging (for diagnostic purposes)
        /// </summary>
        VERBOSE = 4,

        /// <summary>
        /// Almost everything is logged (mostly for public debugging purposes)
        /// </summary>
        MASSIVE = 5
    }

    /// <summary>
    /// A static class which provides access to an activity log maintained by the x509Crypto module.  Logging verbosity is configurable
    /// </summary>
    public static class x509CryptoLog
    {
        const string EVENT_LOG = @"Application";
        const int EVENT_ID = 509;
        const string PREFERRED_EVENT_LOG_SOURCE = @"x509Crypto";
        const string FALLBACK_EVENT_LOG_SOURCE = @".NET Runtime";

        const string sLEVEL_CRITICAL = @"CRITICAL";
        const string sLEVEL_ERROR    = @"ERROR";
        const string sLEVEL_WARNING  = @"WARNING";
        const string sLEVEL_INFO     = @"INFO";
        const string sLEVEL_VERBOSE  = @"VERBOSE";
        const string sLEVEL_MASSIVE  = @"MASSIVE";

        const string DEFAULT_MESSAGE_TYPE = @"General";


        private static string INDENT = @"                                ";
        private static int maxTypeLength = 20;

        private static string eventSource = PREFERRED_EVENT_LOG_SOURCE;
        private static bool eventSourceEstablished = false;

        private static Criticality level = Criticality.INFO;
        private static Criticality messageLevel = Criticality.INFO;

        private static string contents = string.Empty;

        #region Public-facing

        /// <summary>
        /// Gets the current conents of the log
        /// </summary>
        /// <returns>string containing the </returns>
        public static string Get()
        {
            return contents;
        }

        /// <summary>
        /// Changes the current logging verbosity
        /// </summary>
        /// <param name="newLevel">The desired logging level as specified by a value in the "Level" enumeration</param>
        public static void SetLevel(Criticality newLevel)
        {
            level = newLevel;
        }

        /// <summary>
        /// Changes the current logging verbosity
        /// </summary>
        /// <param name="sNewLevel">The desired logging level as specified by a string expression</param>
        public static void SetLevel(string sNewLevel)
        {
            string sanitizedLvl = sNewLevel.ToUpper().Trim();

            switch (sanitizedLvl)
            {
                case "CRITICAL":
                    level = Criticality.CRITICAL;
                    break;
                case "ERROR":
                    level = Criticality.ERROR;
                    break;
                case "WARNING":
                    level = Criticality.WARNING;
                    break;
                case "INFO":
                    level = Criticality.INFO;
                    break;
                case "VERBOSE":
                    level = Criticality.VERBOSE;
                    break;
                case "MASSIVE":
                    level = Criticality.MASSIVE;
                    break;
            }
        }

        /// <summary>
        /// Clears all contents from the log
        /// </summary>
        public static void Clear()
        {
            contents = string.Empty;
        }

        public static void Critical(string text, string messageType = DEFAULT_MESSAGE_TYPE, bool writeToEventLog = false, bool writeToScreen = false)
        {
            messageLevel = Criticality.CRITICAL;
            string message = TimeStamp() + LevelLabel(Criticality.CRITICAL) + TypeLabel(messageType) + text;
            Write(Criticality.CRITICAL, message, writeToEventLog);

            if (writeToScreen)
                Console.WriteLine(text);
        }

        public static void Error(string text, string messageType = DEFAULT_MESSAGE_TYPE, bool writeToEventLog = false, bool writeToScreen = false)
        {
            messageLevel = Criticality.ERROR;
            string message;

            if (level >= messageLevel)
            {
                message = TimeStamp() + LevelLabel(messageLevel) + TypeLabel(messageType) + text;
                Write(Criticality.ERROR, message, writeToEventLog);
            }

            if (writeToScreen)
                Console.WriteLine(text);
        }

        public static void Warning(string text, string messageType = DEFAULT_MESSAGE_TYPE, bool writeToEventLog = false, bool writeToScreen = false)
        {
            messageLevel = Criticality.WARNING;
            string message;

            if (level >= messageLevel)
            {
                message = TimeStamp() + LevelLabel(messageLevel) + TypeLabel(messageType) + text;
                Write(Criticality.WARNING, message, writeToEventLog);
            }

            if (writeToScreen)
                Console.WriteLine(text);
        }

        public static void Info(string text, string messageType = DEFAULT_MESSAGE_TYPE, bool writeToEventLog = false, bool writeToScreen = false)
        {
            messageLevel = Criticality.INFO;
            string message;

            if (level >= messageLevel)
            {
                message = TimeStamp() + LevelLabel(messageLevel) + TypeLabel(messageType) + text;
                Write(Criticality.INFO, message, writeToEventLog);
            }

            if (writeToScreen)
                Console.WriteLine(text);
        }

        public static void Verbose(string text, string messageType = DEFAULT_MESSAGE_TYPE, bool writeToEventLog = false, bool writeToScreen = false)
        {
            messageLevel = Criticality.VERBOSE;
            string message;

            if (level >= messageLevel)
            {
                message = TimeStamp() + LevelLabel(messageLevel) + TypeLabel(messageType) + text;
                Write(Criticality.VERBOSE, message, writeToEventLog);
            }


            if (writeToScreen)
                Console.WriteLine(text);
        }


        public static void Massive(string text, string messageType = DEFAULT_MESSAGE_TYPE, bool writeToEventLog = false, bool writeToScreen = false)
        {
            messageLevel = Criticality.MASSIVE;
            string message;

            if (level >= messageLevel)
            {
                message = TimeStamp() + LevelLabel(messageLevel) + TypeLabel(messageType) + text;
                Write(Criticality.MASSIVE, message, writeToEventLog);
            }

            if (writeToScreen)
                Console.WriteLine(text);
        }

        public static void Echo(string text, Criticality lvl = Criticality.INFO, bool indent = true)
        {
            messageLevel = lvl;

            if (level >= messageLevel)
            {
                string message = (indent ? INDENT.PadRight(maxTypeLength + 2) + text : text);
                AppendLog(message);
            }
        }

        public static void Exception(Exception ex, Criticality lvl = Criticality.ERROR, string messageType = DEFAULT_MESSAGE_TYPE, string text = @"An exception occurred", bool writeToEventLog = false, bool writeToScreen = false)
        {
            messageLevel = lvl;

            if (level >= messageLevel)
            {
                StringBuilder sb = new StringBuilder();
                sb.AppendLine(TimeStamp() + LevelLabel(lvl) + TypeLabel(messageType) + text);
                string[] lines = ex.ToString().Split(new string[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
                foreach (string line in lines)
                    sb.AppendLine(INDENT.PadRight(maxTypeLength + 2) + line);
                Write(Criticality.CRITICAL, sb.ToString(), writeToEventLog);

                if (writeToScreen)
                    Console.WriteLine(sb.ToString());

                sb = null;
            }
        }

        public static void Linefeed(Criticality lvl = Criticality.INFO)
        {
            messageLevel = lvl;
            if (level >= messageLevel)
                AppendLog(string.Empty);
        }

        public static void LogCommandResults(string command, string stdOut, string stdErr)
        {
            string fullMessage;

            if (string.IsNullOrWhiteSpace(stdOut))
                stdOut = @"NULL";
            if (string.IsNullOrWhiteSpace(stdErr))
                stdErr = @"NULL";

            fullMessage = string.Format("Command: {0}\r\n\r\nStandardOutput:\r\n{1}\r\n\r\nStandard Error:\r\n{2}", command, stdOut, stdErr);
            Verbose(string.Format("Command Execution Summary:\r\n{0}", fullMessage));
            WriteToEventLog(fullMessage);
        }

        public static void WriteToEventLog(string message, EventLogEntryType entryType = EventLogEntryType.Information)
        {
            if (!eventSourceEstablished)
            {
                if (!EventLogSourceExists(PREFERRED_EVENT_LOG_SOURCE))
                {
                    try
                    {
                        EventLog.CreateEventSource(PREFERRED_EVENT_LOG_SOURCE, EVENT_LOG);
                    }
                    catch
                    {
                        eventSource = FALLBACK_EVENT_LOG_SOURCE;
                    }
                }

                eventSourceEstablished = true;
            }

            EventLog.WriteEntry(eventSource, message, entryType, EVENT_ID);
        }

        #endregion

        #region Private Methods

        private static string LevelLabel(Criticality lvl)
        {
            string label = string.Empty;

            switch (lvl)
            {
                case Criticality.CRITICAL:
                    label = @"<CRIT>";
                    break;
                case Criticality.ERROR:
                    label = @"<ERROR>";
                    break;
                case Criticality.WARNING:
                    label = @"<WARN >";
                    break;
                case Criticality.INFO:
                    label = @"<INFO >";
                    break;
                case Criticality.VERBOSE:
                    label = @"<VERB >";
                    break;
                case Criticality.MASSIVE:
                    label = @"<MASS >";
                    break;
            }

            return label;
        }

        private static string TypeLabel(string messageType)
        {
            string paddingIndicator = string.Format("{{0,{0}}}", Convert.ToString(maxTypeLength));
            string typeLabel = string.Format("[{0}]", string.Format(paddingIndicator, messageType));
            return typeLabel;
        }

        private static string TimeStamp()
        {
            return string.Format("[{0}]", DateTime.Now.ToString("MM-dd-yy hh:mm:ss.fff"));
        }

        private static void AppendLog(string message)
        {
            contents = @"\r\n" + message;
        }

        private static void Write(Criticality level, string message, bool writeToEventLog)
        {
            AppendLog(message);

            if (writeToEventLog)
            {
                EventLogEntryType entryType = EventLogEntryType.Information;
                if (level <= Criticality.ERROR)
                    entryType = EventLogEntryType.Error;
                else
                {
                    if (level == Criticality.WARNING)
                        entryType = EventLogEntryType.Warning;
                }

                WriteToEventLog(message, entryType);
            }
        }

        private static string GetCallerInfo(StackTrace trace)
        {
            string className = trace.GetFrame(1).GetMethod().ReflectedType.Name;
            string methodName = trace.GetFrame(1).GetMethod().Name;
            return string.Format("{0}.{1}", className, methodName);
        }

        #endregion

        #region public Methods

        private static bool EventLogSourceExists(string sourceToCheck)
        {
            bool result = false;
            try
            {
                result = EventLog.SourceExists(sourceToCheck);
            }
            catch (System.Security.SecurityException) { }

            return result;
        }

        #endregion
    }
}
