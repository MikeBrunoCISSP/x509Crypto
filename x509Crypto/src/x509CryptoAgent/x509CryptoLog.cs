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

        private static Level level = Level.INFO;
        private static Level messageLevel = Level.INFO;

        private static string contents = string.Empty;

        #region Public-facing

        /// <summary>
        /// Supported logging levels
        /// </summary>
        public enum Level
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
            /// Almost everything is logged (mostly for internal debugging purposes)
            /// </summary>
            MASSIVE = 5
        }

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
        public static void SetLevel(Level newLevel)
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
                    level = Level.CRITICAL;
                    break;
                case "ERROR":
                    level = Level.ERROR;
                    break;
                case "WARNING":
                    level = Level.WARNING;
                    break;
                case "INFO":
                    level = Level.INFO;
                    break;
                case "VERBOSE":
                    level = Level.VERBOSE;
                    break;
                case "MASSIVE":
                    level = Level.MASSIVE;
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

        #endregion

        #region Private Methods

        private static string LevelLabel(Level lvl)
        {
            string label = string.Empty;

            switch (lvl)
            {
                case Level.CRITICAL:
                    label = @"<CRIT>";
                    break;
                case Level.ERROR:
                    label = @"<ERROR>";
                    break;
                case Level.WARNING:
                    label = @"<WARN >";
                    break;
                case Level.INFO:
                    label = @"<INFO >";
                    break;
                case Level.VERBOSE:
                    label = @"<VERB >";
                    break;
                case Level.MASSIVE:
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

        private static void Write(Level level, string message, bool writeToEventLog)
        {
            AppendLog(message);

            if (writeToEventLog)
            {
                EventLogEntryType entryType = EventLogEntryType.Information;
                if (level <= Level.ERROR)
                    entryType = EventLogEntryType.Error;
                else
                {
                    if (level == Level.WARNING)
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

        #region Internal Methods

        internal static void Critical(string text, string messageType = DEFAULT_MESSAGE_TYPE, bool writeToEventLog = false)
        {
            messageLevel = Level.CRITICAL;
            string message = TimeStamp() + LevelLabel(Level.CRITICAL) + TypeLabel(messageType) + text;
            Write(Level.CRITICAL, message, writeToEventLog);

        }

        internal static void Error(string text, string messageType = DEFAULT_MESSAGE_TYPE, bool writeToEventLog = false)
        {
            messageLevel = Level.ERROR;
            string message;

            if (level >= messageLevel)
            {
                message = TimeStamp() + LevelLabel(messageLevel) + TypeLabel(messageType) + text;
                Write(Level.ERROR, message, writeToEventLog);
            }
        }

        internal static void Warning(string text, string messageType = DEFAULT_MESSAGE_TYPE, bool writeToEventLog = false)
        {
            messageLevel = Level.WARNING;
            string message;

            if (level >= messageLevel)
            {
                message = TimeStamp() + LevelLabel(messageLevel) + TypeLabel(messageType) + text;
                Write(Level.WARNING, message, writeToEventLog);
            }
        }

        internal static void Info(string text, string messageType = DEFAULT_MESSAGE_TYPE, bool writeToEventLog = false)
        {
            messageLevel = Level.INFO;
            string message;

            if (level >= messageLevel)
            {
                message = TimeStamp() + LevelLabel(messageLevel) + TypeLabel(messageType) + text;
                Write(Level.INFO, message, writeToEventLog);
            }
        }

        internal static void Verbose(string text, string messageType = DEFAULT_MESSAGE_TYPE, bool writeToEventLog = false)
        {
            messageLevel = Level.VERBOSE;
            string message;

            if (level >= messageLevel)
            {
                message = TimeStamp() + LevelLabel(messageLevel) + TypeLabel(messageType) + text;
                Write(Level.VERBOSE, message, writeToEventLog);
            }
        }


        internal static void Massive(string text, string messageType = DEFAULT_MESSAGE_TYPE, bool writeToEventLog = false)
        {
            messageLevel = Level.MASSIVE;
            string message;

            if (level >= messageLevel)
            {
                message = TimeStamp() + LevelLabel(messageLevel) + TypeLabel(messageType) + text;
                Write(Level.MASSIVE, message, writeToEventLog);
            }
        }

        internal static void Echo(string text, Level lvl = Level.INFO, bool indent = true)
        {
            messageLevel = lvl;

            if (level >= messageLevel)
            {
                string message = (indent ? INDENT.PadRight(maxTypeLength + 2) + text : text);
                AppendLog(message);
            }
        }

        internal static void Exception(Exception ex, Level lvl = Level.ERROR, string messageType = DEFAULT_MESSAGE_TYPE, string text = @"An exception occurred")
        {
            messageLevel = lvl;

            if (level >= messageLevel)
            {
                AppendLog(TimeStamp() + LevelLabel(lvl) + TypeLabel(messageType) + text);
                string[] lines = ex.ToString().Split(new string[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
                foreach (string line in lines)
                    Echo(line, lvl);
            }
        }

        internal static void Linefeed(Level lvl = Level.INFO)
        {
            messageLevel = lvl;
            if (level >= messageLevel)
                AppendLog(string.Empty);
        }

        internal static void LogCommandResults(string command, string stdOut, string stdErr)
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

        internal static void WriteToEventLog(string message, EventLogEntryType entryType = EventLogEntryType.Information)
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
