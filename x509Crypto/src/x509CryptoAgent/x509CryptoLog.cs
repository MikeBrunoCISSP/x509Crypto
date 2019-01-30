using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace X509Crypto
{

    /// <summary>
    /// Supported logging levels.  Default logging level is INFO
    /// </summary>
    public enum Criticality
    {
        /// <summary>
        /// Critical errors
        /// </summary>
        CRITICAL = 0,

        /// <summary>
        /// Standard errors
        /// </summary>
        ERROR = 1,

        /// <summary>
        /// Warnings
        /// </summary>
        WARNING = 2,

        /// <summary>
        /// Informational messages
        /// </summary>
        INFO = 3,

        /// <summary>
        /// Verbose messages
        /// </summary>
        VERBOSE = 4,

        /// <summary>
        /// Extremely verbose messages
        /// </summary>
        MASSIVE = 5
    }

    /// <summary>
    /// A static class which provides access to an activity log maintained by the x509Crypto module.  Log contents are maintained in a string expression.  Logging verbosity is configurable
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
        /// Gets the current conents of the log in a string expression
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

        /// <summary>
        /// Write a critical log message
        /// </summary>
        /// <param name="text">log message text</param>
        /// <param name="messageType">Message type label (default: "<see cref="DEFAULT_MESSAGE_TYPE"/>")</param>
        /// <param name="writeToEventLog">Indicates whether the message will be written to the local application event log (default is true)</param>
        /// <param name="writeToScreen">Indicates whether the message will be displayed on in the console (default is true)</param>
        public static void Critical(string text, string messageType = DEFAULT_MESSAGE_TYPE, bool writeToEventLog = true, bool writeToScreen = true)
        {
            messageLevel = Criticality.CRITICAL;
            string message = TimeStamp() + LevelLabel(Criticality.CRITICAL) + TypeLabel(messageType) + text;
            Write(Criticality.CRITICAL, message, writeToEventLog);

            if (writeToScreen)
                Console.WriteLine(text);
        }

        /// <summary>
        /// Write an error log message
        /// </summary>
        /// <param name="text">log message text</param>
        /// <param name="messageType">Message type label (default: "<see cref="DEFAULT_MESSAGE_TYPE"/>")</param>
        /// <param name="writeToEventLog">Indicates whether the message will be written to the local application event log (default is true)</param>
        /// <param name="writeToScreen">Indicates whether the message will be displayed on in the console (default is true)</param>
        public static void Error(string text, string messageType = DEFAULT_MESSAGE_TYPE, bool writeToEventLog = true, bool writeToScreen = true)
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

        /// <summary>
        /// Write a warning log message
        /// </summary>
        /// <param name="text">log message text</param>
        /// <param name="messageType">Message type label (default: "<see cref="DEFAULT_MESSAGE_TYPE"/>")</param>
        /// <param name="writeToEventLog">Indicates whether the message will be written to the local application event log (default is true)</param>
        /// <param name="writeToScreen">Indicates whether the message will be displayed on in the console (default is true)</param>
        public static void Warning(string text, string messageType = DEFAULT_MESSAGE_TYPE, bool writeToEventLog = true, bool writeToScreen = true)
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

        /// <summary>
        /// Write an informational log message
        /// </summary>
        /// <param name="text">log message text</param>
        /// <param name="messageType">Message type label (default: "<see cref="DEFAULT_MESSAGE_TYPE"/>")</param>
        /// <param name="writeToEventLog">Indicates whether the message will be written to the local application event log (default is false)</param>
        /// <param name="writeToScreen">Indicates whether the message will be displayed on in the console (default is false)</param>
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

        /// <summary>
        /// Write a verbose log message
        /// </summary>
        /// <param name="text">log message text</param>
        /// <param name="messageType">log message type label</param>
        /// <param name="writeToEventLog">Indicates whether the message will be written to the local application event log (default is false)</param>
        /// <param name="writeToScreen">Indicates whether the message will be displayed on in the console (default is false)</param>
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

        /// <summary>
        /// Write an extremely verbose log message
        /// </summary>
        /// <param name="text">log message text</param>
        /// <param name="messageType">log message type label</param>
        /// <param name="writeToEventLog">Indicates whether the message will be written to the local application event log (default is false)</param>
        /// <param name="writeToScreen">Indicates whether the message will be displayed on in the console (default is false)</param>
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

        /// <summary>
        /// Write a string literal to the log (without a timestamp, label, etc)
        /// </summary>
        /// <param name="text">message text</param>
        /// <param name="lvl">Level of criticality the log is currently set to include.  If this message does not meet that criteria, it will not be recorded in the log</param>
        /// <param name="indent">Indicates whether the message text will be precluded by an indentation for readability (default is true)</param>
        public static void Echo(string text, Criticality lvl = Criticality.INFO, bool indent = true)
        {
            messageLevel = lvl;

            if (level >= messageLevel)
            {
                string message = (indent ? INDENT.PadRight(maxTypeLength + 2) + text : text);
                AppendLog(message);
            }
        }

        /// <summary>
        /// Converts a .NET exception into a log message
        /// </summary>
        /// <param name="ex">A .NET exception object</param>
        /// <param name="lvl">Level of criticality the log is currently set to include.  If this message does not meet that criteria, it will not be recorded in the log</param>
        /// <param name="messageType">Message type label (default: "<see cref="DEFAULT_MESSAGE_TYPE"/>")</param>
        /// <param name="text"></param>
        /// <param name="writeToEventLog"></param>
        /// <param name="writeToScreen"></param>
        public static void Exception(Exception ex, Criticality lvl = Criticality.ERROR, string messageType = DEFAULT_MESSAGE_TYPE, string text = @"An exception occurred", bool writeToEventLog = true, bool writeToScreen = true)
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

        /// <summary>
        /// Appends a blank line in the log
        /// </summary>
        /// <param name="lvl">Level of criticality the log is currently set to include.  If this message does not meet that criteria, it will not be recorded in the log</param>
        public static void Linefeed(Criticality lvl = Criticality.INFO)
        {
            messageLevel = lvl;
            if (level >= messageLevel)
                AppendLog(string.Empty);
        }

        /// <summary>
        /// Writes the current contents of the log to the indicated text file
        /// </summary>
        /// <param name="path">The fully-qualified path to the text file in which to write the log contents</param>
        /// <param name="overwriteExisting">Indicates whether to overwrite the file if it already exists (default is true).  If false and the file exists, the log contents will be appended to the file</param>
        public static void WriteToFile(string path, bool overwriteExisting = true)
        {
            if (overwriteExisting)
            {
                File.Delete(path);
                File.WriteAllText(path, contents);
            }
            else
            {
                if (File.Exists(path))
                {
                    File.AppendText("\r\n");
                    File.AppendAllText(path, contents);
                }
                else
                    File.WriteAllText(path, contents);
            }

        }

        #endregion

        #region Private Methods

        private static void WriteToEventLog(string message, EventLogEntryType entryType = EventLogEntryType.Information)
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
