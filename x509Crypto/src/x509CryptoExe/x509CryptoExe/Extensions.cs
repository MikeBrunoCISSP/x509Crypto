using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.X509Crypto;

namespace X509CryptoExe
{
    internal static class Extensions
    {
        internal static T Find<T>(this IEnumerable<T> itemSet, string compareItem)
        {
            foreach(T item in itemSet)
            {
                if (item.ToString().Matches(compareItem))
                {
                    return item;
                }
            }
            throw new UnrecognizedExpressionException(compareItem);
        }

        internal static T Find<T>(this T[] itemSet, string compareItem)
        {
            foreach(T item in itemSet)
            {
                if (item.ToString().Matches(compareItem))
                {
                    return item;
                }
            }
            throw new UnrecognizedExpressionException(compareItem);
        }

        internal static bool Contains(this List<ValidSelection> itemSet, string compareItem)
        {
            return itemSet.Any(p => p.Name.Matches(compareItem));
        }

        internal static X509Context GetContext(this OldMode mode, Parameter param, X509Context DefaultContext = null)
        {
            Parameter Result = mode.GetParameter(param);
            if (Result.IsContext)
            {
                if (param.IsDefined)
                {
                    return Result.SelectedContext;
                }
                else
                {
                    if (DefaultContext != null)
                    {
                        return DefaultContext;
                    }
                    else
                    {
                        throw new Exception($"{param.Name} could not be defined");
                    }
                }
            }
            else
            {
                throw new InvalidX509ContextNameException(param.Name);
            }
        }

        internal static X509Context GetContext(this OldMode mode, Parameter param)
        {
            try
            {
                return mode.Parameters.First(p => p.Name.IsMatch(param.Name)).SelectedContext;
            }
            catch
            {
                throw new InvalidX509ContextNameException(param.Name);
            }
        }

        internal static bool And(this IEnumerable<bool> elements)
        {
            return !elements.Any(p => false);
        }

        internal static bool Or(this IEnumerable<bool> elements)
        {
            return elements.Any(p => true);
        }

        internal static string Display(this List<ValidSelection> itemSet)
        {
            StringBuilder sb = new StringBuilder("\r\nAcceptable entries are:");
            itemSet.ForEach(p => sb.AppendLine(p.Name.Align()));
            return sb.ToString();
        }

        internal static string AsKey(this string key)
        {
            return $"-{key}";
        }

        internal static string Align(this string expression, int indentation = 0, int justification = 0, int elementLength = 0)
        {
            int expressionLength = expression.Length;
            int paddedLength = expressionLength + justification + (Constants.BaseIndent * indentation) - elementLength;
            string adjustedExpression = $"\r\n{expression.PadLeft(paddedLength)}";
            return adjustedExpression;
        }

        internal static int GetPadding(this IEnumerable<string> elements)
        {
            return elements.Aggregate("", (max, cur) => max.Length > cur.Length ? max : cur).Length;
        }

        internal static string InBraces(this string expression)
        {
            return $"{{{expression}}}";
        }

        internal static string InBrackets(this string expression)
        {
            return $"[{expression}]";
        }

        internal static string InQuotes(this string expression)
        {
            return $"\"{expression}\"";
        }

        internal static string BarDelimited(this IEnumerable<string> elements)
        {
            return string.Join("|", elements.ToArray());
        }

        internal static List<string> SplitByLength(this string expression, int maxLength)
        {
            int lastIndex = expression.Length;
            int cursor = 0;
            int walkBack = 0;
            int lineEnd = maxLength;
            List<string> Elements = new List<string>();

            while (true)
            {
                if (lineEnd >= lastIndex)
                {
                    Elements.Add(expression.Substring(cursor, lastIndex - cursor));
                    return Elements;
                }
                else
                {
                    walkBack = lineEnd;
                    while (expression[walkBack] != ' ')
                    {
                        walkBack--;
                    }
                    Elements.Add(expression.Substring(cursor, walkBack - cursor));
                    cursor = walkBack + 1;
                    lineEnd = walkBack + maxLength;
                }
            }
        }

        private static Parameter GetParameter(this OldMode mode, Parameter param)
        {
            Parameter Result = mode.Parameters.FirstOrDefault(p => p.ID == param.ID);
            if (Result == null)
            {
                throw new InvalidParameterException(param.Name, mode.Name);
            }
            return Result;
        }
    }
}
