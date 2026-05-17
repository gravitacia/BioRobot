using System;
using System.Collections.Generic;
using System.Text;

namespace BioRobot.Core.Analyzers
{
    public class ExtractedString
    {
        public long Offset { get; set; }
        public string Value { get; set; }
    }

    public static class StringExtractor
    {
        public static List<ExtractedString> Extract(byte[] data, int minLength = 4, bool includeUnicode = true)
        {
            var results = new List<ExtractedString>();

            if (data == null || data.Length == 0)
                return results;

            int i = 0;
            while (i < data.Length)
            {
                if (IsPrintableAscii(data[i]))
                {
                    long start = i;
                    while (i < data.Length && IsPrintableAscii(data[i]))
                    {
                        i++;
                    }

                    int length = (int)(i - start);
                    if (length >= minLength)
                    {
                        string value = Encoding.ASCII.GetString(data, (int)start, length);
                        results.Add(new ExtractedString { Offset = start, Value = value });
                    }
                }
                else if (includeUnicode && i + 1 < data.Length && data[i + 1] == 0 && IsPrintableAscii(data[i]))
                {
                    long start = i;
                    while (i + 1 < data.Length && data[i + 1] == 0 && IsPrintableAscii(data[i]))
                    {
                        i += 2;
                    }

                    int length = (int)((i - start) / 2);
                    if (length >= minLength)
                    {
                        byte[] utf16Bytes = new byte[i - start];
                        Array.Copy(data, start, utf16Bytes, 0, i - start);
                        string value = Encoding.Unicode.GetString(utf16Bytes);
                        results.Add(new ExtractedString { Offset = start, Value = value });
                    }
                }
                else
                {
                    i++;
                }
            }

            return results;
        }
        private static bool IsPrintableAscii(byte b)
        {
            return (b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13;
        }
    }
}