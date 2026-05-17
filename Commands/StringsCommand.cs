using BioRobot.Core.Analyzers;

namespace BioRobot.Commands;

public class StringsCommand : ICommand
{
    public string Name => "strings";
    public string Description => "Extract readable strings from a binary file";

    public int Execute(string[] args)
    {
        string filePath = null;
        int minLength = 4;
        bool includeUnicode = true;
        int limit = 100;
        string outputFile = null;
        bool showOffset = true;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i].ToLower())
            {
                case "--min-length":
                case "-m":
                    if (i + 1 < args.Length)
                        minLength = int.Parse(args[++i]);
                    break;
                case "--no-unicode":
                case "-nu":
                    includeUnicode = false;
                    break;
                case "--limit":
                case "-l":
                    if (i + 1 < args.Length)
                        limit = int.Parse(args[++i]);
                    break;
                case "--output":
                case "-o":
                    if (i + 1 < args.Length)
                        outputFile = args[++i];
                    break;
                case "--no-offset":
                    showOffset = false;
                    break;
                case "--help":
                case "-h":
                    PrintUsage();
                    return 0;
                default:
                    if (filePath == null)
                        filePath = args[i];
                    break;
            }
        }

        if (filePath == null)
        {
            Console.WriteLine("[-] Error: Missing file path");
            PrintUsage();
            return 1;
        }

        if (!File.Exists(filePath))
        {
            Console.WriteLine($"[-] Error: File not found - {filePath}");
            return 1;
        }

        try
        {
            Console.WriteLine($"\n[+] BioRobot - Extracting strings from: {filePath}");
            Console.WriteLine($"[+] Minimum length: {minLength} | Unicode: {(includeUnicode ? "Yes" : "No")} | Limit: {limit}\n");

            byte[] fileBytes = File.ReadAllBytes(filePath);

            var strings = StringExtractor.Extract(fileBytes, minLength, includeUnicode);

            Console.WriteLine($"[+] Found {strings.Count} total strings\n");

            if (strings.Count == 0)
            {
                Console.WriteLine("[!] No readable strings found");
                return 0;
            }

            int displayCount = Math.Min(strings.Count, limit);

            if (showOffset)
            {
                Console.WriteLine($"{"Offset",-12} {"String",-50}");
                Console.WriteLine(new string('-', 65));

                for (int i = 0; i < displayCount; i++)
                {
                    string value = strings[i].Value;
                    if (value.Length > 47)
                        value = value.Substring(0, 44) + "...";

                    Console.WriteLine($"0x{strings[i].Offset:X8}  {value}");
                }
            }
            else
            {
                for (int i = 0; i < displayCount; i++)
                {
                    Console.WriteLine(strings[i].Value);
                }
            }

            if (strings.Count > limit)
            {
                Console.WriteLine($"\n[...] Showing {limit} of {strings.Count} strings.");
                Console.WriteLine("    Use --limit <n> to show more");
            }

            if (!string.IsNullOrEmpty(outputFile))
            {
                using (StreamWriter writer = new StreamWriter(outputFile))
                {
                    foreach (var s in strings)
                    {
                        if (showOffset)
                            writer.WriteLine($"0x{s.Offset:X8}  {s.Value}");
                        else
                            writer.WriteLine(s.Value);
                    }
                }
                Console.WriteLine($"\n[+] Saved {strings.Count} strings to: {outputFile}");
            }

            Console.WriteLine("\n[+] Strings extraction complete");
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error: {ex.Message}");
            return 1;
        }
    }

    private void PrintUsage()
    {
        Console.WriteLine("BioRobot - Strings Extraction Command");
        Console.WriteLine("\nUsage:");
        Console.WriteLine("  biorobot strings <file> [options]");
        Console.WriteLine("\nOptions:");
        Console.WriteLine("  --min-length, -m <n>     Minimum string length (default: 4)");
        Console.WriteLine("  --no-unicode, -nu        Skip UTF-16 strings (ASCII only)");
        Console.WriteLine("  --limit, -l <n>          Maximum strings to display (default: 100)");
        Console.WriteLine("  --output, -o <file>      Save results to file");
        Console.WriteLine("  --no-offset              Hide byte offsets");
        Console.WriteLine("  --help, -h               Show this help");
        Console.WriteLine("\nExamples:");
        Console.WriteLine("  biorobot strings malware.exe");
        Console.WriteLine("  biorobot strings notepad.exe --min-length 6 --limit 50");
        Console.WriteLine("  biorobot strings sample.bin --no-unicode -o strings.txt");
    }
}