using BioRobot.Core.Parsers;
using BioRobot.Core.Models;
using BioRobot.Core.Analyzers;

namespace BioRobot.Commands;

public class AnalyzeCommand : ICommand
{
    public string Name => "analyze";
    public string Description => "Full DNA analysis (sections, imports, entropy, strings, packer, risk score)";

    public int Execute(string[] args)
    {
        string filePath = null;
        bool exportJson = false;
        string jsonOutputPath = null;
        bool includeStrings = true;
        int stringLimit = 50;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i].ToLower())
            {
                case "--json":
                    exportJson = true;
                    break;
                case "--output":
                case "-o":
                    if (i + 1 < args.Length)
                        jsonOutputPath = args[++i];
                    break;
                case "--no-strings":
                    includeStrings = false;
                    break;
                case "--limit":
                case "-l":
                    if (i + 1 < args.Length)
                        stringLimit = int.Parse(args[++i]);
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
            Console.WriteLine($"\n[+] BioRobot - Full DNA Analysis: {filePath}\n");
            Console.WriteLine(new string('═', 60));

            FileType fileType = FileTypeDetector.Detect(filePath);
            BinaryInfo binaryInfo;

            if (fileType == FileType.PeExe || fileType == FileType.PeDll)
            {
                var parser = new PeParser(filePath);
                binaryInfo = parser.Parse();
            }
            else
            {
                var parser = new RawBinaryParser(filePath);
                binaryInfo = parser.Parse();
            }
            List<ExtractedString> strings = null;
            if (includeStrings)
            {
                byte[] fileBytes = File.ReadAllBytes(filePath);
                strings = StringExtractor.Extract(fileBytes, 4, true);
            }

            var detection = RiskScorer.Analyze(binaryInfo);
            string packer = null;
            if (fileType == FileType.PeExe || fileType == FileType.PeDll)
            {
                packer = PackerDetector.Detect(binaryInfo);
            }

            binaryInfo.Detection = detection;

            Console.WriteLine("\n[+] FILE METADATA");
            Console.WriteLine(new string('-', 60));
            Console.WriteLine($"  File Path:  {binaryInfo.FilePath}");
            Console.WriteLine($"  File Size:  {binaryInfo.FileSize:N0} bytes");
            Console.WriteLine($"  MD5:        {binaryInfo.Md5}");
            Console.WriteLine($"  SHA256:     {binaryInfo.Sha256}");
            Console.WriteLine($"  Type:       {binaryInfo.Type}");
            if (fileType == FileType.PeExe || fileType == FileType.PeDll)
            {
                Console.WriteLine($"  64-bit:     {(binaryInfo.Is64Bit ? "Yes" : "No")}");
                Console.WriteLine($"  Entry Point: 0x{binaryInfo.EntryPointRva:X8}");
                Console.WriteLine($"  Image Base: 0x{binaryInfo.ImageBase:X16}");
            }

            Console.WriteLine("\n[+] SECTION ENTROPY ANALYSIS");
            Console.WriteLine(new string('-', 60));
            Console.WriteLine($"{"Name",-12} {"Entropy",-8} {"Indicator",-10}");
            Console.WriteLine(new string('-', 60));

            foreach (var section in binaryInfo.Sections)
            {
                string indicator = section.Entropy > 7.0 ? "[!] HIGH" : "[-] OK";
                Console.WriteLine($"  {section.Name,-12} {section.Entropy,-8:F2} {indicator}");
            }

            if ((fileType == FileType.PeExe || fileType == FileType.PeDll) && binaryInfo.Imports.Count > 0)
            {
                Console.WriteLine("\n[+] IMPORT TABLE");
                Console.WriteLine(new string('-', 60));

                int totalFunctions = binaryInfo.Imports.Sum(i => i.Functions.Count);
                Console.WriteLine($"  Total DLLs: {binaryInfo.Imports.Count}");
                Console.WriteLine($"  Total Functions: {totalFunctions}\n");

                Console.WriteLine($"{"DLL Name",-35} {"Functions",-10}");
                Console.WriteLine(new string('-', 50));

                foreach (var import in binaryInfo.Imports.Take(15))
                {
                    Console.WriteLine($"  {import.DllName,-35} {import.Functions.Count,-10}");
                }

                if (binaryInfo.Imports.Count > 15)
                    Console.WriteLine($"  ... and {binaryInfo.Imports.Count - 15} more DLLs");

                if (detection.SuspiciousImports.Count > 0)
                {
                    Console.WriteLine("\n[!] Suspicious APIs Found:");
                    foreach (var api in detection.SuspiciousImports.Take(10))
                    {
                        Console.WriteLine($"    - {api}");
                    }
                    if (detection.SuspiciousImports.Count > 10)
                        Console.WriteLine($"    ... and {detection.SuspiciousImports.Count - 10} more");
                }
            }

            if (includeStrings && strings != null && strings.Count > 0)
            {
                Console.WriteLine($"\n[+] EXTRACTED STRINGS (first {Math.Min(strings.Count, stringLimit)} of {strings.Count})");
                Console.WriteLine(new string('-', 60));

                for (int i = 0; i < Math.Min(strings.Count, stringLimit); i++)
                {
                    string value = strings[i].Value;
                    if (value.Length > 50)
                        value = value.Substring(0, 47) + "...";
                    Console.WriteLine($"  0x{strings[i].Offset:X8}  {value}");
                }

                if (strings.Count > stringLimit)
                    Console.WriteLine($"\n  [...] Use --limit <n> to show more");
            }
            else if (includeStrings && (strings == null || strings.Count == 0))
            {
                Console.WriteLine("\n[!] No readable strings found");
            }

            if (!string.IsNullOrEmpty(packer))
            {
                Console.WriteLine("\n[!] PACKER DETECTED");
                Console.WriteLine(new string('-', 60));
                Console.WriteLine($"  {packer}");

                if (packer == "UPX")
                {
                    Console.WriteLine("\n  Unpacking suggestion:");
                    Console.WriteLine("    upx -d <file>");
                }
            }

            Console.WriteLine("\n[+] RISK ASSESSMENT");
            Console.WriteLine(new string('-', 60));
            Console.WriteLine($"  Risk Score:  {detection.RiskScore}/100");
            Console.WriteLine($"  Verdict:     {(detection.RiskScore >= 60 ? "MALICIOUS" : (detection.RiskScore >= 30 ? "SUSPICIOUS" : "CLEAN"))}");

            if (detection.HighEntropySections.Count > 0)
            {
                Console.WriteLine($"\n  [!] High entropy sections:");
                foreach (var section in detection.HighEntropySections.Take(5))
                {
                    Console.WriteLine($"      - {section}");
                }
            }

            if (exportJson)
            {
                string outputPath = jsonOutputPath ?? $"{filePath}.json";
                string json = JsonExporter.Export(binaryInfo, detection);
                File.WriteAllText(outputPath, json);
                Console.WriteLine($"\n[+] JSON report saved to: {outputPath}");
            }

            Console.WriteLine("\n[+] Analysis complete");
            Console.WriteLine(new string('═', 60));
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
        Console.WriteLine("BioRobot - Full DNA Analysis Command");
        Console.WriteLine("\nUsage:");
        Console.WriteLine("  biorobot analyze <file> [options]");
        Console.WriteLine("\nOptions:");
        Console.WriteLine("  --json               Export results to JSON");
        Console.WriteLine("  --output, -o <file>  JSON output path (default: <file>.json)");
        Console.WriteLine("  --no-strings         Skip string extraction (faster)");
        Console.WriteLine("  --limit, -l <n>      Max strings to display (default: 50)");
        Console.WriteLine("  --help, -h           Show this help");
        Console.WriteLine("\nExamples:");
        Console.WriteLine("  biorobot analyze malware.exe");
        Console.WriteLine("  biorobot analyze notepad.exe --json");
        Console.WriteLine("  biorobot analyze suspicious.bin --limit 100");
    }
}