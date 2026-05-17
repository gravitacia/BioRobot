using BioRobot.Core.Parsers;
using BioRobot.Core.Models;
using BioRobot.Core.Analyzers;

namespace BioRobot.Commands;

public class ScanCommand : ICommand
{
    public string Name => "scan";
    public string Description => "Scan a PE file and display basic information";

    public int Execute(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("[-] Error: Missing file path");
            Console.WriteLine("Usage: biorobot scan <file>");
            return 1;
        }

        string filePath = args[0];

        if (!File.Exists(filePath))
        {
            Console.WriteLine($"[-] Error: File not found - {filePath}");
            return 1;
        }

        try
        {
            Console.WriteLine($"\n[+] BioRobot - Scanning: {filePath}\n");

            var parser = new PeParser(filePath);
            var binaryInfo = parser.Parse();

            Console.WriteLine($"[+] File Size: {binaryInfo.FileSize:N0} bytes");
            Console.WriteLine($"[+] MD5: {binaryInfo.Md5}");
            Console.WriteLine($"[+] SHA256: {binaryInfo.Sha256}");
            Console.WriteLine($"[+] 64-bit: {(binaryInfo.Is64Bit ? "Yes" : "No")}");
            Console.WriteLine($"[+] Entry Point RVA: 0x{binaryInfo.EntryPointRva:X8}");
            Console.WriteLine($"[+] Image Base: 0x{binaryInfo.ImageBase:X16}\n");

            Console.WriteLine("[+] Sections:");
            Console.WriteLine(new string('-', 75));
            Console.WriteLine($"{"Name",-10} {"RVA",-12} {"RawSize",-10} {"Entropy",-10} {"Indicator",-10}");
            Console.WriteLine(new string('-', 75));

            foreach (var section in binaryInfo.Sections)
            {
                string indicator = section.Entropy > 7.0 ? "[!] HIGH" : "[-] OK";
                Console.WriteLine($"{section.Name,-10} 0x{section.VirtualAddress:X8} {section.RawSize,-10} {section.Entropy:F2}     {indicator}");
            }

            Console.WriteLine(new string('-', 75));

            if (binaryInfo.Imports.Count > 0)
            {
                Console.WriteLine($"\n[+] Imports: {binaryInfo.Imports.Count} DLLs");

                int totalFunctions = 0;
                foreach (var import in binaryInfo.Imports)
                {
                    totalFunctions += import.Functions.Count;
                }
                Console.WriteLine($"[+] Total imported functions: {totalFunctions}\n");

                Console.WriteLine($"{"DLL Name",-35} {"Functions",-10}");
                Console.WriteLine(new string('-', 50));

                foreach (var import in binaryInfo.Imports.Take(10))
                {
                    Console.WriteLine($"{import.DllName,-35} {import.Functions.Count,-10}");
                }

                if (binaryInfo.Imports.Count > 10)
                {
                    Console.WriteLine($"\n[...] and {binaryInfo.Imports.Count - 10} more DLLs");
                }
            }
            else
            {
                Console.WriteLine("[!] No imports found (might be packed or malformed)");
            }

            string detectedPacker = PackerDetector.Detect(binaryInfo);
            if (!string.IsNullOrEmpty(detectedPacker))
            {
                Console.WriteLine($"\n[!] Packer Detected: {detectedPacker}");
            }

            Console.WriteLine("\n[+] Risk Assessment:");
            var detection = RiskScorer.Analyze(binaryInfo);

            Console.WriteLine($"    Risk Score: {detection.RiskScore}/100");
            Console.WriteLine($"    Verdict: {detection.Verdict}");

            if (detection.HighEntropySections.Count > 0)
            {
                Console.WriteLine($"    [!] High entropy sections: {string.Join(", ", detection.HighEntropySections)}");
            }

            if (detection.SuspiciousImports.Count > 0)
            {
                var topImports = detection.SuspiciousImports.Take(5);
                Console.WriteLine($"    [!] Suspicious APIs: {string.Join(", ", topImports)}");
                if (detection.SuspiciousImports.Count > 5)
                    Console.WriteLine($"        ... and {detection.SuspiciousImports.Count - 5} more");
            }

            Console.WriteLine("\n[+] Scan complete");
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error: {ex.Message}");
            return 1;
        }
    }
}