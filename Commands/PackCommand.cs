using BioRobot.Core.Parsers;
using BioRobot.Core.Analyzers;

namespace BioRobot.Commands;

public class PackCommand : ICommand
{
    public string Name => "pack";
    public string Description => "Deep packer/compressor detection and entropy analysis";

    public int Execute(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("[-] Error: Missing file path");
            Console.WriteLine("Usage: biorobot pack <file>");
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
            Console.WriteLine($"\n[+] BioRobot - Packer Analysis: {filePath}\n");

            var parser = new PeParser(filePath);
            var binaryInfo = parser.Parse();

            // Entropy heatmap
            Console.WriteLine("[+] Entropy Heatmap (higher = more random/packed):");
            Console.WriteLine(new string('-', 50));

            foreach (var section in binaryInfo.Sections)
            {
                int barLength = (int)(section.Entropy / 8.0 * 40);
                string bar = new string('█', barLength) + new string('░', 40 - barLength);
                string indicator = section.Entropy > 7.0 ? "[!]" : "   ";
                Console.WriteLine($"{indicator} {section.Name,-10} {bar} {section.Entropy:F2}");
            }

            Console.WriteLine(new string('-', 50));

            string detectedPacker = PackerDetector.Detect(binaryInfo);

            if (!string.IsNullOrEmpty(detectedPacker))
            {
                Console.WriteLine($"\n[!] Packer Identified: {detectedPacker}");

                if (detectedPacker == "UPX")
                {
                    Console.WriteLine("\n[+] Unpacking Suggestion:");
                    Console.WriteLine("    upx -d <file>");
                }
            }
            else
            {
                Console.WriteLine("\n[-] No known packer signatures detected");

                double avgEntropy = binaryInfo.Sections.Average(s => s.Entropy);
                if (avgEntropy > 6.5)
                {
                    Console.WriteLine("[!] Warning: Overall high entropy suggests possible packing/encryption");
                }
            }

            Console.WriteLine("\n[+] Packer analysis complete");
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error: {ex.Message}");
            return 1;
        }
    }
}