using BioRobot.Core.Models;

namespace BioRobot.Core.Analyzers;

public static class PackerDetector
{
    private static readonly Dictionary<string, string> PackerSignatures = new Dictionary<string, string>
    {
        { "upx0", "UPX" },
        { "upx1", "UPX" },
        { "aspack", "ASPack" },
        { "adata", "ASPack" },
        { "themida", "Themida" },
        { "mpress", "MPress" },
        { "enigma", "Enigma" },
        { "vmp", "VMProtect" },
        { "vmp0", "VMProtect" },
        { "vmp1", "VMProtect" },
        { "y0da", "Yoda's Protector" },
        { "pepack", "PEPack" },
        { "petite", "Petite" },
        { "nsp1", "NSPack" },
        { "nsp0", "NSPack" }
    };

    public static string Detect(BinaryInfo binaryInfo)
    {
        foreach (var section in binaryInfo.Sections)
        {
            string normalizedName = section.Name.ToLower().TrimStart('.');

            if (PackerSignatures.ContainsKey(normalizedName))
            {
                return PackerSignatures[normalizedName];
            }
        }

        SectionInfo textSection = binaryInfo.Sections.FirstOrDefault(s => s.Name.Equals(".text", StringComparison.OrdinalIgnoreCase));
        SectionInfo dataSection = binaryInfo.Sections.FirstOrDefault(s => s.Name.Equals(".data", StringComparison.OrdinalIgnoreCase));

        if (textSection != null && dataSection != null)
        {
            if (textSection.Entropy > 7.0 && dataSection.Entropy < 2.0)
            {
                return "Unknown Packer (suspicious entropy pattern)";
            }
        }

        int highEntropySections = binaryInfo.Sections.Count(s => s.Entropy > 7.5);
        if (highEntropySections >= 2)
        {
            return "Possible Packed/Encrypted (multiple high entropy sections)";
        }

        return null;
    }
}