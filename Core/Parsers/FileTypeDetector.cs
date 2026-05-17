using BioRobot.Core.Models;

namespace BioRobot.Core.Parsers;

public static class FileTypeDetector
{
    public static FileType Detect(string filePath)
    {
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read);
        using var reader = new BinaryReader(fs);
        if (fs.Length < 2)
            return FileType.RawBinary;

        byte[] magic = reader.ReadBytes(2);

        if (magic[0] == 0x4D && magic[1] == 0x5A)
        {
            return FileType.PeExe;
        }

        return FileType.RawBinary;
    }
}