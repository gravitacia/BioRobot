using System.Text;
using BioRobot.Core.Models;
using BioRobot.Core.Analyzers;
using Microsoft.VisualBasic.FileIO;
using System.Security.Cryptography;

namespace BioRobot.Core.Parsers;

public class RawBinaryParser
{
    private readonly string _filePath;
    private byte[] _fileBytes;
    private BinaryInfo _binaryInfo;

    public RawBinaryParser(string filePath)
    {
        _filePath = filePath;
        _binaryInfo = new BinaryInfo { FilePath = filePath };
    }

    public BinaryInfo Parse()
    {
        _fileBytes = File.ReadAllBytes(_filePath);
        _binaryInfo.FileSize = _fileBytes.Length;
        _binaryInfo.Type = FileType.RawBinary;
        _binaryInfo.Is64Bit = false;
        _binaryInfo.EntryPointRva = 0;
        _binaryInfo.ImageBase = 0;
        _binaryInfo.Md5 = ComputeMd5();
        _binaryInfo.Sha256 = ComputeSha256();

        double entropy = EntropyCalculator.Compute(_fileBytes);

        var section = new SectionInfo
        {
            Name = ".raw",
            VirtualAddress = 0,
            VirtualSize = (uint)_fileBytes.Length,
            RawSize = (uint)_fileBytes.Length,
            PointerToRawData = 0,
            Characteristics = 0,
            RawData = _fileBytes,
            Entropy = entropy
        };

        _binaryInfo.Sections.Add(section);

        _binaryInfo.Imports = new List<ImportInfo>();
        _binaryInfo.DataDirectories = new List<IMAGE_DATA_DIRECTORY>();

        return _binaryInfo;
    }

    private string ComputeMd5()
    {
        using var md5 = MD5.Create();
        byte[] hash = md5.ComputeHash(_fileBytes);
        return BitConverter.ToString(hash).Replace("-", "").ToLower();
    }

    private string ComputeSha256()
    {
        using var sha256 = SHA256.Create();
        byte[] hash = sha256.ComputeHash(_fileBytes);
        return BitConverter.ToString(hash).Replace("-", "").ToLower();
    }
}