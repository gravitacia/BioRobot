using System;
using System.Collections.Generic;

namespace BioRobot.Core.Models
{
    public enum FileType
    {
        PeExe,
        PeDll,
        RawBinary
    }

    public class SectionInfo
    {
        public string Name { get; set; }
        public uint VirtualAddress { get; set; }
        public uint RawSize { get; set; }
        public double Entropy { get; set; }
        public uint VirtualSize { get; set; }
        public uint PointerToRawData { get; set; }
        public uint Characteristics { get; set; }
        public byte[] RawData { get; set; }
    }

    public class ImportInfo
    {
        public string DllName { get; set; }
        public List<string> Functions { get; set; }
    }

    public class BinaryInfo
    {
        public string FilePath { get; set; }
        public long FileSize { get; set; }
        public string Md5 { get; set; }
        public string Sha256 { get; set; }
        public bool Is64Bit { get; set; }
        public uint EntryPointRva { get; set; }
        public ulong ImageBase { get; set; }
        public uint NumberOfRvaAndSizes { get; set; }
        public FileType Type { get; set; }
        public List<IMAGE_DATA_DIRECTORY> DataDirectories { get; set; }
        public List<SectionInfo> Sections { get; set; }
        public List<ImportInfo> Imports { get; set; }

        public BinaryInfo()
        {
            Sections = new List<SectionInfo>();
            Imports = new List<ImportInfo>();
            DataDirectories = new List<IMAGE_DATA_DIRECTORY>();
        }

        public DetectionResult? Detection { get; set; }
    }
}