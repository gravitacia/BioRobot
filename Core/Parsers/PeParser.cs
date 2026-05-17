using System.Text;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using BioRobot.Core.Models;
using BioRobot.Core.Analyzers;

namespace BioRobot.Core.Parsers;

public class PeParser
{
    private readonly string _filePath;
    private byte[] _fileBytes;
    private IMAGE_DOS_HEADER _dosHeader;
    private IMAGE_FILE_HEADER _fileHeader;
    private BinaryInfo _binaryInfo;

    public PeParser(string filePath)
    {
        _filePath = filePath;
        _binaryInfo = new BinaryInfo { FilePath = filePath };
    }

    public BinaryInfo Parse()
    {
        _fileBytes = File.ReadAllBytes(_filePath);
        _binaryInfo.FileSize = _fileBytes.Length;
        _binaryInfo.Md5 = ComputeMd5();
        _binaryInfo.Sha256 = ComputeSha256();

        ParseDosHeader();
        ParseNtHeaders();
        ParseSectionHeaders();
        ParseImportTable();

        return _binaryInfo;
    }

    private void ParseDosHeader()
    {
        GCHandle handle = GCHandle.Alloc(_fileBytes, GCHandleType.Pinned);
        _dosHeader = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(handle.AddrOfPinnedObject());
        handle.Free();

        if (_dosHeader.e_magic != 0x5A4D)
            throw new InvalidDataException("Not a valid PE file (invalid DOS magic)");
    }

    private void ParseNtHeaders()
    {
        long peOffset = _dosHeader.e_lfanew;

        uint peSignature = BitConverter.ToUInt32(_fileBytes, (int)peOffset);
        if (peSignature != 0x00004550)
            throw new InvalidDataException("Invalid PE signature");

        int fileHeaderOffset = (int)peOffset + 4;
        GCHandle handle = GCHandle.Alloc(_fileBytes, GCHandleType.Pinned);
        IntPtr ptr = handle.AddrOfPinnedObject();

        _fileHeader = Marshal.PtrToStructure<IMAGE_FILE_HEADER>(ptr + fileHeaderOffset);

        int optionalHeaderOffset = fileHeaderOffset + Marshal.SizeOf<IMAGE_FILE_HEADER>();
        ushort magic = BitConverter.ToUInt16(_fileBytes, optionalHeaderOffset);

        if (magic == 0x10B)
        {
            _binaryInfo.Is64Bit = false;
            var optHeader32 = Marshal.PtrToStructure<IMAGE_OPTIONAL_HEADER32>(ptr + optionalHeaderOffset);
            _binaryInfo.EntryPointRva = optHeader32.AddressOfEntryPoint;
            _binaryInfo.ImageBase = optHeader32.ImageBase;
            _binaryInfo.NumberOfRvaAndSizes = optHeader32.NumberOfRvaAndSizes;

            int dataDirOffset = optionalHeaderOffset + Marshal.SizeOf<IMAGE_OPTIONAL_HEADER32>() - (16 * Marshal.SizeOf<IMAGE_DATA_DIRECTORY>());
            _binaryInfo.DataDirectories = new List<IMAGE_DATA_DIRECTORY>();
            for (int i = 0; i < _binaryInfo.NumberOfRvaAndSizes && i < 16; i++)
            {
                var dir = Marshal.PtrToStructure<IMAGE_DATA_DIRECTORY>(ptr + dataDirOffset + (i * Marshal.SizeOf<IMAGE_DATA_DIRECTORY>()));
                _binaryInfo.DataDirectories.Add(dir);
            }
        }
        else if (magic == 0x20B)
        {
            _binaryInfo.Is64Bit = true;
            var optHeader64 = Marshal.PtrToStructure<IMAGE_OPTIONAL_HEADER64>(ptr + optionalHeaderOffset);
            _binaryInfo.EntryPointRva = optHeader64.AddressOfEntryPoint;
            _binaryInfo.ImageBase = optHeader64.ImageBase;
            _binaryInfo.NumberOfRvaAndSizes = optHeader64.NumberOfRvaAndSizes;

            int dataDirOffset = optionalHeaderOffset + Marshal.SizeOf<IMAGE_OPTIONAL_HEADER64>() - (16 * Marshal.SizeOf<IMAGE_DATA_DIRECTORY>());
            _binaryInfo.DataDirectories = new List<IMAGE_DATA_DIRECTORY>();
            for (int i = 0; i < _binaryInfo.NumberOfRvaAndSizes && i < 16; i++)
            {
                var dir = Marshal.PtrToStructure<IMAGE_DATA_DIRECTORY>(ptr + dataDirOffset + (i * Marshal.SizeOf<IMAGE_DATA_DIRECTORY>()));
                _binaryInfo.DataDirectories.Add(dir);
            }
        }
        else
        {
            throw new InvalidDataException("Unknown optional header magic");
        }

        handle.Free();
    }

    private void ParseSectionHeaders()
    {
        long peOffset = _dosHeader.e_lfanew;
        int fileHeaderSize = Marshal.SizeOf<IMAGE_FILE_HEADER>();
        int optionalHeaderSize = _fileHeader.SizeOfOptionalHeader;

        long sectionHeaderOffset = peOffset + 4 + fileHeaderSize + optionalHeaderSize;

        GCHandle handle = GCHandle.Alloc(_fileBytes, GCHandleType.Pinned);
        IntPtr ptr = handle.AddrOfPinnedObject();

        for (int i = 0; i < _fileHeader.NumberOfSections; i++)
        {
            long offset = sectionHeaderOffset + (i * Marshal.SizeOf<IMAGE_SECTION_HEADER>());
            var sectionHeader = Marshal.PtrToStructure<IMAGE_SECTION_HEADER>(ptr + (int)offset);

            string name = Encoding.ASCII.GetString(sectionHeader.Name).TrimEnd('\0');

            byte[] sectionData = new byte[sectionHeader.SizeOfRawData];
            if (sectionHeader.PointerToRawData > 0 && sectionHeader.SizeOfRawData > 0)
            {
                Array.Copy(_fileBytes, sectionHeader.PointerToRawData, sectionData, 0,
                    Math.Min(sectionHeader.SizeOfRawData, _fileBytes.Length - sectionHeader.PointerToRawData));
            }

            double entropy = EntropyCalculator.Compute(sectionData);

            var section = new SectionInfo
            {
                Name = name,
                VirtualAddress = sectionHeader.VirtualAddress,
                VirtualSize = sectionHeader.VirtualSize,
                RawSize = sectionHeader.SizeOfRawData,
                PointerToRawData = sectionHeader.PointerToRawData,
                Characteristics = sectionHeader.Characteristics,
                RawData = sectionData,
                Entropy = entropy
            };

            _binaryInfo.Sections.Add(section);
        }

        handle.Free();
    }

    private void ParseImportTable()
    {
        if (_binaryInfo.DataDirectories.Count <= 1)
            return;

        uint importRva = _binaryInfo.DataDirectories[1].VirtualAddress;
        if (importRva == 0)
            return;

        uint importSize = _binaryInfo.DataDirectories[1].Size;
        if (importSize == 0)
            return;

        long importOffset = RvaToRawOffset(importRva);
        if (importOffset < 0)
            return;

        int descriptorSize = Marshal.SizeOf<IMAGE_IMPORT_DESCRIPTOR>();
        int maxDescriptors = (int)(importSize / descriptorSize);

        GCHandle handle = GCHandle.Alloc(_fileBytes, GCHandleType.Pinned);
        IntPtr ptr = handle.AddrOfPinnedObject();

        for (int i = 0; i < maxDescriptors; i++)
        {
            long offset = importOffset + (i * descriptorSize);
            var descriptor = Marshal.PtrToStructure<IMAGE_IMPORT_DESCRIPTOR>(ptr + (int)offset);

            if (descriptor.Name == 0 && descriptor.FirstThunk == 0)
                break;

            if (descriptor.Name == 0)
                continue;

            long dllNameOffset = RvaToRawOffset(descriptor.Name);
            if (dllNameOffset < 0)
                continue;

            string dllName = ReadStringAtOffset(dllNameOffset);

            var importEntry = new ImportInfo { DllName = dllName, Functions = new List<string>() };

            uint thunkRva = descriptor.OriginalFirstThunk != 0 ? descriptor.OriginalFirstThunk : descriptor.FirstThunk;
            long thunkOffset = RvaToRawOffset(thunkRva);

            if (thunkOffset >= 0)
            {
                if (_binaryInfo.Is64Bit)
                {
                    int thunkIndex = 0;
                    while (true)
                    {
                        long thunkAddr = thunkOffset + (thunkIndex * 8);
                        if (thunkAddr + 8 > _fileBytes.Length)
                            break;

                        ulong thunkValue = BitConverter.ToUInt64(_fileBytes, (int)thunkAddr);
                        if (thunkValue == 0)
                            break;

                        if ((thunkValue & 0x8000000000000000) != 0)
                        {
                            uint ordinal = (uint)(thunkValue & 0xFFFF);
                            importEntry.Functions.Add($"Ordinal_{ordinal}");
                        }
                        else
                        {
                            uint nameRva = (uint)(thunkValue & 0x7FFFFFFFFFFFFFFF);
                            long nameOffset = RvaToRawOffset(nameRva);
                            if (nameOffset >= 0)
                            {
                                string funcName = ReadImportNameAtOffset(nameOffset);
                                importEntry.Functions.Add(funcName);
                            }
                        }
                        thunkIndex++;
                    }
                }
                else
                {
                    int thunkIndex = 0;
                    while (true)
                    {
                        long thunkAddr = thunkOffset + (thunkIndex * 4);
                        if (thunkAddr + 4 > _fileBytes.Length)
                            break;

                        uint thunkValue = BitConverter.ToUInt32(_fileBytes, (int)thunkAddr);
                        if (thunkValue == 0)
                            break;

                        if ((thunkValue & 0x80000000) != 0)
                        {
                            uint ordinal = thunkValue & 0xFFFF;
                            importEntry.Functions.Add($"Ordinal_{ordinal}");
                        }
                        else
                        {
                            long nameOffset = RvaToRawOffset(thunkValue);
                            if (nameOffset >= 0)
                            {
                                string funcName = ReadImportNameAtOffset(nameOffset);
                                importEntry.Functions.Add(funcName);
                            }
                        }
                        thunkIndex++;
                    }
                }
            }

            _binaryInfo.Imports.Add(importEntry);
        }

        handle.Free();
    }

    private long RvaToRawOffset(uint rva)
    {
        foreach (var section in _binaryInfo.Sections)
        {
            if (rva >= section.VirtualAddress && rva < section.VirtualAddress + section.VirtualSize)
            {
                uint offsetInSection = rva - section.VirtualAddress;
                return section.PointerToRawData + offsetInSection;
            }
        }
        return -1;
    }

    private string ReadStringAtOffset(long offset)
    {
        List<byte> bytes = new List<byte>();
        long pos = offset;
        while (pos < _fileBytes.Length && _fileBytes[pos] != 0)
        {
            bytes.Add(_fileBytes[pos]);
            pos++;
        }
        return Encoding.ASCII.GetString(bytes.ToArray());
    }

    private string ReadImportNameAtOffset(long offset)
    {
        ushort hint = BitConverter.ToUInt16(_fileBytes, (int)offset);
        long nameOffset = offset + 2;
        return ReadStringAtOffset(nameOffset);
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