using System.Runtime.InteropServices;

namespace BioRobot.Core.Models;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IMAGE_DOS_HEADER
{
    public ushort e_magic;      // Magic number (MZ)
    public ushort e_cblp;       // Bytes on last page of file
    public ushort e_cp;         // Pages in file
    public ushort e_crlc;       // Relocations
    public ushort e_cparhdr;    // Size of header in paragraphs
    public ushort e_minalloc;   // Minimum extra paragraphs needed
    public ushort e_maxalloc;   // Maximum extra paragraphs needed
    public ushort e_ss;         // Initial (relative) SS value
    public ushort e_sp;         // Initial SP value
    public ushort e_csum;       // Checksum
    public ushort e_ip;         // Initial IP value
    public ushort e_cs;         // Initial (relative) CS value
    public ushort e_lfarlc;     // File address of relocation table
    public ushort e_ovno;       // Overlay number
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public ushort[] e_res1;     // Reserved words
    public ushort e_oemid;      // OEM identifier (for e_oeminfo)
    public ushort e_oeminfo;    // OEM information
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
    public ushort[] e_res2;     // Reserved words
    public int e_lfanew;        // File address of new exe header (PE header offset)
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IMAGE_FILE_HEADER
{
    public ushort Machine;              // Machine type (e.g., 0x14C = x86, 0x8664 = x64)
    public ushort NumberOfSections;     // Number of section headers
    public uint TimeDateStamp;          // Timestamp (seconds since 1970)
    public uint PointerToSymbolTable;   // File offset of COFF symbol table
    public uint NumberOfSymbols;        // Number of symbols
    public ushort SizeOfOptionalHeader; // Size of optional header that follows
    public ushort Characteristics;      // File characteristics flags
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IMAGE_OPTIONAL_HEADER32
{
    public ushort Magic;                // 0x10B for 32-bit
    public byte MajorLinkerVersion;
    public byte MinorLinkerVersion;
    public uint SizeOfCode;
    public uint SizeOfInitializedData;
    public uint SizeOfUninitializedData;
    public uint AddressOfEntryPoint;    // RVA of entry point
    public uint BaseOfCode;
    public uint BaseOfData;
    public uint ImageBase;              // Preferred load address
    public uint SectionAlignment;
    public uint FileAlignment;
    public ushort MajorOperatingSystemVersion;
    public ushort MinorOperatingSystemVersion;
    public ushort MajorImageVersion;
    public ushort MinorImageVersion;
    public ushort MajorSubsystemVersion;
    public ushort MinorSubsystemVersion;
    public uint Win32VersionValue;
    public uint SizeOfImage;
    public uint SizeOfHeaders;
    public uint CheckSum;
    public ushort Subsystem;
    public ushort DllCharacteristics;
    public uint SizeOfStackReserve;
    public uint SizeOfStackCommit;
    public uint SizeOfHeapReserve;
    public uint SizeOfHeapCommit;
    public uint LoaderFlags;
    public uint NumberOfRvaAndSizes;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public IMAGE_DATA_DIRECTORY[] DataDirectory;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IMAGE_OPTIONAL_HEADER64
{
    public ushort Magic;                // 0x20B for 64-bit
    public byte MajorLinkerVersion;
    public byte MinorLinkerVersion;
    public uint SizeOfCode;
    public uint SizeOfInitializedData;
    public uint SizeOfUninitializedData;
    public uint AddressOfEntryPoint;    // RVA of entry point
    public uint BaseOfCode;
    public ulong ImageBase;             // Preferred load address (64-bit)
    public uint SectionAlignment;
    public uint FileAlignment;
    public ushort MajorOperatingSystemVersion;
    public ushort MinorOperatingSystemVersion;
    public ushort MajorImageVersion;
    public ushort MinorImageVersion;
    public ushort MajorSubsystemVersion;
    public ushort MinorSubsystemVersion;
    public uint Win32VersionValue;
    public uint SizeOfImage;
    public uint SizeOfHeaders;
    public uint CheckSum;
    public ushort Subsystem;
    public ushort DllCharacteristics;
    public ulong SizeOfStackReserve;
    public ulong SizeOfStackCommit;
    public ulong SizeOfHeapReserve;
    public ulong SizeOfHeapCommit;
    public uint LoaderFlags;
    public uint NumberOfRvaAndSizes;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public IMAGE_DATA_DIRECTORY[] DataDirectory;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IMAGE_DATA_DIRECTORY
{
    public uint VirtualAddress;         // RVA of the data
    public uint Size;                   // Size of the data
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IMAGE_SECTION_HEADER
{
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public byte[] Name;                 // Section name (not null-terminated)
    public uint VirtualSize;            // Size of section when loaded in memory
    public uint VirtualAddress;         // RVA of section in memory
    public uint SizeOfRawData;          // Size of section on disk
    public uint PointerToRawData;       // File offset to section data
    public uint PointerToRelocations;
    public uint PointerToLinenumbers;
    public ushort NumberOfRelocations;
    public ushort NumberOfLinenumbers;
    public uint Characteristics;        // Section flags (executable, readable, etc.)
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IMAGE_IMPORT_DESCRIPTOR
{
    public uint OriginalFirstThunk;     // RVA to INT (Import Name Table)
    public uint TimeDateStamp;
    public uint ForwarderChain;
    public uint Name;                   // RVA to DLL name string
    public uint FirstThunk;             // RVA to IAT (Import Address Table)
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IMAGE_EXPORT_DIRECTORY
{
    public uint Characteristics;
    public uint TimeDateStamp;
    public ushort MajorVersion;
    public ushort MinorVersion;
    public uint Name;                   // RVA to DLL name
    public uint Base;                   // Starting ordinal number
    public uint NumberOfFunctions;      // Number of exported functions
    public uint NumberOfNames;          // Number of exported names
    public uint AddressOfFunctions;     // RVA to array of function addresses
    public uint AddressOfNames;         // RVA to array of function names
    public uint AddressOfNameOrdinals;  // RVA to array of ordinals
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IMAGE_THUNK_DATA32
{
    public uint ForwarderString;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IMAGE_THUNK_DATA64
{
    public ulong ForwarderString;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IMAGE_IMPORT_BY_NAME
{
    public ushort Hint;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 1)]
    public string Name;
}