using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using BioRobot.Core.Models;

namespace BioRobot.Core.Analyzers
{
    public static class JsonExporter
    {
        public static string Export(BinaryInfo binaryInfo, DetectionResult detection = null)
        {
            var jsonObject = new Dictionary<string, object>();

            var fileInfo = new Dictionary<string, object>
            {
                { "path", binaryInfo.FilePath },
                { "size", binaryInfo.FileSize },
                { "md5", binaryInfo.Md5 },
                { "sha256", binaryInfo.Sha256 },
                { "type", binaryInfo.Type.ToString() },
                { "is64Bit", binaryInfo.Is64Bit },
                { "entryPointRva", $"0x{binaryInfo.EntryPointRva:X8}" },
                { "imageBase", $"0x{binaryInfo.ImageBase:X16}" }
            };
            jsonObject["file"] = fileInfo;
            var sections = new List<Dictionary<string, object>>();
            foreach (var section in binaryInfo.Sections)
            {
                var sectionObj = new Dictionary<string, object>
                {
                    { "name", section.Name },
                    { "virtualAddress", $"0x{section.VirtualAddress:X8}" },
                    { "virtualSize", section.VirtualSize },
                    { "rawSize", section.RawSize },
                    { "entropy", section.Entropy }
                };
                sections.Add(sectionObj);
            }
            jsonObject["sections"] = sections;
            var imports = new List<Dictionary<string, object>>();
            foreach (var import in binaryInfo.Imports)
            {
                var importObj = new Dictionary<string, object>
                {
                    { "dll", import.DllName },
                    { "functionCount", import.Functions.Count },
                    { "functions", import.Functions.Take(50).ToList() } // First 50 only
                };
                imports.Add(importObj);
            }
            jsonObject["imports"] = imports;
            if (detection != null)
            {
                var detectionObj = new Dictionary<string, object>
                {
                    { "riskScore", detection.RiskScore },
                    { "verdict", detection.Verdict },
                    { "suspiciousImports", detection.SuspiciousImports },
                    { "highEntropySections", detection.HighEntropySections }
                };
                jsonObject["detection"] = detectionObj;
            }
            var options = new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };

            return JsonSerializer.Serialize(jsonObject, options);
        }
    }
}