using System;
using System.Collections.Generic;
using System.Linq;
using BioRobot.Core.Models;

namespace BioRobot.Core.Analyzers
{
    public class RiskScorer
    {
        private static readonly HashSet<string> SuspiciousApis = new HashSet<string>
        {
            // Process injection
            "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
            "QueueUserAPC", "NtCreateThreadEx", "RtlCreateUserThread",
            
            // Process creation
            "CreateProcess", "CreateProcessA", "CreateProcessW", "WinExec", "ShellExecute",
            "ShellExecuteEx", "System", "exec",
            
            // Persistence
            "RegSetValue", "RegSetValueEx", "RegCreateKey", "RegCreateKeyEx",
            "RegOpenKey", "RegOpenKeyEx", "SchTasksCreate", "CreateService",
            
            //Antidebug
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugString",
            "GetTickCount", "GetTickCount64", "Sleep", "NtDelayExecution",
            
            // Networking
            "socket", "connect", "send", "recv", "WSASocket", "InternetOpen",
            "InternetConnect", "URLDownloadToFile", "WinHttpOpen", "HttpOpenRequest",
            
            // Encryption
            "CryptAcquireContext", "CryptEncrypt", "CryptDecrypt", "BCryptEncrypt",
            "BCryptDecrypt", "RtlEncryptMemory", "RtlDecryptMemory"
        };

        public static DetectionResult Analyze(BinaryInfo binaryInfo)
        {
            var suspiciousImports = new List<string>();
            var highEntropySections = new List<string>();

            foreach (var import in binaryInfo.Imports)
            {
                foreach (string function in import.Functions)
                {
                    if (function.StartsWith("Ordinal_"))
                        continue;

                    if (SuspiciousApis.Contains(function))
                    {
                        suspiciousImports.Add(function);
                    }
                }
            }

            suspiciousImports = suspiciousImports.Distinct().ToList();

            foreach (var section in binaryInfo.Sections)
            {
                if (section.Entropy > 7.0)
                {
                    highEntropySections.Add($"{section.Name} ({section.Entropy:F2})");
                }
            }

            int riskScore = 0;
            riskScore += Math.Min(suspiciousImports.Count * 3, 30);
            riskScore += Math.Min(highEntropySections.Count * 5, 25);
            riskScore = Math.Min(riskScore, 100);

            string verdict;
            if (riskScore >= 60)
                verdict = "Malicious";
            else if (riskScore >= 30)
                verdict = "Suspicious";
            else
                verdict = "Clean";

            return new DetectionResult
            {
                SuspiciousImports = suspiciousImports,
                HighEntropySections = highEntropySections,
                RiskScore = riskScore,
                Verdict = verdict
            };
        }
    }
}