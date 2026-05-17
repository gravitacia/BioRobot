using System.Collections.Generic;

namespace BioRobot.Core.Models
{
    public class DetectionResult
    {
        public List<string> SuspiciousImports { get; set; }
        public List<string> HighEntropySections { get; set; }
        public int RiskScore { get; set; }
        public string Verdict { get; set; }
    }
}