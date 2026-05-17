using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BioRobot.Core.Analyzers
{
    public static class EntropyCalculator
    {
        public static double Compute(byte[] data)
        {
            if (data == null || data.Length == 0)
                return 0.0;
            long[] frequency = new long[256];
            foreach (byte b in data)
            {
                frequency[b]++;
            }

            double entropy = 0.0;
            double total = data.Length;
            foreach (long count in frequency)
            {
                if (count > 0)
                {
                    double probability = count / total;
                    entropy -= probability * Math.Log2(probability);
                }
            }

            return Math.Round(entropy, 2);
        }
    }
}