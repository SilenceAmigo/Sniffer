using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Netzwerkscanner.dataModels
{
    public class SystemInformations
    {
        public string BaseMacAddr { get; set; }
        public string RomVersion { get; set; }
        public string SerialNumber { get; set; }
        public string UpTime { get; set; }
        public string MemoryTotal { get; set; }
        public string Free { get; set; }
        public string CpuUtil { get; set; }
    }
}