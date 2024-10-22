using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Netzwerkscanner.dataModels
{
    public class DeviceInfo
    {
        public string HostNum { get; set; }
        public string IpAdresse { get; set; }
        public string MACAdresse { get; set; }
        public string Hostname { get; set; }
        public string Manufacturer { get; set; }
        public string Latency { get; set; }

    }
}