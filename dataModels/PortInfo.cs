using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Netzwerkscanner.dataModels
{
    public class PortInfo
    {
        public string Description { get; set; }
        public bool Udp { get; set; }
        public string Status { get; set; }
        public string Port { get; set; }
        public bool Tcp { get; set; }
    }
}