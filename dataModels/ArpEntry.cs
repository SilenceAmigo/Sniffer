using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Netzwerkscanner.dataModels
{
    public class ArpEntry
    {
        public string ip { get; set; }
        public string mac { get; set; }
        public string type { get; set; }
        public string port { get; set; }

    }
}