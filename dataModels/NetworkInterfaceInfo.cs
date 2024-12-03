using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Netzwerkscanner.dataModels
{
    public class NetworkInterfaceInfo
    {
        public string Name { get; set; }
        public string IPAddress { get; set; }
        public int[] SubnetMask { get; set; }
        public string Gateway { get; set; }
    }

}