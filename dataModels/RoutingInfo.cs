using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Netzwerkscanner.dataModels
{
    public class RoutingInfo
    {
        public string IPRouting { get; set; }
        public string DefaultGateway { get; set; }
        public string DefaultTTL { get; set; }
        public string ArpAge { get; set; }
        public string DomainSuffix { get; set; }
        public string DNSServer { get; set; }

    }
}