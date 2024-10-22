using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Netzwerkscanner.dataModels
{
    public class Paket
    {
        public string TotalNumberOfPackages { get; set; }
        public string IncomingPackages { get; set; }
        public string OutgoingPackets { get; set; }
        public string BufferIncoming { get; set; }
        public string MinBuffer { get; set; }
        public string LostPackets { get; set; }

    }
}