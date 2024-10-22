using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Netzwerkscanner.dataModels
{
    public class NetzwerkInfo
    {
        public string LokaleIP { get; set; }
        public string Subnetz { get; set; }
        public string NetworkSize { get; set; }
        public string Gateway { get; set; }
    }
}