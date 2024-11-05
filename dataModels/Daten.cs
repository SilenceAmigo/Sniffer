using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Netzwerkscanner.project;

namespace Netzwerkscanner.dataModels
{
    public class Data
    {
        public NetzwerkInfo Netzwerk { get; set; }
        public List<DeviceInfo> Hosts { get; set; }
        public SwitchInfos SwitchInfos { get; set; }


    }

}