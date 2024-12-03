using Netzwerkscanner.dataModels;

namespace Netzwerkscanner.project
{
    public class SwitchInfos
    {
        public string Manufacturer { get; set; }

        public string Model { get; set; }

        public string DeviceType { get; set; }

        public string FirmwareVersion { get; set; }

        public List<Port> Ports { get; set; }
        public List<Vlan> Vlans { get; set; }

        public List<Paket> Pakets { get; set; }

        public RoutingInfo RroutingInfo { get; set; }

        public SystemInformations SystemInformations { get; set; }

        public List<ArpEntry> ActiveDevices { get; set; }

        public List<InactiveDevices> InactiveDevices { get; set; }

    }
}