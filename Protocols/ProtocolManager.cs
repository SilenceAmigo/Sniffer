using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Netzwerkscanner.dataModels;

namespace Netzwerkscanner.Protocols
{
    public class ProtocolManager
    {
        private readonly Dictionary<string, IProtocolScanner> _protocolScanners = new Dictionary<string, IProtocolScanner>();

        public ProtocolManager()
        {
            // Hier kann man weitere Protokoll-Scanner hinzufügen
            _protocolScanners["arp"] = new ArpScanner();
            // _protocolScanners["SNMP"] = new SnmpScanner(); // Beispiel für zukünftige Scanner
        }

        public List<string> GetAvailableProtocols()
        {
            return new List<string>(_protocolScanners.Keys);
        }

        public async Task<(List<DeviceInfo> foundDevices, double elapsedSeconds)> ScanNetwork(string protocol, string target, int originalNumOfIps, int[] subnetArray)
        {
            if (_protocolScanners.ContainsKey(protocol))
            {
                // Entpacke das Tuple von ScanAsync
                var (foundDevices, elapsedSeconds) = await _protocolScanners[protocol].ScanAsync(target, originalNumOfIps, subnetArray);
                return (foundDevices, elapsedSeconds); // Gib das Tuple zurück
            }
            else
            {
                Console.WriteLine("Protokoll nicht verfügbar.");
                return (new List<DeviceInfo>(), 0); // Rückgabe eines leeren Tuples
            }
        }
    }
}
