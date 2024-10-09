using System.Net;
using System.Diagnostics;
using Newtonsoft.Json;
using System.Security;




namespace Netzwerkscanner
{
    class Network_Scanner
    {
        public static int count;  // Class-level field for tracking found hosts
        public static int totalTestedIps = 0;  // Shared progress counter
        public static int originalNumOfIps = 0;  // Store the original number of IPs


        public static async Task Main(string[] args)
        {
            var dummyPassword = new SecureString();
            foreach (char c in "dummy")
            {
                dummyPassword.AppendChar(c);
            }
            dummyPassword.MakeReadOnly();
            Authorization.CheckSwitchLoginWithShell("10.1.200.187", "manager", dummyPassword);

            bool scanSubnet = InAndOutput.GetUserInput("Möchten Sie das Netz, in dem Sie sich befinden, scannen?");

            if (scanSubnet)
            {
                // Netzwerkinformationen abrufen
                var (localIP, subnetMask, gateway) = NetworkscannerFunctions.GetLocalIPAddressAndSubnetMask();
                if (localIP == null || subnetMask == null)
                {
                    Console.WriteLine("Keine lokale IP-Adresse oder Subnetzmaske gefunden.");
                    return;
                }
                // Berechnung der Anzahl der IP-Adressen
                int subnetzSize = NetworkscannerFunctions.CalcSubnetSize(subnetMask);
                originalNumOfIps = NetworkscannerFunctions.CalcNumOfIps(subnetzSize); // Store original number of IPs in shared class-level variable


                string subnet = NetworkscannerFunctions.GetSubnet(localIP);
                int[] subnetArray = NetworkscannerFunctions.GetSubnetArray(localIP);

                // Ausgabe der Netzwerkinformationen
                InAndOutput.PrintNetworkInfo(localIP, subnet, subnetzSize, gateway);

                // ARP-Sweep durchführen und Zeit messen
                var (foundDevices, elapsedSeconds) = await ARPFunktions.PerformArpSweepAndMeasureTime(originalNumOfIps, subnetArray, scanSubnet);

                // Ausgabe der gefundenen Geräte
                InAndOutput.PrintFoundDevices(foundDevices, scanSubnet);

                // Ausgabe der Zeit und Anzahl der gefundenen Hosts
                InAndOutput.PrintSummary(elapsedSeconds);
            }

            bool scanSwitch = InAndOutput.GetUserInput("Möchten Sie einen Switch scannen?");
            if (scanSwitch)
            {
                string switchIp = InAndOutput.GetValidIpAddress();

                IPAddress ip = IPAddress.Parse(switchIp);
                byte[] ipBytes = ip.GetAddressBytes();

                // IP-Adresse in Ganzzahl konvertieren
                int ipInt = BitConverter.ToInt32(ipBytes, 0);

                byte[] macAddr = new byte[6]; // Array für die MAC-Adresse
                int len = macAddr.Length;

                ARPFunktions.SendARP(ipInt, 0, macAddr, ref len);

                // Hersteller von MAC-Adresse abrufen
                string macAddress = NetworkscannerFunctions.FormatMacAddress(macAddr);
                string manufacturer = await NetworkscannerFunctions.GetManufacturerFromMac(macAddress);
                Console.WriteLine($"Scanne Gerät von: {manufacturer} ({switchIp}) mit der MAC-Adresse {macAddress}");

                bool scanSwitchWithPw = InAndOutput.GetUserInputAndClear("Haben Sie Adminrechte auf dem Switch?");
                if (scanSwitchWithPw)
                {
                    InAndOutput.RequestAdminCredentialsAndLogin(switchIp, manufacturer, macAddress);
                }

            }
            else
            {
                return;
            }
        }



    }
}
