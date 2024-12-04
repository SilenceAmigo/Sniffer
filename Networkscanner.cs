using Newtonsoft.Json;
using System.Runtime.InteropServices;
using Newtonsoft.Json.Schema;
using Netzwerkscanner.dataModels;
using Netzwerkscanner.Protocols;
using System.Net.NetworkInformation;
using System.Text;
using Netzwerkscanner.project;

namespace Netzwerkscanner
{
    class Network_Scanner
    {
        public static int count;  // Class-level field for tracking found hosts
        public static int totalTestedIps = 0;  // Shared progress counter
        public static int originalNumOfIps = 0;  // Store the original number of IPs


        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        public static extern int SendARP(int destIp, int srcIp, byte[] macAddr, ref int physicalAddrLen);

        public static async Task Main(string[] args)
        {

            NetzwerkInfo netzwerkInfo = new NetzwerkInfo { };

            bool scanSubnet = InAndOutput.GetUserInput("Would you like to scan a Network?");

            if (scanSubnet)
            {
                // Netzwerkinformationen abrufen
                var (localIP, subnetMask, gateway) = NetworkscannerFunctions.SelectNetworkInterface();

                if (localIP == null || subnetMask == null)
                {
                    Console.WriteLine("No local IP address or subnet mask found.");
                    return;
                }
                // Berechnung der Anzahl der IP-Adressen
                int subnetzSize = NetworkscannerFunctions.CalcSubnetSize(subnetMask);
                originalNumOfIps = NetworkscannerFunctions.CalcNumOfIps(subnetzSize); // Store original number of IPs in shared class-level variable


                string subnet;
                int[] subnetArray;

                if (string.IsNullOrEmpty(gateway))
                {
                    subnet = NetworkscannerFunctions.GetSubnet(localIP);
                    subnetArray = NetworkscannerFunctions.GetSubnetArray(localIP);
                }
                else
                {
                    subnet = NetworkscannerFunctions.GetSubnet(gateway);
                    subnetArray = NetworkscannerFunctions.GetSubnetArray(gateway);
                }




                // Ausgabe der Netzwerkinformationen
                InAndOutput.PrintNetworkInfo(localIP, subnet, subnetzSize, gateway);
                netzwerkInfo = new NetzwerkInfo
                {
                    LokaleIP = localIP,
                    Subnetz = subnet,
                    NetworkSize = $"/{subnetzSize}",
                    Gateway = gateway
                };

                // Protocol Manager initialisieren
                ProtocolManager protocolManager = new ProtocolManager();


                // Wählen Sie ein Protokoll aus der Liste verfügbarer Protokolle
                var availableProtocols = protocolManager.GetAvailableProtocols();
                foreach (var protocol in availableProtocols)
                {

                    Console.WriteLine($"- {protocol}");
                }

                string selectedProtocol = InAndOutput.GetUserInputAndReturnString("Select a protocol for scanning:");

                InAndOutput.PrintNetworkInfo(localIP, subnet, subnetzSize, gateway);
                Console.WriteLine($"The selected protocol is {selectedProtocol}\n");
                var (foundDevices, elapsedSeconds) = await protocolManager.ScanNetwork(selectedProtocol, subnet, originalNumOfIps, subnetArray);


                if (elapsedSeconds != 0)
                {
                    InAndOutput.PrintFoundDevicesAsync(foundDevices, elapsedSeconds);
                }
            }

            Data data = new Data
            {
                Netzwerk = netzwerkInfo,
                Hosts = InAndOutput.results,
                SwitchInfos = InAndOutput.switchInfos,
            };

            // Switch scannen
            if (InAndOutput.GetUserInput("Would you like to scan a switch?"))
            {
                string switchIp = InAndOutput.GetValidIpAddress();

                bool reachable = false; // Flag to track reachability

                while (!reachable)
                {
                    Ping ping = new Ping();
                    PingReply reply = ping.Send(switchIp);

                    if (reply.Status == IPStatus.Success)
                    {
                        Console.WriteLine($"Device reachable: {switchIp}");
                        reachable = true;
                    }
                    else
                    {
                        Console.WriteLine($"Device {switchIp} not reachable. It is possible that the ICMP protocol is blocked on this device.");
                        bool tryAgain = InAndOutput.GetUserInput("Would you like to try again? (yes/no)");
                        if (!tryAgain)
                        {
                            Console.WriteLine("Device is not reachable, but continuing with the program.");
                            break; // Beendet die Schleife und setzt das Programm fort.
                        }
                    }
                }

                bool scanSwitchWithPw = InAndOutput.GetUserInputAndClear("Do you have admin rights on the switch?");
                if (scanSwitchWithPw)
                {
                    InAndOutput.RequestAdminCredentialsAndLogin(switchIp);
                }



            }

            // Festlegen des Projektverzeichnisses, indem du zwei Verzeichnisebenen nach oben gehst
            string projectDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, @"..\..\..");

            // Auflösen des Pfads, um den tatsächlichen Projektverzeichnis-Pfad zu erhalten
            projectDirectory = Path.GetFullPath(projectDirectory);


            // JSON-Schema Validierung und Speichern
            string schemaPath = Path.Combine(projectDirectory, "jsonSpec.json");
            string schemaJson = File.ReadAllText(schemaPath);

            // JSON-Schema laden
            JSchema schema = JSchema.Parse(schemaJson);

            // Konvertiere die Daten in JSON
            string json = JsonConvert.SerializeObject(data, Formatting.Indented);

            string dataPath = Path.Combine(projectDirectory, "result.json");
            File.WriteAllText(dataPath, json);

            // await DataToRestServer.SendDataToRestServer(json, "Restserver Domain");

        }
    }

}
