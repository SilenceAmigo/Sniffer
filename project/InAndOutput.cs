using System.Security;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Renci.SshNet;
using Netzwerkscanner.dataModels;
using Netzwerkscanner.project;

namespace Netzwerkscanner
{
    public static class InAndOutput
    {
        public static List<DeviceInfo> results = new List<DeviceInfo>();

        public static SwitchInfos switchInfos = new SwitchInfos();

        public static Port portJson = new Port();


        // Fragt den Benutzer nach einer Ja/Nein-Eingabe und wiederholt die Eingabe bei ungültigen Werten.
        public static bool GetUserInput(string question)
        {
            string input;
            do
            {
                Console.WriteLine(question + " (y/n):");
                input = Console.ReadLine()?.Trim().ToLower();

                if (input != "y" && input != "n")
                {
                    Console.WriteLine("Invalid input. Please enter 'y' for yes or 'n' for no.\n");

                }
            } while (input != "y" && input != "n");

            return input == "y";
        }

        public static bool GetUserInputAnDClearMessage(string message)
        {
            string input;
            do
            {
                Console.WriteLine(message + " (y/n):");
                input = Console.ReadLine()?.Trim().ToLower();

                if (input != "y" && input != "n")
                {
                    Console.WriteLine("Invalid input. Please enter 'y' for yes or 'n' for no.\n");

                }
            } while (input != "y" && input != "n");

            return input == "y";
        }

        // Fragt nach einer Ja/Nein-Eingabe, löscht das Display und überprüft die Eingabe.
        public static bool GetUserInputAndClear(string message)
        {
            string input;
            do
            {
                Console.WriteLine(message + " (y/n):");
                input = Console.ReadLine()?.Trim().ToLower();
                Console.Clear();

                if (input != "y" && input != "n")
                {
                    Console.WriteLine("Invalid input. Please enter 'y' for yes or 'n' for no.\n");
                }
            } while (input != "y" && input != "n");

            return input == "y";
        }

        public static string GetUserInputAndReturnString(string message)
        {
            string input;

            Console.WriteLine(message);
            input = Console.ReadLine()?.Trim().ToLower();
            Console.Clear();

            return input;
        }

        // Zeigt eine Nachricht an, fordert eine Eingabe an und gibt die Eingabe zurück. Prüft, ob die Eingabe leer ist.
        public static string PrintAndClearGetInput(string message)
        {
            string input;
            do
            {
                Console.WriteLine(message);
                input = Console.ReadLine()?.Trim();

                if (string.IsNullOrEmpty(input))
                {
                    Console.WriteLine("Invalid input. Please enter a value.");
                }
            } while (string.IsNullOrEmpty(input));

            Console.Clear();
            return input;
        }

        public static string GetValidIpAddress()
        {
            string ipAddress = string.Empty;
            bool isValid = false;

            // Solange die Eingabe keine gültige IP-Adresse ist, wird die Eingabe wiederholt
            while (!isValid)
            {
                Console.WriteLine("Please enter the IP address of the switch:");
                ipAddress = Console.ReadLine();

                // Überprüfen, ob die eingegebene IP-Adresse im gültigen Format ist
                if (IsValidIpAddress(ipAddress))
                {
                    isValid = true;
                }
                else
                {
                    Console.WriteLine("Invalid IP address! Please enter a correct IP address.\n");
                }
            }

            return ipAddress;
        }

        // Überprüfen, ob eine gegebene IP-Adresse gültig ist
        private static bool IsValidIpAddress(string ipAddress)
        {
            // Muster für eine gültige IPv4-Adresse
            string pattern = @"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\." +
                             @"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\." +
                             @"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\." +
                             @"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";

            // Regex zur Validierung der IP-Adresse
            return Regex.IsMatch(ipAddress, pattern);
        }

        public static void PrintAdvancedSwitchInfos(string result, Match routingRegex, List<string> systemInformation, List<ArpEntry> arpTable, string runningConfig)
        {
            Console.WriteLine("Advanced information:");
            Console.WriteLine(new string('─', 60));

            if (routingRegex.Success)
            {
                RoutingInfo routingInfo = new RoutingInfo();
                Console.WriteLine("Routing information:\n");

                // Schleife über die Gruppen im regulären Ausdruck-Ergebnis
                for (int i = 1; i < routingRegex.Groups.Count; i++)
                {
                    string value = routingRegex.Groups[i].Value;
                    Console.WriteLine($"{value}");

                    // Extrahiere den Teil nach dem Doppelpunkt, entferne Leerzeichen und \r
                    string cleanedValue = ExtractInfoAfterColon(value);

                    // Zuordnen zu den entsprechenden RoutingInfo-Feldern
                    if (value.Contains("IP Routing"))
                    {
                        routingInfo.IPRouting = cleanedValue;
                    }
                    else if (value.Contains("Default Gateway"))
                    {
                        routingInfo.DefaultGateway = cleanedValue;
                    }
                    else if (value.Contains("Default TTL"))
                    {
                        routingInfo.DefaultTTL = cleanedValue;
                    }
                    else if (value.Contains("Arp Age"))
                    {
                        routingInfo.ArpAge = cleanedValue;
                    }
                    else if (value.Contains("Domain Suffix"))
                    {
                        routingInfo.DomainSuffix = cleanedValue;
                    }
                    else if (value.Contains("DNS server"))
                    {
                        routingInfo.DNSServer = cleanedValue;
                    }
                }

                switchInfos.RroutingInfo = routingInfo;
            }

            Console.WriteLine(new string('─', 60));
            Console.WriteLine("System Informationen:\n");
            SystemInformations systemInformationsJson = new SystemInformations();

            // Bereinigung und Ausgabe der Systeminformationen
            foreach (var info in systemInformation)
            {
                Console.WriteLine(info);
                string cleanedInfo = ExtractInfoAfterColon(info);
                if (info.Contains("Base MAC Addr"))
                {
                    systemInformationsJson.BaseMacAddr = cleanedInfo;
                }
                else if (info.Contains("ROM Version"))
                {
                    systemInformationsJson.RomVersion = cleanedInfo;
                }
                else if (info.Contains("Serial Number"))
                {
                    systemInformationsJson.SerialNumber = cleanedInfo;
                }
                else if (info.Contains("Up Time"))
                {
                    systemInformationsJson.UpTime = cleanedInfo;
                }
                else if (info.Contains("Memory   - Total"))
                {
                    systemInformationsJson.MemoryTotal = cleanedInfo;
                }
                else if (info.Contains("Free"))
                {
                    systemInformationsJson.Free = cleanedInfo;
                }
                else if (info.Contains("CPU Util (%)"))
                {
                    systemInformationsJson.CpuUtil = cleanedInfo + "%";
                }
            }
            switchInfos.SystemInformations = systemInformationsJson;

            Console.WriteLine(new string('─', 60));
            Console.WriteLine("ARP-Table:\n");

            // ARP-Einträge in der Konsole ausgeben und gleichzeitig in JSON schreiben
            List<ArpEntry> arpEntriesJson = new List<ArpEntry>(); // Für JSON

            foreach (var arpEntry in arpTable)
            {
                Console.WriteLine($"IP: {arpEntry.ip}, MAC: {arpEntry.mac}, Typ: {arpEntry.type}, Port: {arpEntry.port}");

                arpEntriesJson.Add(new ArpEntry
                {
                    ip = arpEntry.ip,
                    mac = arpEntry.mac,
                    type = arpEntry.type,
                    port = arpEntry.port
                });
            }

            switchInfos.ArpTable = arpEntriesJson;

            Console.WriteLine(new string('─', 60));

            Console.WriteLine("Running configuration:\n");
            Console.WriteLine(runningConfig);
            Console.WriteLine(new string('─', 60));
        }


        private static string ExtractInfoAfterColon(string input)
        {
            var parts = input.Split(':');

            if (parts.Length > 1)
            {
                return parts[1].Trim().Replace("\r", string.Empty);
            }

            return input.Trim();
        }



        public static void PrintAndClear(string message)
        {
            Console.WriteLine(message);
            Thread.Sleep(1000);
            Console.Clear();
        }

        public static async Task PrintFoundDevicesAsync(List<DeviceInfo> foundDevices, double elapsedSeconds)
        {
            Console.WriteLine("\n\nDevices found :\n\n");
            int i = 0;

            foreach (var device in foundDevices)
            {
                i++;
                string hostname = NetworkscannerFunctions.GetHostName(device.IpAdresse);
                results.Add(new DeviceInfo
                {
                    HostNum = i.ToString(),
                    IpAdresse = device.IpAdresse,
                    MACAdresse = device.MACAdresse,
                    Hostname = hostname,
                    Manufacturer = device.Manufacturer,
                    Latency = device.Latency,
                });
                Console.WriteLine($"Host Num {i}\nIp address: {device.IpAdresse}\nMAC-Adresse: {device.MACAdresse}\nHostname: {hostname}\nManufacturer: {device.Manufacturer}\nLatencz: {device.Latency} s\n\n");
            }
            Console.WriteLine($"\n{i} Hosts found in {elapsedSeconds}");

        }

        // Gibt Netzwerkinformationen aus.
        public static void PrintNetworkInfo(string localIP, string subnet, int subnetzSize, string gateway)
        {
            Console.Clear();
            Console.WriteLine("Network information:");
            Console.WriteLine($"- Local IP address: {localIP}");
            Console.WriteLine($"- Subnet: {subnet}");
            Console.WriteLine($"- Network size: /{subnetzSize}");
            Console.WriteLine($"- Gateway: {gateway}");
            Console.WriteLine();


        }

        // Gibt eine Zusammenfassung der Scans aus.
        public static void PrintSummary(double elapsedSeconds)
        {
            Console.WriteLine($"Duration of the ARP sweep: {elapsedSeconds:F2} seconds");
            Console.WriteLine($"Number of hosts found: {Network_Scanner.count}");
            Console.WriteLine();
        }

        // Fragt nach Administrator-Zugangsdaten und versucht, sich per SSH anzumelden.
        public static void RequestAdminCredentialsAndLogin(string switchIp)
        {


            string switchType = typeOfSwitch(switchIp);

            if (switchType == "Managed Switch" || switchType == "Automatic detection")
            {
                Console.WriteLine("Please enter the username of the admin:");
                string adminName = Console.ReadLine();

                Console.WriteLine("Please enter the password of the admin:");
                SecureString password = Authorization.ReadPassword(); // Hier wird das Passwort ohne Sichtbarkeit eingegeben

                bool login = Authorization.CheckSwitchLoginWithShell(switchIp, adminName, password);

                if (!login)
                {
                    if (switchType == "Automatic detection")
                    {
                        Console.WriteLine("Your switch may be a legacy or unmanaged switch. Your switch is not accessible via Ssh, which indicates that");
                    }
                    else // Für den Fall, dass es sich um einen Managed Switch handelt
                    {
                        Console.WriteLine("The login was not successful. SSH may need to be activated on the managed switch. " +
                                          "Please try again.");
                    }
                }
            }
            else
            {
                Console.WriteLine("There is currently no implementation for the device: " + switchType + " in the software.");
            }
        }

        // Fortschrittsanzeige für Scans in der Konsole.
        public static void UpdateProgressBar(int current, int total, int progressBarLength, object consoleLock)
        {

            if (total > 0)
            {
                double progressPercentage = Math.Min((current / (double)total), 1.0);
                int progressBarFilled = (int)(progressBarLength * progressPercentage);

                // Fortschrittsbalken erstellen
                int progress = Math.Max(progressBarLength - progressBarFilled - 1, 0);
                string progressBar = new string('#', progressBarFilled) + new string('-', progress);

                lock (consoleLock)
                {
                    // Lösche die aktuelle Zeile und schreibe den Fortschrittsbalken
                    Console.SetCursorPosition(0, Console.CursorTop);
                    if (progressBarLength == progressBarFilled + 1)
                    {
                        Console.Write($"[{progressBar}] (100%)");
                    }
                    else
                    {
                        Console.Write($"[{progressBar}] ({progressPercentage:P0})");
                    }
                }
            }
        }

        // Start-Informationen anzeigen und Benutzerabfragen.
        public static string OutputStartInfo(ShellStream shellStream)
        {
            string manufacturer = "";
            shellStream.WriteLine("");
            string result = Authorization.ReadStream(shellStream, "");

            if (!string.IsNullOrEmpty(result))
            {
                if (result.Contains("Aruba"))
                {
                    manufacturer = "Aruba";
                }
                shellStream.WriteLine("A");
                Authorization.ReadStream(shellStream, "A");
            }
            return manufacturer;
        }

        // Führt einen SSH-Befehl aus, liest die Ausgabe und zeigt sie an.
        public static string ExecuteSshCommand(string command, ShellStream shellStream)
        {
            shellStream.WriteLine(command);
            Authorization.ReadStream(shellStream, "");
            shellStream.WriteLine("A");
            string result = Authorization.ReadStream(shellStream, "");
            shellStream.Flush();

            return result;
        }

        public static string typeOfSwitch(string switchIpAddress)
        {
            string switchType = "";
            Console.WriteLine("Select the type of switch:");
            Console.WriteLine("1. Managed Switch");
            Console.WriteLine("2. Unmanaged Switch");
            Console.WriteLine("3. Legacy Switch");
            Console.WriteLine("4. Automatic detection");

            string choice = Console.ReadLine();

            switch (choice)
            {
                case "1":
                    Console.WriteLine("Managed Switch selected.");
                    // Logik für Managed Switch
                    switchType = "Managed Switch";
                    break;
                case "2":
                    Console.WriteLine("Unmanaged Switch selected.");
                    // Logik für Unmanaged Switch
                    switchType = "Unmanaged Switch";
                    break;
                case "3":
                    Console.WriteLine("Legacy Switch selected.");
                    // Logik für Legacy Switch
                    switchType = "Legacy Switch";
                    break;
                case "4":
                    switchType = "Automatische Erkennung";
                    break;
                default:
                    Console.WriteLine("Invalid selection. Please select a valid option.");
                    typeOfSwitch(switchIpAddress);
                    break;
            }

            return switchType;

        }

        public static void PrintSwitchInfos(string manufacturer, string model, string deviceType, string firmwareVersion, string result)
        {
            Console.WriteLine(new string('─', 60));
            Console.WriteLine($"-Manufacturer        : {manufacturer}");
            Console.WriteLine($"-Model               : {model}");
            Console.WriteLine($"-Device type         : {deviceType}");
            Console.WriteLine($"-Firmware-Version    : {firmwareVersion}");
            Console.WriteLine(new string('─', 60));


            switchInfos.Manufacturer = manufacturer;
            switchInfos.Model = model;
            switchInfos.DeviceType = deviceType;
            switchInfos.FirmwareVersion = firmwareVersion;

            string json = LoadJson.LoadEmbeddedJson();
            // Deserialisiere den JSON-String in ein PortsList-Objekt
            var portsDictionary = JsonConvert.DeserializeObject<Dictionary<string, List<PortInfo>>>(json);

            // Jetzt die offenen Ports extrahieren und ausgeben
            List<string> openPorts = ManufacturerRegex.GetOpenPorts(result);
            Console.WriteLine("Open ports:\n");

            if (openPorts.Count >= 0)
            {
                switchInfos.Ports = new List<Port>();
                foreach (var port in openPorts)
                {
                    string portTrimmed = port.Trim(); // Entferne mögliche Leerzeichen

                    // Überprüfe, ob der Port in der portsDictionary vorhanden ist
                    if (portsDictionary.TryGetValue(portTrimmed, out var portInfoList))
                    {
                        foreach (var portInfo in portInfoList)
                        {
                            Console.WriteLine($"-{portTrimmed}\t{portInfo.Description}");

                            // Initialisiere das Port-Objekt hier neu, um sicherzustellen, dass es nicht null ist
                            var portJson = new Netzwerkscanner.dataModels.Port
                            {
                                PortNum = portTrimmed,
                                PortDescription = portInfo.Description
                            };
                            // Füge das Port-Objekt zur Ports-Liste in switchInfos hinzu
                            switchInfos.Ports.Add(portJson);
                        }
                    }
                    else
                    {
                        var portNotJson = new Netzwerkscanner.dataModels.Port
                        {
                            PortNum = portTrimmed,
                            PortDescription = "unknown"
                        };
                        Console.WriteLine($"-{portTrimmed}\tunknown");
                        switchInfos.Ports.Add(portNotJson);
                    }
                }
            }
            else
            {
                Console.WriteLine("No open ports found.");
            }

            Console.WriteLine(new string('─', 60));

            // VLAN-Informationen anzeigen
            var vlans = ManufacturerRegex.GetVlans(result);
            if (vlans.Count > 0)
            {
                switchInfos.Vlans = new List<Vlan>();
                // Kopfzeile für die Tabelle
                Console.WriteLine($"{"VLAN",-20} {"IP Address",-20} {"Subnet Mask",-20}");
                Console.WriteLine(new string('-', 60)); // Längere Trennlinie

                // Ausgabe jeder Zeile in der Tabelle
                foreach (var vlan in vlans)
                {
                    var vlanJson = new Vlan
                    {
                        VlanName = vlan.VlanName,
                        IpAdress = vlan.Ip,
                        SubMask = vlan.SubnetMask,

                    };
                    switchInfos.Vlans.Add(vlanJson);
                    Console.WriteLine($"{vlan.VlanName,-20} {vlan.Ip,-20} {vlan.SubnetMask,-20}");
                }
            }

            Console.WriteLine(new string('─', 60));
            switchInfos.Pakets = new List<Paket>();
            // Eingehende und ausgehende Pakete anzeigen
            var packetCounts = ManufacturerRegex.GetPacketCounts(result);
            var paket = new Paket();
            if (packetCounts.Count > 0)
            {
                Console.WriteLine("Packets received and sent:\n");

                foreach (var packet in packetCounts)
                {
                    Console.WriteLine($"{packet.Key} : {packet.Value}");
                    if (packet.Key == "Eingehende Pakete")
                    {
                        paket.IncomingPackages = packet.Value;
                    }
                    else
                    {
                        paket.OutgoingPackets = packet.Value;
                    }
                }
                switchInfos.Pakets.Add(paket);
            }
            else
            {
                Console.WriteLine("No package information found.");
            }

            var packetDetails = ManufacturerRegex.GetPacketDetails(result);
            if (packetDetails.Count > 0)
            {
                Console.WriteLine("\nPackage details:\n");
                foreach (var detail in packetDetails)
                {
                    Console.WriteLine($"{detail.Key} : {detail.Value}");
                    if (detail.Key == "Gesamtzahl der Pakete")
                    {
                        paket.TotalNumberOfPackages = detail.Value;
                    }
                    if (detail.Key == "Verfügbare Puffer für eingehende Pakete")
                    {
                        paket.BufferIncoming = detail.Value;
                    }
                    if (detail.Key == "Niedrigste Anzahl an verfügbaren Puffern")
                    {
                        paket.MinBuffer = detail.Value;
                    }
                    if (detail.Key == "Verpasste Pakete aufgrund fehlender Puffer")
                    {
                        paket.LostPackets = detail.Value;
                    }

                }
            }
            else
            {
                Console.WriteLine("No further package details found.");
            }
            Console.WriteLine(new string('─', 60));
        }
    }
}
