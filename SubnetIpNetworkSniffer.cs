using System.Net;
using System.Runtime.InteropServices;
using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Net.Http;

class SubnetIpNetworkSniffer
{
	[DllImport("iphlpapi.dll", ExactSpelling = true)]
	private static extern int SendARP(int destIp, int srcIp, byte[] macAddr, ref int physicalAddrLen);
	private static int count;

	public static async Task Main(string[] args)
	{
		// Benutzerabfrage
		Console.WriteLine("Möchten Sie alle Informationen (IP-Adresse, MAC-Adresse, Hostname und Hersteller) sehen? (y/n):");
		string input = Console.ReadLine().Trim().ToLower();
		bool showAllInfo = input == "y";

		var (localIP, subnetMask, gateway) = GetLocalIPAddressAndSubnetMask();
		if (localIP == null || subnetMask == null)
		{
			Console.WriteLine("Keine lokale IP-Adresse oder Subnetzmaske gefunden.");
			return;
		}

		int subnetzSize = 0;
		foreach (int octet in subnetMask)
		{
			string binaryOctet = Convert.ToString(octet, 2).PadLeft(8, '0');
			foreach (char bit in binaryOctet)
			{
				if (bit == '1')
				{
					subnetzSize++;
				}
				else
				{
					break;
				}
			}
		}

		int maxOctetSize = 32;
		int maxSubnetzSize = maxOctetSize - subnetzSize;
		int numOfIps = (int)Math.Pow(2, maxSubnetzSize);

		string subnet = GetSubnet(localIP);
		int[] subnetArray = GetSubnetArray(localIP);
		Console.WriteLine($"IP-Adresse: {localIP} -> Subnetz: {subnet}0/{subnetzSize}");
		Console.WriteLine($"Gateway: {gateway}");

		Stopwatch stopwatch = new Stopwatch();
		stopwatch.Start();

		var foundDevices = await ARPSweep(numOfIps, subnetArray, showAllInfo);

		stopwatch.Stop();

		Console.WriteLine("\nGefundene Geräte sortiert nach IP-Adresse:");
		foreach (var device in foundDevices)
		{
			string hostname = GetHostName(device.Key);
			if (showAllInfo)
			{
				Console.WriteLine($"Gerät gefunden: {device.Key}, MAC-Adresse: {device.Value.MacAddress}, \n\nHostname: {hostname}, Hersteller: {device.Value.Manufacturer}");
			}
			else
			{
				Console.WriteLine($"Gerät gefunden: {device.Key}, MAC-Adresse: {device.Value.MacAddress}, Hostname: {hostname}");
			}
		}

		Console.WriteLine($"\n{count} Hosts gefunden");
		Console.WriteLine($"Zeit für den ARP-Sweep: {stopwatch.Elapsed.TotalSeconds:F2} s");
		Console.WriteLine($"Gateway: {gateway}");
	}

	static async Task<SortedDictionary<string, (string MacAddress, string Manufacturer)>> ARPSweep(int numOfIps, int[] subnetArray, bool showAllInfo)
	{
		var foundDevices = new SortedDictionary<string, (string MacAddress, string Manufacturer)>();
		int j = 0;
		int k = 0;

		if (numOfIps == 0)
		{
			return foundDevices;
		}

		if (showAllInfo)
		{
			await Parallel.ForEachAsync(Enumerable.Range(1, 254), async (i, _) =>
			{
				string subnet = string.Join(".", subnetArray.Take(subnetArray.Length - 1));
				string ip = $"{subnet}.{i}";
				IPAddress ipAddress;

				try
				{
					ipAddress = IPAddress.Parse(ip);
				}
				catch (FormatException)
				{
					return;
				}

				byte[] macAddr = new byte[6];
				int len = macAddr.Length;

				try
				{
					int result = SendARP(BitConverter.ToInt32(ipAddress.GetAddressBytes(), 0), 0, macAddr, ref len);

					if (result == 0)
					{
						var macAddress = FormatMacAddress(macAddr);
						string manufacturer = "Unbekannt";

						if (showAllInfo)
						{
							manufacturer = await GetManufacturerFromMac(macAddress);
						}

						lock (foundDevices)
						{
							j++;
							Console.WriteLine($"{j}: Host gefunden");
							if (!foundDevices.ContainsKey(ip))
							{
								foundDevices.Add(ip, (macAddress, manufacturer));
								count++;
							}
						}
					}
				}
				catch
				{
				}
			});
		}
		else
		{
			Parallel.For(1, 255, i => // bedeutet ip adresse von 1 bis 254
			{
				string subnet = string.Join(".", subnetArray.Take(subnetArray.Length - 1));
				string ip = $"{subnet}.{i}";
				IPAddress ipAddress;

				if (i == 254)  // "255 -> Brodcast" "1-254 -> 254 pro Octette"
				{
					k++;
				}

				try
				{
					ipAddress = IPAddress.Parse(ip);
				}
				catch (FormatException)
				{
					return;
				}

				byte[] macAddr = new byte[6];
				int len = macAddr.Length;

				try
				{
					int result = SendARP(BitConverter.ToInt32(ipAddress.GetAddressBytes(), 0), 0, macAddr, ref len);

					if (result == 0)
					{
						var macAddress = FormatMacAddress(macAddr);

						lock (foundDevices)
						{
							j++;
							Console.WriteLine($"{j}: Host gefunden");
							if (!foundDevices.ContainsKey(ip))
							{
								foundDevices.Add(ip, (macAddress, "Unbekannt"));
								count++;
							}
						}
					}
				}
				catch (Exception ex)
				{
					Console.WriteLine($"Fehler beim Senden von ARP-Request für {ip}: {ex.Message}");
				}
			});
		}

		if (k > 0)
		{
			subnetArray[2] = subnetArray[2] - 1;
			if (subnetArray[2] < 0)
			{
				subnetArray[1] = subnetArray[1] - 1;
				subnetArray[2] = 255;
				if (subnetArray[1] < 0)
				{
					subnetArray[0] = subnetArray[0] - 1;
					subnetArray[1] = 255;
					if (subnetArray[0] < 0)
					{
						return foundDevices;
					}
				}
			}
			foundDevices = await ARPSweep(numOfIps - 256, subnetArray, showAllInfo);
			k = 0;
		}

		return foundDevices;
	}

	static (string, int[], string) GetLocalIPAddressAndSubnetMask()
	{
		foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
		{
			if (ni.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up)
			{
				foreach (var ua in ni.GetIPProperties().UnicastAddresses)
				{
					if (ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
					{
						string ipAddress = ua.Address.ToString();
						string subnetMask = ua.IPv4Mask.ToString();
						string gateway = ni.GetIPProperties().GatewayAddresses.FirstOrDefault()?.Address.ToString();
						int[] subnetMaskArray = subnetMask.Split('.').Select(int.Parse).ToArray();
						return (ipAddress, subnetMaskArray, gateway);
					}
				}
			}
		}
		return (null, null, null);
	}

	static string GetSubnet(string ipAddress)
	{
		var segments = ipAddress.Split('.');
		if (segments.Length == 4)
		{
			return $"{segments[0]}.{segments[1]}.{segments[2]}.";
		}
		else
		{
			throw new FormatException("Invalid IP address format.");
		}
	}

	static int[] GetSubnetArray(string ipAddress)
	{
		var segments = ipAddress.Split('.');
		if (segments.Length == 4)
		{
			return segments.Select(s => int.Parse(s)).ToArray();
		}
		else
		{
			throw new FormatException("Invalid IP address format.");
		}
	}

	static string FormatMacAddress(byte[] macAddr)
	{
		return string.Join(":", macAddr.Select(b => b.ToString("X2")));
	}

	static string GetHostName(string ipAddress)
	{
		try
		{
			IPHostEntry entry = Dns.GetHostEntry(ipAddress);
			return entry.HostName;
		}
		catch (Exception)
		{
			return "Unbekannt";
		}
	}

	static string ExtractOUI(string macAddress)
	{
		return string.Join(":", macAddress.Split(':').Take(3));
	}

	static async Task<string> GetManufacturerFromMac(string macAddress)
	{
		string oui = ExtractOUI(macAddress);

		string apiUrl = $"https://api.macvendors.com/{oui.Replace(":", "")}";

		try
		{
			using (HttpClient client = new HttpClient())
			{
				HttpResponseMessage response = await client.GetAsync(apiUrl);
				response.EnsureSuccessStatusCode();
				string manufacturer = await response.Content.ReadAsStringAsync();
				return manufacturer;
			}
		}
		catch 
		{
			return "Unbekannt";
		}
	}
}
