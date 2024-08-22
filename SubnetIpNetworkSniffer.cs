﻿using System.Net;
using System.Runtime.InteropServices;
using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Diagnostics;

class SubnetIpNetworkSniffer
{
	[DllImport("iphlpapi.dll", ExactSpelling = true)]
	private static extern int SendARP(int destIp, int srcIp, byte[] macAddr, ref int physicalAddrLen);
	private static int count;

	public static void Main(string[] args)
	{
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
		int numOfIps = (int)Math.Pow(2, 5 + maxSubnetzSize); // Berechnung der Größe des Subnetzes

		string subnet = GetSubnet(localIP);  // nur da für die ausgabe vieleicht auch noch anders lösbar 
		int[] subnetArray = GetSubnetArray(localIP);
		Console.WriteLine($"IP-Adresse: {localIP} -> Subnetz: {subnet}0/{subnetzSize}");
		Console.WriteLine($"Gateway: {gateway}");

		Stopwatch stopwatch = new Stopwatch();
		stopwatch.Start();

		int[] subnetArray1 = { 1, 1, 1, 0 };
		var foundDevices = ARPSweep(numOfIps, subnetArray1);

		stopwatch.Stop();

		Console.WriteLine("\nGefundene Geräte sortiert nach IP-Adresse:");
		foreach (var device in foundDevices)
		{
			string hostname = GetHostName(device.Key);
			Console.WriteLine($"Gerät gefunden: {device.Key}, MAC-Adresse: {device.Value}, Hostname: {hostname}");
		}

		Console.WriteLine($"\n{count} Hosts gefunden");
		Console.WriteLine($"Zeit für den ARP-Sweep: {stopwatch.Elapsed.TotalSeconds:F2} s");
		Console.WriteLine($"Gateway: {gateway}");
	}

	public static void GetARPTable()
	{
		Process process = new Process();
		process.StartInfo.FileName = "arp";
		process.StartInfo.Arguments = "-a";
		process.StartInfo.RedirectStandardOutput = true;
		process.StartInfo.UseShellExecute = false;
		process.StartInfo.CreateNoWindow = true;
		process.Start();

		string output = process.StandardOutput.ReadToEnd();
		process.WaitForExit();

		Console.WriteLine(output);
	}


	static SortedDictionary<string, string> ARPSweep(int numOfIps, int[] subnetArray)
	{
		var foundDevices = new SortedDictionary<string, string>();
		int j = 0;
		int k = 0;
		Console.WriteLine(numOfIps);
		Parallel.For(1, 255, i =>
		{


			if (i == 254)  // O -> Router 256 -> Brodcast 1-254 -> 254 pro Octette
			{
				k++;
			}

			string subnet = string.Join(".", subnetArray.Take(subnetArray.Length - 1));
			string ip = $"{subnet}.{i}";
			IPAddress ipAddress;
			Console.WriteLine($"{ip}");

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

			// try
			// {
			// 	int result = SendARP(BitConverter.ToInt32(ipAddress.GetAddressBytes(), 0), 0, macAddr, ref len);

			// 	if (result == 0)
			// 	{
			// 		var macAddress = FormatMacAddress(macAddr);

			// 		lock (foundDevices)
			// 		{
			// 			j++;
			// 			Console.WriteLine($"{j}: Host gefunden");
			// 			if (!foundDevices.ContainsKey(ip))
			// 			{
			// 				foundDevices[ip] = macAddress;
			// 				count++;
			// 			}
			// 		}
			// 	}
			// }
			// catch (Exception ex)
			// {
			// 	Console.WriteLine($"Fehler beim Senden von ARP-Request für {ip}: {ex.Message}");
			// }
		});

		if (k > 0)
		{
			Console.WriteLine("\n");
			Console.WriteLine($"subnetArray[2] = {subnetArray[2]}");
			subnetArray[2] = subnetArray[2] - 1;
			Console.WriteLine($"subnetArray[2] - 1 = {subnetArray[2]}");
			Console.WriteLine($"ARPSweep wird mit numOfIps = {numOfIps - 1 - 255} und subnetArray {string.Join(".", subnetArray.Take(subnetArray.Length - 1))}");
			Console.WriteLine(subnetArray[2]);
			
			if (subnetArray[2] < 0)
			{
				subnetArray[1] = subnetArray[1] - 1;
				subnetArray[2] = 255;
				if (subnetArray[1] < 0)
				{
					subnetArray[0] = subnetArray[0] - 1;
					subnetArray[1] = 1;
					if(subnetArray[0] < 0)
					{
						return foundDevices;	
						
					}
				}
				}
			ARPSweep(numOfIps - 1 - 255, subnetArray);
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

	static string GetSubnet(string ipAddress) // funktion später unnötig
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
}
