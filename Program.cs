using System;
using System.Management;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Security.Principal;

namespace Project_internship
{
	//this is a collection of little things. 
	//Some of those things are similiar to what I did in the summer
	//which is gather system requirement and then check if user met the requirement 
	//C# provides a lot of useful libraries itself that people already written 
	//This makes it easier to program complicated things 
	//There are also a lot of resources/instructions/discussion online about how to 
	//use C# more efficiently, I used them a lot to finish this project

	//The project could only run correctly under windowns environment, the debug folder
	//under bin folder could use to test the result of program

	class MainClass
	{
		public static void Main (string[] args)
		{
			int choice = 0;

			while (choice != -1) {
				Console.WriteLine ("");
				Console.WriteLine ("Tool kit");
				Console.WriteLine ("What do you want to do?");
				Console.WriteLine ("1. Get system configuration.");
				Console.WriteLine ("2. Check if current user is admin.");
				Console.WriteLine ("3. Block a website (User need to be an admin to do this).");
				Console.WriteLine ("4. Unblock a website.");
				Console.WriteLine ("5. Encypt a File with Password.");
				Console.WriteLine ("6. Decypt a File with Password");
				Console.WriteLine ("-1. quit.");
				Console.WriteLine ("");

				choice = Convert.ToInt32 (Console.ReadLine ());
				switch (choice) {
				case 1:
					try {
						Console.WriteLine ("Your current OS and its Version: {0}", Environment.OSVersion.ToString ());

						var memory_size_byte = new Microsoft.VisualBasic.Devices.ComputerInfo ().TotalPhysicalMemory;
						var memory_size_gb = memory_size_byte/ (1024 * 1024 * 1024);
						Console.WriteLine ("You have {0} GB of RAM", memory_size_gb);

						Console.WriteLine("CPU: {0}", GetCPUInfo());

						if (AntivirusInstalled () == false)
							Console.WriteLine ("Don't have any antivirus software installed!");
						else
							Console.WriteLine ("Have antivirus software installed!");
							
					} catch (Exception e) {
						Console.WriteLine (e.ToString ());
					}
					break;
				case 2:
					if (IsAdmin ())
						Console.WriteLine ("Current user is an admin");
					else
						Console.WriteLine ("Current user is not an admin");
					break;
				case 3: 
					if (IsAdmin ()) {
						Console.WriteLine ("Input the webite site you want to block:");
						var site = Console.ReadLine ();
						BlockWebsite (site);
					} else {
						Console.WriteLine ("Current user is not an admin therefore you can't use this");
					}

					break;
				case 4:
					if (IsAdmin ()) {
						Console.WriteLine ("Input the website site you want to unblock:");
						var new_site = Console.ReadLine ();
						UnblockWebsite (new_site);
					} else {
						Console.WriteLine ("Current user is not an admin therefore you can't use this");
					}
					break;
				case 5:
					Console.WriteLine ("Input the file name that you want to encrpt(including path, and there should be content in the file!):");
					var input_file_name = Console.ReadLine ();
					Console.WriteLine ("Input password for the file: (8 characters) ");
					var password = Console.ReadLine ();
			
					EncryptFile (input_file_name, password);
					break;
				case 6:
					Console.WriteLine ("Input the file name that you want to decrpt(including path):");
					var file_name = Console.ReadLine ();
					Console.WriteLine ("Input password for the file: ");
					var password1 = Console.ReadLine ();

					DecryptFile (file_name, password1);
					break;
				default:
					Console.WriteLine ("No such choice.");
					break;
				}
			}	
		}

		static private bool IsAdmin()
		{
			bool isAdmin;
			try
			{
				WindowsIdentity user = WindowsIdentity.GetCurrent();
				WindowsPrincipal principal = new WindowsPrincipal(user);
				isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
			}
			catch (Exception e)
			{
				isAdmin = false;
			}
			return isAdmin;
		}

		static private void BlockWebsite (string site)
		{
			var path = @"C:\Windows\System32\drivers\etc\hosts";
			try {
				using (StreamWriter sw = new StreamWriter (path, true)) {
					String sitetoblock = string.Format ("\n127.0.0.1    {0}", site);
					sw.WriteLine (sitetoblock);
				}
				Console.WriteLine (String.Format ("Site {0} Blocked", site));
			} catch (Exception e) {
				Console.WriteLine (e.ToString ());
			}
		}

		static private void UnblockWebsite (string site)
		{
			try {
				var path = @"C:\Windows\System32\drivers\etc\hosts";
				var temp = @"C:\Windows\System32\drivers\etc\hosts_new";
				string line = "";

				using (var sr = new StreamReader (path)) {

					using (StreamWriter sw = new StreamWriter (temp)) {
						line = sr.ReadLine ();
						while (line != null) {

							if (line == string.Format ("\n127.0.0.1    {0}", site)) {
								sw.WriteLine ("");
							} else {
								sw.WriteLine (line);
							}

							line = sr.ReadLine ();
						}
					}
				}

				File.Delete (path);
				File.Move (temp, path);
				File.Delete (temp);
				Console.WriteLine (String.Format ("Site {0} Unblocked", site));
			} catch (Exception e) {
				Console.WriteLine (e.ToString ());
			}
		}

		static private bool AntivirusInstalled()
		{
			try
			{
				string path = @"\\" + Environment.MachineName + @"\root\SecurityCenter";
				ManagementObjectSearcher searcher = new ManagementObjectSearcher(path, "SELECT * FROM AntivirusProduct");
				ManagementObjectCollection instances = searcher.Get();
				return instances.Count > 0;
			}catch (Exception e)
			{
				Console.WriteLine(e.ToString());
			}

			return false;
		} 
			
		static private string GetCPUInfo()
		{
			try
			{
				string name ="", manufacturer="",version=""; 

				ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Processor");
				foreach (ManagementObject instance in searcher.Get()){
					name = instance["Name"].ToString();
					manufacturer = instance["Manufacturer"].ToString();
					version = instance["Version"].ToString();
				
				}
				return name + manufacturer + version;
			}catch (Exception e)
			{
				Console.WriteLine(e.ToString());
			}

			return "";
		} 

		[System.Runtime.InteropServices.DllImport ("KERNEL32.DLL", EntryPoint = "RtlZeroMemory")]
		public static extern bool ZeroMemory (ref string Destination, int Length);

		static private void EncryptFile (string sInputFilename, string sKey)
		{
			try {
				FileStream fsInput = new FileStream (sInputFilename, FileMode.Open, FileAccess.Read);
				String temp = sInputFilename+"~";
				FileStream fsEncrypted = new FileStream (temp, FileMode.Create, FileAccess.Write);
				Console.WriteLine("pass 186");

				DESCryptoServiceProvider DES = new DESCryptoServiceProvider ();

				DES.Key = ASCIIEncoding.ASCII.GetBytes (sKey);
				DES.IV = ASCIIEncoding.ASCII.GetBytes (sKey);

				ICryptoTransform desencrypt = DES.CreateEncryptor ();
				CryptoStream cryptostream = new CryptoStream (fsEncrypted, desencrypt, CryptoStreamMode.Write);
				byte[] bytearrayinput = new byte[fsInput.Length - 1];
				fsInput.Read (bytearrayinput, 0, bytearrayinput.Length);
				cryptostream.Write (bytearrayinput, 0, bytearrayinput.Length);

				cryptostream.Flush();
				cryptostream.Close();
				fsInput.Flush();
				fsInput.Close();

				File.Delete(sInputFilename);
				File.Move (temp, sInputFilename);
			} catch (Exception e) {
				Console.WriteLine (e.ToString ());
			}
		}

		static private void DecryptFile (string sInputFilename, string sKey)
		{
			try {
				String fileName = sInputFilename;
				fileName=fileName+"~";
				FileStream fsread = new FileStream (sInputFilename, FileMode.Open, FileAccess.Read);

				DESCryptoServiceProvider DES = new DESCryptoServiceProvider ();

				DES.Key = ASCIIEncoding.ASCII.GetBytes (sKey);
				DES.IV = ASCIIEncoding.ASCII.GetBytes (sKey);

				ICryptoTransform desdecrypt = DES.CreateDecryptor ();
				CryptoStream cryptostream1 = new CryptoStream (fsread, desdecrypt, CryptoStreamMode.Read);

				StreamWriter fsDecrypted = new StreamWriter (fileName);

				fsDecrypted.Write (new StreamReader (cryptostream1).ReadToEnd ());
				fsDecrypted.Flush ();
				fsDecrypted.Close ();

				cryptostream1.Flush();
				cryptostream1.Close();

				File.Delete(sInputFilename);
				File.Move (fileName, sInputFilename);

			} catch (Exception e) {
				Console.WriteLine (e.ToString ());
			}
		}
	}
}
