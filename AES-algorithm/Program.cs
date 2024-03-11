using System.Security.Cryptography;
using System.Text;
using System.Threading.Channels;
using Microsoft.VisualBasic.FileIO;
using Newtonsoft.Json;

class Program
{
	static void Main(string[] args)
	{
		start:

		FileIO data = new();

		Console.WriteLine("AES algorithm encryption/decryption.");
		Console.WriteLine("1. Encrypt your text.");
		Console.WriteLine("2. Decrypt your text.");
		Console.WriteLine("0. Quit the application.");
		Console.Write("Your selection: ");

		int opSelection = int.Parse(Console.ReadLine());

		string dfv = @"EncryptionInfo.json";

		switch (opSelection)
		{
			case 1:
				Console.Write("Type in your cipher key: ");
				string strKey = Console.ReadLine();
				data.key = Encoding.UTF8.GetBytes(strKey);

				make128b(ref data.key);
				
				Console.Write("Type in your initialization vector: ");
				string strIv = Console.ReadLine();
				data.iv = Encoding.UTF8.GetBytes(strIv);

				make128b(ref data.iv);

				Console.Write("Type in the word(-s) you'd like to be encrypted: ");
				string simpleText = Console.ReadLine();

				data.encryptedText = Encrypt(simpleText, data.key, data.iv);

				string input = JsonConvert.SerializeObject(data);
				File.WriteAllText(dfv, input);

				Console.WriteLine(data.encryptedText);
				break;

			case 2:
				if (!File.Exists(dfv))
				{
					Console.WriteLine("Oopsies, it appears that you have not ecnrypted any text yet. Go do that first!");
					break;
				}

				data = JsonConvert.DeserializeObject<FileIO>(File.ReadAllText(dfv));

				simpleText = Decrypt(data.encryptedText, data.key, data.iv);

				Console.WriteLine(simpleText);

				break;

			case 0:
				Console.WriteLine("The program has been stopped.");
				return;

			default:
				Console.Write("The operation you've selected doesn't exist, please type in a valid operation number.");
				break;
		}

		goto start;
	}

	static byte[] Encrypt(string simpleText, byte[] key, byte[] iv)
	{
		byte[] cipheredText;
		using (Aes aes = Aes.Create())
		{
			ICryptoTransform encryptor = aes.CreateEncryptor(key, iv);
			using (MemoryStream memoryStream = new MemoryStream())
			{
				using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
				{
					using (StreamWriter streamWriter = new StreamWriter(cryptoStream))
					{
						streamWriter.Write(simpleText);
					}

					cipheredText = memoryStream.ToArray();
				}
			}
		}

		return cipheredText;
	}

	static string Decrypt(byte[] cipheredText, byte[] key, byte[] iv)
	{
		string simpleText = string.Empty;
		using (Aes aes = Aes.Create())
		{
			ICryptoTransform decryptor = aes.CreateDecryptor(key, iv);
			using(MemoryStream memoryStream = new MemoryStream(cipheredText))
			{
				using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
				{
					using (StreamReader streamReader = new StreamReader(cryptoStream))
					{
						simpleText = streamReader.ReadToEnd();
					}
				}
			}
		}
		return simpleText;
	}

	static void make128b(ref byte[] bytes)
	{
		var outputBytes = new List<byte>();

		for(int i = 0; i < 16; i++)
			outputBytes.Add(bytes[i % bytes.Length]);

		bytes = outputBytes.ToArray();
	}
}

class FileIO
{
	public byte[] key;
	public byte[] iv;
	public byte[] encryptedText;
}