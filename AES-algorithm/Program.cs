using Newtonsoft.Json;
using System.Security.Cryptography;
using System.Text;

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
				Console.WriteLine("0. standard\n1. Cbc\n2. Cbf\n3. Ecb\n");
				Console.WriteLine("Select your encryption mode: ");
				data.mode = int.Parse(Console.ReadLine());

				switch (data.mode)
				{
					case 0:
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

						break;

					case 1:
						Console.Write("Type in your initialization vector: ");
						strIv = Console.ReadLine();
						data.iv = Encoding.UTF8.GetBytes(strIv);

						make128b(ref data.iv);

						Console.Write("Type in the word(-s) you'd like to be encrypted: ");
						simpleText = Console.ReadLine();

						data.encryptedText = EncryptCbc(simpleText, data.iv);

						input = JsonConvert.SerializeObject(data);
						File.WriteAllText(dfv, input);
						break;

					case 2:

						Console.Write("Type in your initialization vector: ");
						strIv = Console.ReadLine();
						data.iv = Encoding.UTF8.GetBytes(strIv);

						make128b(ref data.iv);

						Console.Write("Type in the word(-s) you'd like to be encrypted: ");
						simpleText = Console.ReadLine();

						data.encryptedText = EncryptCfb(simpleText, data.iv);

						input = JsonConvert.SerializeObject(data);
						File.WriteAllText(dfv, input);
						break;

					case 3:

						Console.Write("Type in the word(-s) you'd like to be encrypted: ");
						simpleText = Console.ReadLine();

						data.encryptedText = EncryptEcb(simpleText);

						input = JsonConvert.SerializeObject(data);
						File.WriteAllText(dfv, input);
						break;

					default:
						Console.WriteLine("The mode you've selected doesn't exist, please try again.");
						goto start;
				}

				foreach (var garbage in data.encryptedText)
					Console.Write($"{garbage} ");

				Console.Write("\n\n");
				break;

			case 2:
				if (!File.Exists(dfv))
				{
					Console.WriteLine("Oopsies, it appears that you have not ecnrypted any text yet. Go do that first!");
					break;
				}

				data = JsonConvert.DeserializeObject<FileIO>(File.ReadAllText(dfv));

				switch (data.mode)
				{
					case 0:

						string simpleText = Decrypt(data.encryptedText, data.key, data.iv);

						Console.WriteLine(simpleText);

						break;

					case 1:

						simpleText = Encoding.UTF8.GetString(DecryptCbc(data.encryptedText, data.iv));

						Console.WriteLine(simpleText);
						break;

					case 2:

						simpleText = Encoding.UTF8.GetString(DecryptCfb(data.encryptedText, data.iv));

						Console.WriteLine(simpleText);
						break;

					case 3:

						simpleText = Encoding.UTF8.GetString(DecryptEcb(data.encryptedText));

						Console.WriteLine(simpleText);
						break;

					default:
						Console.WriteLine("The mode you've selected doesn't exist, please try again.");
						break;
				}
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
			using (MemoryStream memoryStream = new MemoryStream(cipheredText))
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

	static byte[] EncryptCbc(string simpleText, byte[] iv)
	{
		using (Aes aes = Aes.Create())
		{
			return aes.EncryptCbc(Encoding.UTF8.GetBytes(simpleText), iv, PaddingMode.Zeros);

		}
	}

	static byte[] DecryptCbc(byte[] cipheredText, byte[] iv)
	{
		using (Aes aes = Aes.Create())
		{
			return aes.DecryptCbc(cipheredText, iv, PaddingMode.Zeros);

		}
	}

	static byte[] EncryptCfb(string simpleText, byte[] iv)
	{
		using (Aes aes = Aes.Create())
		{
			return aes.EncryptCfb(Encoding.UTF8.GetBytes(simpleText), iv);

		}
	}

	static byte[] DecryptCfb(byte[] cipheredText, byte[] iv)
	{
		using (Aes aes = Aes.Create())
		{
			return aes.DecryptCfb(cipheredText, iv);

		}
	}

	static byte[] EncryptEcb(string simpleText)
	{
		using (Aes aes = Aes.Create())
		{
			return aes.EncryptEcb(Encoding.UTF8.GetBytes(simpleText), PaddingMode.None);

		}
	}

	static byte[] DecryptEcb(byte[] cipheredText)
	{
		using (Aes aes = Aes.Create())
		{
			return aes.DecryptEcb(cipheredText, PaddingMode.None);

		}
	}

	static void make128b(ref byte[] bytes)
	{
		var outputBytes = new List<byte>();

		for (int i = 0; i < 16; i++)
			outputBytes.Add(bytes[i % bytes.Length]);

		bytes = outputBytes.ToArray();
	}
}

[Serializable]
class FileIO
{
	public int mode;
	public byte[] key;
	public byte[] iv;
	public byte[] encryptedText;
}