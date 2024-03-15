using Newtonsoft.Json;
using System.Security.Cryptography;
using System.Text;

class Program
{
	public static FileIO data = new();

	enum modes
	{
		CBC = 1,
		ECB = 2,
		CFB = 4
	}

	static void Main(string[] args)
	{
	start:
		//aes.Mode = CipherMode.CBC;--------------------------------------------------------------------------------------------------

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
				Console.WriteLine("1. Cbc\n2. Ecb\n3. Cfb");
				Console.WriteLine("Select your encryption mode: ");
				data.mode = Math.Clamp(int.Parse(Console.ReadLine()), 1, 3);

				data.mode = (int)((CipherMode)(int)(Enum.GetValues(typeof(modes)).GetValue(data.mode - 1) ?? 1));

				Console.Write("Type in your cipher key: ");
				string strKey = Console.ReadLine();
				data.key = Encoding.UTF8.GetBytes(strKey);

				make128b(ref data.key);

				Console.Write("Type in the word(-s) you'd like to be encrypted: ");
				string simpleText = Console.ReadLine();

				data.encryptedText = Encrypt(simpleText, data.key, data.mode);

				string input = JsonConvert.SerializeObject(data);
				File.WriteAllText(dfv, input);

				foreach (var garbage in data.encryptedText)
					Console.Write($"{garbage} ");

				Console.Write("\n\n");
				break;

			case 2:
				data = null;

				if (File.Exists(dfv))
				{
					Console.Write("Saved encryption detected, would you like to decrypt it? (y/n): ");
					if (Console.ReadLine().ToLower()[0] == 'y')
						data = JsonConvert.DeserializeObject<FileIO>(File.ReadAllText(dfv));
				}

				
				if(data == null)
				{
					goto start;
				}


				simpleText = Decrypt(data.encryptedText, data.key, data.mode);

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

	static byte[] Encrypt(string simpleText, byte[] key, int mode)
	{
		byte[] cipheredText;
		byte[] iv;

		using (Aes aes = Aes.Create())
		{
			if (mode != 0)
				aes.Mode = (CipherMode)mode;

			aes.Padding = PaddingMode.PKCS7;

			if (aes.Mode == CipherMode.ECB)
				iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			else
				iv = aes.IV;

			data.iv = iv;

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

	static string Decrypt(byte[] cipheredText, byte[] key, int mode)
	{
		string simpleText = string.Empty;
		byte[] iv;

		using (Aes aes = Aes.Create())
		{
			if (mode != 0)
				aes.Mode = (CipherMode)mode;
			aes.Padding = PaddingMode.PKCS7;

			if (aes.Mode == CipherMode.ECB)
				iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			else
				iv = data.iv;

			data.iv = iv;

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