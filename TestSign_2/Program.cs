namespace TestSign_2;

class Program
{
    static void Main()
    {
        const string certificateCn = "Test Certificate";

        ISignProvider provider = new CryptoProProvider();

        var inputFilePath = Path.Combine(Environment.CurrentDirectory, "input.txt");
        var signedFilePathAttached = Path.Combine(Environment.CurrentDirectory, "input.sig");
        try
        {
            CreateFile(inputFilePath);
            provider.Sign(inputFilePath, signedFilePathAttached, certificateCn, true);
            Console.WriteLine("Документ успешно подписан");
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
        }
    }

    private static void CreateFile(string inputFilePath)
    {
        if (!File.Exists(inputFilePath))
        {
            using var sw = new StreamWriter(inputFilePath);
            sw.Write("TEST");
        }
    }
}