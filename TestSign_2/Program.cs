namespace SignTestApp;

internal static class Program
{
    private static void Main()
    {
        const string certificateCn = "Test Certificate 2";
        const string email = "test@email.ru";

        var provider = new CryptoProProvider();

        ICryptoService cryptoService = new CryptoProService();

        var inputFilePath = Path.Combine(Environment.CurrentDirectory, "input.txt");
        var signedFilePathAttached = Path.Combine(Environment.CurrentDirectory, "input.sig");
        try
        {
            var cert = cryptoService.GetCert(email);

            //CreateFile(inputFilePath);
            //provider.Sign(inputFilePath, signedFilePathAttached, certificateCn, true);
            //Console.WriteLine("Документ успешно подписан");
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