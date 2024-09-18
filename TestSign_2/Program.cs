using System.Text;

namespace SignTestApp;

internal static class Program
{
    // Тестовый сертификат с сайта крипто про
    private const string Thumbprint = "08a8068fbf9577ea7e3c4f16b30d01eb6d032e87";
    
    private const string CertificateCn = "Test Certificate";
    private const string Email = "test@email.ru";
    private const string SampleData = "Sample data to sign";
    private static void Main()
    {
        var encoding = new UnicodeEncoding();
        var msgBytes = encoding.GetBytes(SampleData);

        var useDefaultCert = false;

        ICryptoProService provider = new CryptoProService();

        try
        {
            var cert = useDefaultCert
                ? provider.GetDefaultCert(Thumbprint)
                : provider.GetCert(Email) ?? provider.GenerateCertificate(CertificateCn, Email);

            if (cert == null)
            {
                return;
            }

            var signature = provider.Sign(msgBytes, cert);
            WriteBytes("Signature", signature);

            var encrypted = provider.Encrypt(msgBytes, cert); 
            WriteBytes("Encrypted",encrypted.ToArray());

            var decrypted = provider.Decrypt(encrypted, cert);
            Console.WriteLine($"Decrypted: {encoding.GetString(decrypted)}");
        }
        catch (Exception ex)
        {       
            Console.WriteLine(ex);
        }
    }

    private static void WriteBytes(string header, IEnumerable<byte> source)
    {
        Console.WriteLine($"{header}: ");
        foreach (var b in source)
        {
            Console.Write("{0:x}", b);
        }
        Console.WriteLine();
    }

}