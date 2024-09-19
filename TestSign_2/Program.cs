using System.Reflection.PortableExecutable;
using System.Text;

namespace SignTestApp;

internal static class Program
{
    private const string CertificateCn = "Test Certificate";
    private const string Email = "test@email.ru";
    private const string SampleData = "Sample data to sign";
    private static void Main()
    {
        var encoding = new UnicodeEncoding();
        var msgBytes = encoding.GetBytes(SampleData);

        ICryptoProService provider = new CryptoProService();

        try
        {
            File.WriteAllBytes("source.txt", msgBytes);
            var cert = provider.GetCert(Email) ?? provider.GenerateCertificate(CertificateCn, Email);

            var signature = provider.Sign(msgBytes, cert);
            Console.WriteLine("Signature: ");
            Console.WriteLine(Convert.ToBase64String(signature));
            Console.WriteLine();
            File.WriteAllBytes("signature.sig", signature);

            var encrypted = provider.Encrypt(msgBytes, cert);
            Console.WriteLine("Encrypted: ");
            Console.WriteLine(Convert.ToBase64String(encrypted));
            Console.WriteLine();
            File.WriteAllBytes("encrypted.txt.p7e", encrypted);

            var decrypted = provider.Decrypt(encrypted, cert);
            Console.WriteLine($"Decrypted: {encoding.GetString(decrypted)}");
            File.WriteAllBytes("decrypted.txt", decrypted);
        }
        catch (Exception ex)
        {       
            Console.WriteLine(ex);
        }
    }
}