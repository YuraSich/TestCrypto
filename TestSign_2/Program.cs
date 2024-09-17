using CryptoModuleTest;

namespace SignTestApp;

internal static class Program
{
    private static void Main()
    {
        const string certificateCn = "Test Certificate";
        const string email = "test@email.ru";

        var provider = new CryptoProService();

        try
        {
            var cert = provider.GetCert(email) ?? provider.GenerateCertificate(certificateCn, email);
            //var cert = provider.GetDefaultCert();
            provider.EnvelopedCmsGost2012_256(cert);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
        }
    }
}