using System.Runtime.InteropServices;
using System.Text;
using CryptoModuleTest;

namespace SignTestApp;

internal static class Program
{
    private static void Main()
    {
        const string certificateCn = "Test Certificate";
        const string email = "test@email.ru";

        const string sampleData = "Sample data to sign";

        var encoding = new UTF8Encoding();
        var msgBytes = encoding.GetBytes(sampleData);

        var provider = new CryptoProService();

        try
        {
            var cert = provider.GetCert(email) ?? provider.GenerateCertificate(certificateCn, email);
            //var cert = provider.GetDefaultCert();
            //provider.EnvelopedCmsGost2012_256(cert);

            //var signature = provider.Sign(msgBytes, cert);
            provider.EnvelopedCmsGost2012_256(cert);
            var encrypted = provider.Encrypt(msgBytes, cert);
            var decrypted = provider.Decrypt(encrypted, cert);
        }
        catch (Exception ex)
        {       
            Console.WriteLine(ex);
        }
    }
}