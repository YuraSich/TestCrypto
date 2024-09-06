using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using CryptoPro.Security.Cryptography.Pkcs;
using CryptoPro.Security.Cryptography.X509Certificates;

namespace TestSign_2;

public class CryptoProProvider : ISignProvider
{
    public void Sign(string inputFilePath, string signedFilePath, string certificateCn, bool detached)
    {
        var bytesToHash = File.ReadAllBytes(inputFilePath);
        using var gostCert = GetCertificate(certificateCn);
        var contentInfo = new ContentInfo(bytesToHash);
        var signedCms = new CpSignedCms(contentInfo, detached);
        var cmsSigner = new CpCmsSigner(gostCert);

        signedCms.ComputeSignature(cmsSigner);
        var signature = signedCms.Encode();

        File.WriteAllBytes(signedFilePath, signature);
    }

    private static CpX509Certificate2 GetCertificate(string certificateCn)
    {
        using var store = new CpX509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        return store.Certificates.Find(X509FindType.FindBySubjectName, certificateCn, true).FirstOrDefault() ?? throw new Exception("Не найден сертификат");
    }
}