using System.Security.Cryptography.X509Certificates;
using TestSign_1.NetWinapiCms;

namespace TestSign_2;

public class NetWinapiCmsProvider : ISignProvider
{
    public void Sign(string inputFilePath, string signedFilePath, string certificateCn, bool detached)
    {
        var data = File.ReadAllBytes(inputFilePath);

        var certificate = GetSignerCert(certificateCn) ?? throw new Exception("Сертификат врача не найден на компьютере");
        var digestOid = GostOids.id_tc26_gost3410_12_256;
        var signed = CmsHelper.Sign(data, true, certificate, digestOid, false, "");
        File.WriteAllBytes(signedFilePath, signed);
    }

    private static X509Certificate2 GetSignerCert(string certificateCn)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        return store.Certificates.Find(X509FindType.FindBySubjectName, certificateCn, true).FirstOrDefault() ?? throw new Exception("Не найден сертификат");
    }
}