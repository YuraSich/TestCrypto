using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using CryptoPro.Security.Cryptography;
using CryptoPro.Security.Cryptography.Pkcs;
using CryptoPro.Security.Cryptography.X509Certificates;

namespace SignTestApp;

public class CryptoProProvider
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
        return store.Certificates.Find(X509FindType.FindBySubjectName, certificateCn, true).FirstOrDefault() ?? CreateCertificate(certificateCn);
    }

    private static CpX509Certificate2 CreateCertificate(string certificateCn)
    {
        var gost3410 = Gost3410_2012_256.Create();

        var builder = new X500DistinguishedNameBuilder();
        builder.AddCommonName(certificateCn);
        builder.AddCountryOrRegion("RU");
        builder.AddDomainComponent("DomainComponent");
        builder.AddEmailAddress("test@email.ru");
        builder.AddLocalityName("localityName");
        builder.AddOrganizationName("Organization");
        builder.AddOrganizationalUnitName("OrganizationUnitName");
        builder.AddStateOrProvinceName("State");

        var distinguishedName = builder.Build();

        var certificateRequest = new CpCertificateRequest(distinguishedName.Name, gost3410);

        certificateRequest.CertificateExtensions.Add(
            new CpX509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature
                | X509KeyUsageFlags.NonRepudiation
                | X509KeyUsageFlags.KeyEncipherment,
                false));

        var oidCollection = new OidCollection {
            new("1.3.6.1.5.5.7.3.2")
        };

        certificateRequest.CertificateExtensions.Add(
            new CpX509EnhancedKeyUsageExtension(
                oidCollection,
                true));

        var cert = certificateRequest.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

        var file = cert.Export(X509ContentType.Pfx, new SecureString());
        var certificate = new CpX509Certificate2(file);
        using var store = new CpX509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        store.Add(certificate);
        return certificate;
    }
}