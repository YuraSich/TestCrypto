using CryptoPro.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.X509Certificates;

namespace SignTestApp;

internal class CryptoProService : ICryptoService
{
    private string Postfix { get; init; } = "_SberIRM";

    public CpX509Certificate2? GetCert(string? email)
    {
        if (!CryptoProInstalled())
        {
            throw new CryptoProNotFoundException();
        }

        if (!IsCryptoProLicenseValid())
        {
            throw new CryptoProLicenseMissingException();
        }

        using var store = new CpX509Store(StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);

        var certCollection = store.Certificates;
        var currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
        var irmCertificates = currentCerts.Where(x => CheckEmail(x, email) && CheckCn(x)).ToArray();
        return irmCertificates.MaxBy(x => x.NotAfter);
    }


    public CpX509Certificate2? GenerateCertificate()
    {
        throw new NotImplementedException();
    }

    #region private methods

    private bool IsCryptoProLicenseValid()
    {
        //TODO
        return true;
    }

    private bool CryptoProInstalled()
    {
        //TODO
        return true;
    }

    private bool CheckEmail(CpX509Certificate2 cert, string? email) => cert.ExtractEmail()?.Equals(email, StringComparison.OrdinalIgnoreCase) ?? false;

    private bool CheckCn(CpX509Certificate2 cert) => cert.ExtractCommonName()?.EndsWith(Postfix, StringComparison.OrdinalIgnoreCase) ?? false;

    #endregion
}