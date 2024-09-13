using System.Runtime.InteropServices;
using CryptoPro.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.X509Certificates;

namespace SignTestApp;

internal class CryptoProService : ICryptoService
{
    private const int CRYPT_VERIFYCONTEXT = -268435456; //No private key access required

    private const string Postfix = "_SberIRM";

    private static readonly CryptoProVersion MinimalSupportedVersion = new(5, 0);

    public CpX509Certificate2? GetCert(string? email)
    {
        var cryptoProVersion = GetCryptoProInstalledVersion();
        if (cryptoProVersion == null)
        {
            throw new CryptoProNotFoundException();
        }

        if (cryptoProVersion < MinimalSupportedVersion)
        {
            throw new CryptoProObsoleteException(MinimalSupportedVersion, cryptoProVersion);
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

    public CpX509Certificate2? CreateCert(string cn, string? email)
    {
        throw new NotImplementedException();
    }


    public CpX509Certificate2? GenerateCertificate()
    {
        throw new NotImplementedException();
    }

    #region private methods

    private bool IsCryptoProLicenseValid()
    {
        // TODO
        return true;
    }

    private CryptoProVersion? GetCryptoProInstalledVersion()
    {
        var dProvider = new nint();
        var version = new byte[4];
        if (CryptAcquireContext(ref dProvider, null, null, 75, CRYPT_VERIFYCONTEXT))
        {
            uint ll = 4;
            if (CryptGetProvParam(dProvider, 5, version, ref ll, 0))
            {
                return new CryptoProVersion(version[1], version[0]);
            }
        }

        return null;
    }

    private bool CheckEmail(CpX509Certificate2 cert, string? email) => cert.ExtractEmail()?.Equals(email, StringComparison.OrdinalIgnoreCase) ?? false;

    private bool CheckCn(CpX509Certificate2 cert) => cert.ExtractCommonName()?.EndsWith(Postfix, StringComparison.OrdinalIgnoreCase) ?? false;


    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CryptGetProvParam(
        nint hProv,
        uint dwParam,
        [In, Out] byte[] pbData,
        ref uint dwDataLen,
        uint dwFlags);

    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool CryptAcquireContext(
        ref nint hProv,
        string pszContainer,
        string pszProvider,
        int dwProvType,
        int dwFlags
    );

    #endregion
}