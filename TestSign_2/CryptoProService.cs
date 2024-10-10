using CryptoPro.Security.Cryptography;
using CryptoPro.Security.Cryptography.Pkcs;
using CryptoPro.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace SignTestApp;

internal class CryptoProService : ICryptoProService
{
    private const int CRYPT_VERIFYCONTEXT = -268435456; //No private key access required

    private const string Postfix = "_SberIRM";

    private static readonly CryptoProVersion MinimalSupportedVersion = new(5, 0);

    public CpX509Certificate2? GetCert(string email)
    {
        //var cryptoProVersion = GetCryptoProInstalledVersion();
        //if (cryptoProVersion == null)
        //{
        //    throw new CryptoProNotFoundException();
        //}

        //if (cryptoProVersion < MinimalSupportedVersion)
        //{
        //    throw new CryptoProObsoleteException(MinimalSupportedVersion, cryptoProVersion);
        //}

        //if (!IsCryptoProLicenseValid())
        //{
        //    throw new CryptoProLicenseMissingException();
        //}

        using var store = new CpX509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);

        var certCollection = store.Certificates;
        var currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
        var irmCertificates = currentCerts.Where(x => CheckEmail(x, email) && CheckCn(x)).ToArray();
        return irmCertificates.MaxBy(x => x.NotAfter);
    }

    /// <summary>
    /// Формирование ключа шифрования и подписи.
    /// </summary>
    public CpX509Certificate2 GenerateCertificate(string cn, string email)
    {
        using var cryptoServiceProvider = new Gost3410_2012_256CryptoServiceProvider();
        var builder = new X500DistinguishedNameBuilder();
        builder.AddCommonName(cn + Postfix);
        builder.AddEmailAddress(email);
        var distinguishedName = builder.Build();

        var request = new CpCertificateRequest(distinguishedName.Name, cryptoServiceProvider);

        request.CertificateExtensions.Add(new CpX509BasicConstraintsExtension(true, false, 0, true));

        request.CertificateExtensions.Add(new CpX509SubjectKeyIdentifierExtension(request.PublicKey, true));

        using var parentCert = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));
        var certData = parentCert.Export(X509ContentType.Pfx, string.Empty);
        var cert = new CpX509Certificate2(certData);
        using var store = new CpX509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        store.Add(cert);
        return cert;
    }

    public CpX509Certificate2 GenerateRootCertificate(string cn)
    {
        using var cryptoServiceProvider = new Gost3410_2012_256CryptoServiceProvider();
        var builder = new X500DistinguishedNameBuilder();
        builder.AddCommonName(cn);
        var distinguishedName = builder.Build();

        var request = new CpCertificateRequest(distinguishedName.Name, cryptoServiceProvider);
        request.CertificateExtensions.Add(new CpX509BasicConstraintsExtension(true, false, 0, true)); // Указываем, что это сертификат ЦС
        request.CertificateExtensions.Add(new CpX509SubjectKeyIdentifierExtension(request.PublicKey, true));

        // Создание самоподписанного сертификата для УЦ
        using var rootCert = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(5)); // Срок действия можно задать больше
        var certData = rootCert.Export(X509ContentType.Pfx, "your-secure-password");
        var cert = new CpX509Certificate2(certData);

        // Добавляем корневой сертификат в хранилище
        using var store = new CpX509Store(StoreName.Root, StoreLocation.CurrentUser); // Корневые сертификаты хранятся в хранилище "Root"
        store.Open(OpenFlags.ReadWrite);
        store.Add(cert);

        return cert;
    }

    public CpX509Certificate2 GenerateSignedCertificate(CpX509Certificate2 caCert, string cn, string email)
    {
        using var cryptoServiceProvider = new Gost3410_2012_256CryptoServiceProvider();
        var builder = new X500DistinguishedNameBuilder();
        builder.AddCommonName(cn);
        builder.AddEmailAddress(email);
        var distinguishedName = builder.Build();

        var request = new CpCertificateRequest(distinguishedName.Name, cryptoServiceProvider);
        request.CertificateExtensions.Add(new CpX509BasicConstraintsExtension(false, false, 0, true)); // Обычный сертификат, не ЦС
        request.CertificateExtensions.Add(new CpX509SubjectKeyIdentifierExtension(request.PublicKey, true));

        // Подписываем сертификат с помощью УЦ
        using var signedCert = request.Create(caCert, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1), Guid.NewGuid().ToByteArray());
        var certData = signedCert.Export(X509ContentType.Pfx, "your-secure-password");
        var cert = new CpX509Certificate2(certData);

        // Добавляем сертификат в хранилище
        using var store = new CpX509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        store.Add(cert);

        return cert;
    }


    public byte[] Sign(byte[] bytesToHash, CpX509Certificate2 cert)
    {
        var contentInfo = new ContentInfo(bytesToHash);
        var signedCms = new CpSignedCms(contentInfo, true);
        var cmsSigner = new CpCmsSigner(cert);

        signedCms.ComputeSignature(cmsSigner);
        return signedCms.Encode();
    }

    /// <summary>
    /// Зашифровываем сообщение, используя открытый ключ получателя, при помощи класса EnvelopedCms.
    /// </summary>
    /// <param name="msgBytes">Сообщение</param>
    /// <param name="cert">Сертификат получателя</param>
    /// <returns>Зашифрованное сообщение</returns>
    public byte[] Encrypt(byte[] msgBytes, CpX509Certificate2 cert)
    {
        var contentInfo = new ContentInfo(new Oid("1.2.840.113549.1.7.1"), msgBytes);

        // https://tc26.ru/about/protsedury-i-reglamenty/identifikatory-obektov-oid-tekhnicheskogo-komiteta-po-standartizatsii-kriptograficheskaya-zashchita-1.html
        // OID - 1.2.643.7.1.1.5.2 - алгоритм шифрования «Кузнечик»
        var envelopedCms = new CpEnvelopedCms(contentInfo, new AlgorithmIdentifier(new Oid("1.2.643.7.1.1.5.2")));
        var recipient = new CpCmsRecipient(SubjectIdentifierType.IssuerAndSerialNumber, cert);
        envelopedCms.Encrypt(recipient);
        return envelopedCms.Encode();
    }

    /// <summary>
    /// Расшифрование закодированного EnvelopedCms сообщения.
    /// </summary>
    /// <param name="msgBytes">Закодированное сообщение.</param>
    /// <param name="cert">Сертификат</param>
    /// <returns>Раскодированное сообщение</returns>
    public byte[] Decrypt(ReadOnlySpan<byte> msgBytes, CpX509Certificate2 cert)
    {
        var envelopedCms = new CpEnvelopedCms();
        envelopedCms.Decode(msgBytes);
        envelopedCms.Decrypt(new CpX509Certificate2Collection(cert));
        return envelopedCms.ContentInfo.Content;
    }

    #region private methods

    public bool IsCryptoProLicenseValid()
    {
        // TODO
        return true;
    }

    public CryptoProVersion? GetCryptoProInstalledVersion()
    {
        var dProvider = new nint();
        var version = new byte[4];
        var contextAcquiredSuccessfully = CryptAcquireContext(
            ref dProvider, // дескриптор CSP
            null, // имя контейнера
            null, // использовать поставщика по умолчанию
            75, // тип поставщика
            CRYPT_VERIFYCONTEXT); // значения флагов

        if (contextAcquiredSuccessfully)
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


    /// <summary>
    /// Попытаться получить контекст и контейнер ключей.
    /// Контекст будет использовать CSP по умолчанию для типа поставщика RSA_FULL.
    /// DwFlags устанавливается в ноль для попытки открыть существующий контейнер ключей.
    /// </summary>
    /// <param name="hProv"></param>
    /// <param name="pszContainer"></param>
    /// <param name="pszProvider"></param>
    /// <param name="dwProvType"></param>
    /// <param name="dwFlags"></param>
    /// <returns></returns>
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptAcquireContext(
        ref nint hProv,
        string pszContainer,
        string pszProvider,
        int dwProvType,
        int dwFlags
    );

    #endregion
}