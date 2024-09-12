using CryptoPro.Security.Cryptography.X509Certificates;

namespace SignTestApp;

internal interface ICryptoService
{
    /// <summary>
    /// Запросить доступные сертификаты
    /// </summary>
    /// <returns><see langword="CpX509Certificate2"/>  - последний доступный сертификат></returns>
    /// <exception cref="CryptoProNotFoundException"></exception>
    /// <exception cref="CryptoProLicenseMissingException"></exception>
    CpX509Certificate2? GetCert(string? email);
    
    CpX509Certificate2? CreateCert(string cn,string? email);

    CpX509Certificate2? GenerateCertificate();
}

internal abstract class CryptoProException : Exception
{
    // TODO
}

internal class CryptoProNotFoundException : CryptoProException
{
    // TODO
}

internal class CryptoProLicenseMissingException : CryptoProException
{
    // TODO
}