using CryptoPro.Security.Cryptography.X509Certificates;
using Microsoft.VisualBasic.CompilerServices;

namespace SignTestApp;

internal interface ICryptoService
{
    /// <summary>
    /// Запросить доступные сертификаты
    /// </summary>
    /// <returns><see langword="CpX509Certificate2"/>  - последний доступный сертификат></returns>
    /// <exception cref="CryptoProNotFoundException"></exception>
    /// <exception cref="CryptoProObsoleteException"></exception>
    /// <exception cref="CryptoProLicenseMissingException"></exception>
    CpX509Certificate2? GetCert(string? email);

    CpX509Certificate2? CreateCert(string cn, string? email);

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

internal class CryptoProObsoleteException : CryptoProException
{
    public CryptoProVersion Expected { get; init; }
    public CryptoProVersion Actual { get; init; }
    public CryptoProObsoleteException(CryptoProVersion expected, CryptoProVersion actual)
    {
        Expected = expected;
        Actual = actual;
    }

    public override string ToString()
    {
        return $"Minimal supported version {Expected}, but found {Actual}";
    }
}

internal class CryptoProLicenseMissingException : CryptoProException
{
    // TODO
}

internal class CryptoProVersion
{
    public byte MajorVersion { get; init; }
    public byte MinorVersion { get; init; }

    public CryptoProVersion(byte major, byte minor)
    {
        MajorVersion = major;
        MinorVersion = minor;
    }

    public override string ToString()
    {
        return $"{MajorVersion}.{MinorVersion}";
    }

    public static bool operator <(CryptoProVersion a, CryptoProVersion b) => a.MajorVersion < b.MajorVersion || (a.MajorVersion == b.MajorVersion && a.MinorVersion < b.MinorVersion);
    public static bool operator >(CryptoProVersion a, CryptoProVersion b) => a.MajorVersion > b.MajorVersion || (a.MajorVersion == b.MajorVersion && a.MinorVersion > b.MinorVersion);

}