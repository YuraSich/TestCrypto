using CryptoPro.Security.Cryptography.X509Certificates;

namespace SignTestApp;

internal interface ICryptoProService
{
    CpX509Certificate2? GetCert(string email);
    CpX509Certificate2? GetDefaultCert(string thumbprint);

    CpX509Certificate2 GenerateCertificate(string cn, string email);

    byte[] Sign(byte[] bytesToHash, CpX509Certificate2 cert);

    /// <summary>
    /// Зашифровываем сообщение, используя открытый ключ получателя, при помощи класса EnvelopedCms.
    /// </summary>
    /// <param name="msgBytes">Сообщение</param>
    /// <param name="cert">Сертификат получателя</param>
    /// <returns>Зашифрованное сообщение</returns>
    ReadOnlySpan<byte> Encrypt(byte[] msgBytes, CpX509Certificate2 cert);

    /// <summary>
    /// Расшифрование закодированного EnvelopedCms сообщения.
    /// </summary>
    /// <param name="msgBytes">Закодированное сообщение.</param>
    /// <param name="cert">Сертификат</param>
    /// <returns>Раскодированное сообщение</returns>
    ReadOnlySpan<byte> Decrypt(ReadOnlySpan<byte> msgBytes, CpX509Certificate2 cert);

    bool IsCryptoProLicenseValid();
    
    CryptoProVersion? GetCryptoProInstalledVersion();
}