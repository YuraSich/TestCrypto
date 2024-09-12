using CryptoPro.Security.Cryptography.X509Certificates;

namespace SignTestApp;

internal static class CpX509Certificate2Extension
{
    private const string CnPrefix = "CN=";
    private const string EmailPrefix = "E=";

    public static string? ExtractCommonName(this CpX509Certificate2 certificate) => Extract(certificate, CnPrefix);

    public static string? ExtractEmail(this CpX509Certificate2 certificate) => Extract(certificate, EmailPrefix);

    private static string? Extract(CpX509Certificate certificate, string prefix)
    {
        var subject = certificate.Subject;
        var subjectParts = subject.Split(',');

        var part = subjectParts.FirstOrDefault(x => x.Trim().StartsWith(prefix));
        return part?.Trim()[prefix.Length..];
    }
}