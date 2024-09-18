namespace SignTestApp;

internal class CryptoProVersion
{
    private byte MajorVersion { get; init; }
    private byte MinorVersion { get; init; }

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