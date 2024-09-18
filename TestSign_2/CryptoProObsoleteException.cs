namespace SignTestApp;

internal class CryptoProObsoleteException : CryptoProException
{
    private CryptoProVersion Expected { get; init; }
    private CryptoProVersion Actual { get; init; }
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