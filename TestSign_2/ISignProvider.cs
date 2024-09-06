namespace TestSign_2;

internal interface ISignProvider
{
    void Sign(string inputFilePath, string signedFilePath, string certificateCn, bool detached);
}