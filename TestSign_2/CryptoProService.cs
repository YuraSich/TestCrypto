using CryptoPro.Security.Cryptography;
using CryptoPro.Security.Cryptography.Pkcs;
using CryptoPro.Security.Cryptography.X509Certificates;
using CryptoPro.Security.Cryptography.Xml;
using SignTestApp;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace CryptoModuleTest;

internal class CryptoProService
{
    private const int CRYPT_VERIFYCONTEXT = -268435456; //No private key access required

    private const string Postfix = "_SberIRM";

    private static readonly CryptoProVersion MinimalSupportedVersion = new(5, 0);

    public CpX509Certificate2? GetCert(string email)
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

    /// <summary>
    /// Формирование ключа шифрования и подписи.
    /// ??? Функция CryptGenKey генерирует случайные криптографические ключи или ключевую пару(закрытый/открытый ключи). 
    /// Полученный дескриптор ключа должен в обязательном порядке быть удалён
    /// с помощью вызова функции CryptDestroyKey до вызова функции CryptReleaseContext для рабочего дескриптора криптопровайдера.
    /// 
    /// + Криптопровайдер - Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider;
    /// + Алгоритм генерации ключа - ГОСТ 34.10-2012 256 бит;
    /// Назначение ключа - Подпись и шифрование;
    /// Параметры экспорта - Не экспортируемые;
    /// + Способы использования ключа - Подпись(digitalSignature) Шифрование(dataEncryption), Согласование(keyAgreement);
    /// + Назначение сертификата - Проверка подлинности клиента.
    /// ? Срок действия открытого ключа - 1 год.
    /// ? Срок действия закрытого ключа - 4 года.
    /// </summary>
    public CpX509Certificate2 GenerateCertificate(string cn, string email)
    {
        using var gost3410 = Gost3410_2012_256.Create();

        var builder = new X500DistinguishedNameBuilder();
        builder.AddCommonName(cn + Postfix);
        builder.AddEmailAddress(email);
        var distinguishedName = builder.Build();

        var certificateRequest = new CpCertificateRequest(distinguishedName.Name, gost3410);

        const X509KeyUsageFlags usageFlags = X509KeyUsageFlags.DigitalSignature |
                                             X509KeyUsageFlags.DataEncipherment |
                                             X509KeyUsageFlags.KeyAgreement;

        certificateRequest.CertificateExtensions.Add(new CpX509KeyUsageExtension(usageFlags, false));

        certificateRequest.CertificateExtensions.Add(new CpX509BasicConstraintsExtension());

        var oidCollection = new OidCollection {
            new("1.3.6.1.5.5.7.3.2") //Проверка подлинности клиента (1.3.6.1.5.5.7.3.2)
        };

        certificateRequest.CertificateExtensions.Add(new CpX509EnhancedKeyUsageExtension(oidCollection, true));

        var cert = certificateRequest.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

        using (var store = new CpX509Store(StoreName.My, StoreLocation.CurrentUser))
        {
            store.Open(OpenFlags.ReadWrite);
            store.Add(cert);
        }

        return cert;
    }

    public void EnvelopedCmsGost2012_256(CpX509Certificate2 cert)
    {
        // Исходное сообщение.
        const string msg = "Это сообщение, которое будет зашифровано.";

        Console.WriteLine("{0}Исходное сообщение (длина {1}): {2}  ", Environment.NewLine, msg.Length, msg);

        // Переводим исходное сообщение в массив байтов.
        var encoding = new UTF8Encoding();
        var msgBytes = encoding.GetBytes(msg);

        Console.WriteLine("{0}{0}------------------------------", Environment.NewLine);
        Console.WriteLine(" На стороне отправителя");
        Console.WriteLine("------------------------------{0}", Environment.NewLine);

        var encodedEnvelopedCms = EncryptMsg(msgBytes, cert, true);

        Console.WriteLine("{0}Сообщение после зашифрования (длина {1}):  ", Environment.NewLine, encodedEnvelopedCms.Length);
        foreach (var b in encodedEnvelopedCms)
        {
            Console.Write("{0:x}", b);
        }

        File.WriteAllBytes("encrypted.txt.p7e", encodedEnvelopedCms);
        Console.WriteLine();

        Console.WriteLine("{0}{0}------------------------------", Environment.NewLine);
        Console.WriteLine(" На стороне получателя  ");
        Console.WriteLine("------------------------------{0}", Environment.NewLine);

        // Расшифровываем сообщение для одного из получателей
        // и возвращаем сообщение для отображения.
        var decryptedMsg = DecryptMsg(encodedEnvelopedCms, cert);

        File.WriteAllText("decrypted.txt", encoding.GetString(decryptedMsg));
        // Преобразуем расшифрованные байты в сообщение
        Console.WriteLine("{0}Расшифрованное сообщение: {1}", Environment.NewLine, encoding.GetString(decryptedMsg));


        // Зашифровываем сообщение, используя открытый ключ 
        // получателя, при помощи класса EnvelopedCms.
        static byte[] EncryptMsg(byte[] msg, CpX509Certificate2 recipientCert, bool useDataContextType)
        {
            // Помещаем сообщение в объект ContentInfo 
            // Это требуется для создания объекта EnvelopedCms.
            var contentInfo = useDataContextType ?
                new ContentInfo(new Oid("1.2.840.113549.1.7.1"), msg) :
                new ContentInfo(ContentInfo.GetContentType(msg), msg);

            // Создаем объект EnvelopedCms, передавая ему
            // только что созданный объект ContentInfo.
            // Используем идентификацию получателя (SubjectIdentifierType)
            // по умолчанию (IssuerAndSerialNumber).
            // При необходимости использовать другой алгоритм шифрования данных
            // (отличный от 28147-89 по умолчанию), его AlgorithmIdentifier можно передать вторым параметром.
            // Например для id-tc26-cipher-gostr3412-2015-magma-ctracpkm (oid: 1.2.643.7.1.1.5.1.1):
            // CpEnvelopedCms envelopedCms = new CpEnvelopedCms(
            //    contentInfo, 
            //    new AlgorithmIdentifier(new Oid("1.2.643.7.1.1.5.1.1")));
            var envelopedCms = new CpEnvelopedCms(contentInfo);

            // Создаем объект CmsRecipient, который 
            // идентифицирует получателя зашифрованного сообщения.
            var recip1 = new CpCmsRecipient(SubjectIdentifierType.IssuerAndSerialNumber, recipientCert);

            Console.Write("Зашифровываем данные для одного получателя с именем {0} ...", recip1.Certificate.SubjectName.Name);
            // Зашифровываем сообщение.
            envelopedCms.Encrypt(recip1);
            Console.WriteLine("Выполнено.");

            // Закодированное EnvelopedCms сообщение содержит
            // зашифрованный текст сообщения и информацию
            // о каждом получателе данного сообщения.
            return envelopedCms.Encode();
        }

        // Расшифрование закодированного EnvelopedCms сообщения.
        static byte[] DecryptMsg(byte[] encodedEnvelopedCms, CpX509Certificate2 cert)
        {
            // Создаем объект для декодирования и расшифрования.
            var envelopedCms = new CpEnvelopedCms();

            // Декодируем сообщение.
            envelopedCms.Decode(encodedEnvelopedCms);

            // Выводим количество получателей сообщения и алгоритм зашифрования.
            DisplayEnvelopedCms(envelopedCms, false);

            // Расшифровываем сообщение для получателя.
            Console.Write("Расшифрование ... ");
            envelopedCms.Decrypt(new CpX509Certificate2Collection(cert));
            Console.WriteLine("Выполнено.");

            // После вызова метода Decrypt в свойстве ContentInfo 
            // содержится расшифрованное сообщение.
            return envelopedCms.ContentInfo.Content;
        }

        // Отображаем свойство ContentInfo объекта EnvelopedCms 
        static void DisplayEnvelopedCmsContent(string desc, CpEnvelopedCms envelopedCms)
        {
            Console.WriteLine(desc + " (длина {0}):  ", envelopedCms.ContentInfo.Content.Length);
            foreach (var b in envelopedCms.ContentInfo.Content)
            {
                Console.Write(b + " ");
            }
            Console.WriteLine();
        }

        // Отображаем некоторые свойства объекта EnvelopedCms.
        static void DisplayEnvelopedCms(CpEnvelopedCms e, bool displayContent)
        {
            Console.WriteLine("{0}Закодированное CMS/PKCS #7 Сообщение.{0}" + "Информация:", Environment.NewLine);
            Console.WriteLine("\tАлгоритм шифрования сообщения:{0}", e.ContentEncryptionAlgorithm.Oid.FriendlyName);
            Console.WriteLine("\tКоличество получателей закодированного CMS/PKCS #7 сообщения:{0}", e.RecipientInfos.Count);
            for (var i = 0; i < e.RecipientInfos.Count; i++)
            {
                Console.WriteLine(
                    "\tПолучатель #{0} тип {1}.",
                    i + 1,
                    e.RecipientInfos[i].RecipientIdentifier.Type);
            }
            if (displayContent)
            {
                DisplayEnvelopedCmsContent("Закодированное CMS/PKCS #7 содержимое", e);
            }
            Console.WriteLine();
        }
    }

    public byte[] Sign(byte[] bytesToHash, CpX509Certificate2 cert)
    {
        var contentInfo = new ContentInfo(bytesToHash);
        var signedCms = new CpSignedCms(contentInfo, true);
        var cmsSigner = new CpCmsSigner(cert);

        signedCms.ComputeSignature(cmsSigner);
        return signedCms.Encode();
    }


    public byte[] Encrypt(byte[] msgBytes, CpX509Certificate2 cert)
    {
        var contentInfo = new ContentInfo(new Oid("1.2.840.113549.1.7.1"), msgBytes);

        // https://tc26.ru/about/protsedury-i-reglamenty/identifikatory-obektov-oid-tekhnicheskogo-komiteta-po-standartizatsii-kriptograficheskaya-zashchita-1.html
        // OID - 1.2.643.7.1.1.5.2 - алгоритм шифрования «Кузнечик»
        var envelopedCms = new CpEnvelopedCms(contentInfo);
        var recipient = new CpCmsRecipient(SubjectIdentifierType.IssuerAndSerialNumber, cert);
        envelopedCms.Encrypt(recipient);
        return envelopedCms.Encode();
    }

    public byte[] Decrypt(byte[] msgBytes, CpX509Certificate2 cert)
    {
        var envelopedCms = new CpEnvelopedCms();
        
        envelopedCms.Decode(msgBytes);
        
        envelopedCms.Decrypt(new CpX509Certificate2Collection(cert));
        return envelopedCms.ContentInfo.Content;
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


    /// <summary>
    /// Расшифрование на сертификате
    /// </summary>
    /// <param name="gostKey"></param>
    static void Decrypt(string srcName, string destName, CpX509Certificate2 cert)
    {
        // Создаем новый объект xml документа.
        var xmlDoc = new XmlDocument();

        // Пробельные символы участвуют в вычислении подписи и должны быть сохранены для совместимости с другими реализациями
        xmlDoc.PreserveWhitespace = true;

        // Загружаем в объект созданный XML документ.
        xmlDoc.Load(srcName);

        // Создаем новый объект CpEncryptedXml по XML документу.
        var exml = new CpEncryptedXml(xmlDoc);

        // Небольшие хаки, чтобы не устанавливать серт в хранилище
        {
            var ns = new XmlNamespaceManager(xmlDoc.NameTable);
            ns.AddNamespace("ki", "http://www.w3.org/2000/09/xmldsig#");
            ns.AddNamespace("ek", "http://www.w3.org/2001/04/xmlenc#");
            var keyName = Convert.ToBase64String(cert.Export(X509ContentType.Cert));
            var keyInfoNode = xmlDoc.SelectSingleNode("//ki:KeyInfo/ek:EncryptedKey/ki:KeyInfo", ns);
            if (keyInfoNode == null)
            {
                throw new InvalidOperationException("Неверный формат зашифрованного XML-документа.");
            }

            if (keyInfoNode.InnerText.Equals(keyName, StringComparison.InvariantCultureIgnoreCase))
            {
                keyInfoNode.InnerXml = $"<KeyName>{keyName}</KeyName>";
            }
            exml.AddKeyNameMapping(keyName, cert.PrivateKey);
            exml.Recipient = keyName;
        }

        // Расшифровываем зашифрованные узлы XML документа.
        exml.DecryptDocument();

        // Сохраняем расшифрованный документ.
        xmlDoc.Save(destName);
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