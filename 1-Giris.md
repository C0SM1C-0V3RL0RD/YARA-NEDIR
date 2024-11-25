Kötü amaçlı yazılım tespiti hakkında konuşurken, bir dosyanın zararlı olup olmadığını belirlemenin üç ana yöntemi vardır:
             1- imza tabanlı, 
             2- sezgisel,
             3- metin dizisi imzası tabanlı 
yöntemler olarak ayırabiliriz.
######
İMZA TABANLI
######
Antivirüs tespit sistemlerinde en yaygın kullanılan yöntem imza tabanlı tespittir. Bu yöntemde, bir dosyanın HASH değeri alınır, bir imza veritabanıyla karşılaştırılır ve bu dosyanın daha önce kötü amaçlı yazılım olarak tespit edilip edilmediği kontrol edilir. Ancak bu tür bir imza, bilinmeyen kötü amaçlı yazılımların tespiti için etkisizdir. Bu sistemi atlatmak için kodu farklı bir sistemde yeniden derlemek veya sadece bir bitlik değişiklik yapmak yeterlidir. Örnek olarak bu anlatılan aşağıda değinilmiştir:

#Temel olarak elimizde bir zararli.exe adında bir executable dosya olduğunu varsayalım.Bu executable dosyanın hash imzasının ise "5d41402abc4b2a6b9519h911012c592" olduğunu varsayalım.Antivirüs sistemi veritabanından bu zararlı dosyanın hash imzasını karşılaştırır ve bu imza sunucu tarafında eşleşirse zararlı yazılım engellenir.Sistemi atlatmak için:

                    1- Farklı bir sistemde tekrar derlemek,
                    2- Bir bitlik değişiklik yapmak,

işlemleri uygulanabilir.

## 
1- FARKLI BİR SİSTEMDE TEKRAR DERLEME YAPMAK:

    zararlı yazılımın kaynak koduna hiç dokunulmadan aynı kodu başka bir bilgisayarda veya başka bir derleyici ile derlenirse, ortaya çıkan HASH değeri farklı olacaktır.

    Başlangıçta HASH değeri "5d41402abc4b2a6b9519h911012c592" olan zararlı yazılımı başka bir sistemde tekrar derlediğimiz zaman yeni HASH değeri "z335a08721y73458o671t6016e362m4" şeklini alır.Antivirüs database tarafında yeni oluşturulan bu HASH bilgisini eşitleyemediği için dosyayı zararlı olarak tespit edemez.

##
2- BİR BİTLİK DEĞİŞİKLİK YAPMAK(BIT FLIP):

    binary seviyesinde, dosyada önemsiz bir değişiklik yapmak da HASH'i tamamen değiştirebilir.
    örnek olarak dosyanın sonunda bir boşluk karakteri veya gereksiz bir byte eklenirse HASH değeri değişecektir.

    5A 41 59 4F 54 45 4D  --> Orjinal hex kodu "ZAYOTEM"
    5A 41 59 4F 54 45 4D 20 --> Sonuna bir boşluk eklendi. "ZAYOTEM "
    5A 41 59 4F 54 45 4D FF --> Sonuna eklenen anlamsız bir byte "ZAYOTEMÿ"

    Bu işlemin sonucu olarak dosyanın HASH bilgileri değişmektedir.

## 
3- KOD ŞİFRELEME(CODE ENCRYPTION)

    zararlı yazılımın kodu, çalıştırılmadan önce şifrelenmiş bir formatta saklar çalıştırılma sırasında kod kendini çözerek bellekte çalışır.

    Bu yöntem, HASH tabanlı tespiti atlatabilir bunun nedeni dosyanın şifrelenmiş hali antivirüs sunucularındaki imzadan farklı olacaktır. Örnek olarak;

    char encoded_payload[] = { 0x23, 0x44, 0x56 }; // XOR ile şifrelenmiş
    char key = 0xAA;

    for (int i = 0; i < sizeof(encoded_payload); i++) {
        encoded_payload[i] ^= key; // Bellekte şifre çözülür
    }


##
4- DOSYA PAKETLEME (UPX İŞLEMİ ÜZERİNDEN ANLATIM)

    upx -9 malware.exe


######
2-SEZGİSEL YAKLAŞIM (Heuristic Method)
######

Sezgisel Yaklaşım, kötü amaçlı yazılımların davranışlarını ve özelliklerini analiz ederek bir dosyanın kötü amaçlı olup olmadığını belirlemeye çalışır. Sezgisel analiz, dosyanın bilinen kötü amaçlı yazılım imzalarına sahip olup olmadığına bakmaksızın, şüpheli davranışlar ya da gizli kodlar arar Temel Prensipleri:

            1- Davranış temelli prensip,
            2- Özellik analizi,
            3- İzleme ve karar verme

##
1- Davranış temelli prensip

    zararlı yazılım dosyasının içerdiği kodun davranışlarını gözlemler.Örnek olarak

            * Sistem Dosyalarına yetksizi erişim yapılıyor mu?
            * Bellek üzerinde şüpheli erişim yapılıyor mu?
            * Ağa bağlanmaya çalışıyor mu?

##
2- Özellik Analizi

    bu yöntem, kötü amaçlı yazılımların tipik özelliklerine dayalı olarak şüpheli aktiviteleri tespit etmeye çalışır.

            * Şifreleme tekniklerinin varlığı,
            * Belirli API çağrıları,
##

--Sezgisel yöntemin avantajları--
1- Zararlı yazılımın imza bilgisi veritabanında olmasa bile zararlı yazılımın davranışına bakılarak şüpheli aktivite hakkında bilgi edinilebilir.
2- Zararlı yazılım içeriği değişse bile sezgisel analiz bu değişmiş versiyonları bile tespit edebilir çünkü davranışlar genellikle aynı olmaktadır.

######
3- METİN DİZİSİ İMZASI TABANLI
######

Metin dizisi imzası tabanlı tespit bulunmaktadır. Bu yöntem, yukarıda bahsedilenlerden farklı bir tür imza kullanır. HASH imzaları yerine, kötü amaçlı yazılım örneğini benzersiz şekilde tanımlayan metin veya ikili diziler kullanır. Bu şekilde, dosya değiştirilmiş olsa bile, eğer bu metin dizisi imzalarını hâlâ içeriyorsa, analistler kötü amaçlı yazılım örneğini tespit edip sınıflandırabilir.

            * Kötü amaçlı yazılımın işlevsel özelliklerini (örneğin, şifreleme anahtarları, zararlı komutlar) içerir.
            * API çağrıları, dosya yolları, veritabanı sorguları gibi belirli komutlar ya da veriler olabilir.
            * Bu diziler zararlı yazılımın kimliğini benzersiz bir şekilde tanımlar.

1- Dizi Tabanlı Tanımlama:
    Bu yöntemde, kötü amaçlı yazılımlar belirli metin dizileri veya ikili diziler içerir. Bu diziler, genellikle:

    Kötü amaçlı yazılımın işlevsel özelliklerini (örneğin, şifreleme anahtarları, zararlı komutlar) içerir.
    API çağrıları, dosya yolları, veritabanı sorguları gibi belirli komutlar ya da veriler olabilir.
    Bu diziler zararlı yazılımın kimliğini benzersiz bir şekilde tanımlar.

2- Dizilerin Tanımlanması ve Kullanımı:

    Yazılım analiz araçları, zararlı yazılımlar içinde bulunan belirli metin dizilerini (string) tespit edebilir. Bu diziler, zararlı yazılımın karakteristik işlevlerinin izlerini taşır. Örneğin:

    Kötü amaçlı yazılım, bir şifreleme algoritması kullanıyorsa, bu algoritmanın adı ya da bir şifreleme anahtarı dizisi metin dizisi imzası olabilir.
    Dosyanın içeriğinde belirli API fonksiyonlarına veya belirli bir veritabanı bağlantı yoluna dair diziler de olabilir.

3-FARKLAR

Hash Tabanlı İmza: Dosyanın tam bir "parmak izi"ni alır. Dosya değişirse, hash değeri değişir ve bu tür değişiklikler hash tespiti için başarısızlığa yol açar.

Metin Dizisi İmzası: Dosyanın içeriğinde belirli dizileri arar. Bu diziler, dosyanın içeriğinde değişiklik olsa da hala var olabilir. Bu, daha dayanıklı bir tespit yöntemidir çünkü zararlı yazılım, her zaman belirli işlevleri (örn. şifreleme, anahtar kullanımı) aynı şekilde uygular.