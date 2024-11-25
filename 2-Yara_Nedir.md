####
YARA NEDİR?
####
    YARA, "Yet Another Recursive Acronym" (Yine Bir Diğer Rekürsif Akronim) anlamına gelen bir terimdir ve açık kaynaklı, kural tabanlı bir desen eşleştirme aracıdır. Başta kötü amaçlı yazılım araştırmalarında kullanılan YARA, metinsel veya ikili desenlere dayalı olarak kötü amaçlı yazılım ailelerini tanımlamak ve sınıflandırmak için kullanılır. YARA, kullanıcıların özel kurallar oluşturmasına olanak tanır. Bu kurallar, bir dizi dize ve mantıksal ifadeden oluşur ve belirli tehditleri hızlıca tespit etmek için büyük veri kümelerini tarar. Esnek yapısı sayesinde, araştırmacılar farklı kötü amaçlı yazılım türlerini veya diğer tehditleri tanımlamak için YARA kurallarını özelleştirebilirler. Bu, YARA'nın güçlü ve verimli bir araç olmasını sağlar.

####
YARA UYGULAMASININ İNDİRİLMESİ
####

Yara github üzerinden indirilebilir indirme linki: https://github.com/virustotal/yara/releases
#
Windows
#
 >> yara-v4.5.2-2326-win32.zip 
        or
 >> yara-v4.5.2-2326-win64.zip
 * Windows sistemde gerekirse ortam değişkenlerine eklenebilir.
#
Linux
#
 >> git clone https://github.com/VirusTotal/yara.git
 >> ./bootstrap.sh
 >> ./configure
 >>  make
 >> sudo make install
 >> yara --version

###
YARA SÖZDİZİMİ
###

Yara kuralları .yar uzantısına sahip dosyalarda yazılır.YARA kuralı tespit açısından birkaç bölümden oluşur.Bunlar:

    1- MetaVeri Bölümü,
    2- Strings Bölümü,
    3- Condition Bölümü,

1- METAVERİ BÖLÜMÜ:

    Yazılacak YARA kuralı hakkında açıklamalar veya bilgilerin bulunduğu yerdir.Burada;
        - Kuralın yazarı,
        - Kuralın oluşturulma tarihi,
        - Tehdit türü,
        - Başlık,
        - Referans,
        - Kategori,
        - Versiyon,

    vb. bilgiler bulunur.

2- STRINGS BÖLÜMÜ:

    Bu bölümde, zararlı yazılım içerisinde aranmak istenen özel stringler tanımlanır. Yara bu stringleri zararlı yazılım içerisinde bulmak için kullanır.

3- CONDITION BÖLÜMÜ:

    Kuralların nasıl uygulanacağı burada belirtilir.Bu bölümdeki koşullar hangi durumlarda bir dosyanın bu kurala uyduğunu belirler.


* Her yara kuralının kullanıcı tarafından tanımlanan benzersiz bir adı olmalıdır.Burada verilecek kural adı anlamlı ve kolay anlaşılabilir olmalıdır.
* Metaveriler kuralın amacını anlamayı kolaylaştırır.Tarama sonucunu etkilemez.
* Dizeler, kuralın dosyalarda veya bellekte arayacağı desenleri tanımlar.Yara farklı türde dizeler destekler.Bunlar;

            - Düz metin Dizeleri(Plain Text):
                * strings:
                    $text_yazim = "zayotem yakaladi"
            
            - Hexadecimal Dizerler(Hexadecimal Strings):
                * strings:
                    $hex_strings = {4D 5A 90 ? ? 00 00}
            
            -Düzenli ifadeler(Regular Expression):
                * strings:
                    $regex = /[a-f0-9]{32}/
    
* Koşullar(Condititons)
    Kuralın mantığını belirler ve hangi durumda eşleşmenin gerçekleşeceğini tanımlar. Dizelerin bir kısmının veya tamamının eşleşip eşleşmediğini kontrol edebilir.
    condition:
        any of ($text_string, $hex_string, $regex)

    1-Boolean Mantığı(Boolean Logic):

        Boolean mantığı, birden fazla koşulu birleştirmek için AND, OR, ve NOT operatörlerini kullanır.
        
        condition: 
            $hex_string and $text_string

    2-Miktar Belirleyicileri (Quantifiers):

        Miktar belirleyiciler, bir dize ya da koşulun dosyada kaç kez tekrarlandığını tanımlamanıza olanak sağlar. at least, at most, ve any of them gibi ifadeler kullanılır.

        condition: 
            $string1 at least 2 and $string2 at most 4
    
    3- Dosya Boyutu Koşulları (File Size Condition)

        Dosyanın boyutuna göre koşullar tanımlamak için $filesize özelliği kullanılır.

        condition: 
            $filesize < 5MB

    4-  Koşulların Birleştirilmesi (Combining Multiple Conditions)

        Boolean mantığı, miktar belirleyiciler ve dosya boyutu gibi özellikleri birleştirerek daha kapsamlı koşullar oluşturabilirsiniz.

        condition: 
            $filesize < 2MB and ($string1 or $string2) and not $string3


