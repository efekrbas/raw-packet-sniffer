# Raw Packet Sniffer

Python'un yerleşik `socket` ve `struct` modülleriyle yazılmış, eğitim amaçlı temel bir Linux paket yakalayıcısı. Haricî bir paket yakalama kütüphanesi (Scapy, Npcap vb.) kullanmaz.

Araç, Ethernet çerçevelerini yakalar ve IPv4 paketlerinde IP, TCP ve UDP başlıklarını ayrıştırır. TCP/UDP yüklerini (payload) yazdırılabilir ASCII ise metin olarak, değilse hexadecimal biçimde gösterir.

> Yalnızca size ait veya açıkça yetkili olduğunuz ağ ve sistemlerde kullanın. Paket payload'ları oturum bilgileri ve diğer hassas veriler içerebilir.

## Gereksinimler

- Linux (Ubuntu gibi)
- Python 3
- Ham soket açma yetkisi: `root` ya da `CAP_NET_RAW`

Kod, Linux'a özgü `AF_PACKET` soket ailesini kullandığı için Windows ve macOS'ta bu haliyle çalışmaz.

## Çalıştırma

Önce ağ arayüzünüzü belirleyin:

```bash
ip link
```

Ardından yakalayıcıyı seçtiğiniz arayüzle başlatın:

```bash
sudo python3 sniffer.py enp0s3
```

Arayüz adı bilgisayara göre değişebilir: `enp0s3`, `eth0`, `wlan0` gibi. Arayüz adı verilmezse program erişebildiği tüm arayüzleri dinlemeyi dener:

```bash
sudo python3 sniffer.py
```

Yakalamayı durdurmak için `Ctrl+C` kullanın.

## Yakalanan bilgiler

Her Ethernet çerçevesi için:

- Hedef ve kaynak MAC adresi
- EtherType (`IPv4`, `ARP`, `IPv6` vb.)

IPv4 paketleri için:

- Kaynak ve hedef IP adresi
- IP protokol numarası ve adı (`ICMP`, `TCP`, `UDP`)
- IP başlığının bayt aralığı

TCP veya UDP paketleri için:

- Kaynak port
- Hedef port
- Uygulama verisi (payload)

## Kısa denemeler

Şifresiz HTTP isteğini görmek için, yakalayıcı çalışırken başka bir terminalde şunu deneyin:

```bash
curl http://neverssl.com/
```

Hedef portu `80` olan TCP paketlerinde `GET / HTTP/1.1` gibi HTTP isteği satırları ASCII olarak görünebilir. Bir tarayıcı HTTP'yi HTTPS'e yükseltirse içerik şifreli olur ve okunabilir HTTP metni görülmez.

ICMP trafiğini görmek için:

```bash
ping 1.1.1.1
```

Çıktıda `IP Protokol: ICMP (1)` görünür. Bu örnek ICMP başlığını ayrıca ayrıştırmaz; ICMP başlığı ve veri payload olarak gösterilir.

## Nasıl çalışır?

`AF_PACKET` + `SOCK_RAW` Linux çekirdeğinden Ethernet düzeyindeki ham çerçeveleri alır. Ethernet başlığı ilk 14 bayttır:

| Bayt aralığı | Alan |
| --- | --- |
| 0-5 | Hedef MAC |
| 6-11 | Kaynak MAC |
| 12-13 | EtherType |

EtherType `0x0800` olduğunda IPv4 başlığı Ethernet başlığının hemen ardından başlar. `struct.unpack()` ikili başlık alanlarını Python sayılarına ve bayt dizilerine dönüştürür; `socket.inet_ntoa()` dört ham IP baytını `192.168.1.1` gibi okunabilir bir IPv4 adresine çevirir.

IPv4'te IHL alanı IP başlığının değişken uzunluğunu belirtir. TCP başlığı IP başlığının bitiminde başlar ve kendi Data Offset alanına göre biter; UDP başlığı ise sabit 8 bayttır. Bu konumlardan sonra kalan baytlar payload olarak ele alınır.

## Sınırlamalar

- Linux dışındaki işletim sistemleri için farklı bir yakalama altyapısı gerekir.
- VLAN etiketli Ethernet çerçeveleri için ek ayrıştırma uygulanmamıştır.
- Paketler tek tek gösterilir; TCP akış birleştirmesi, sıralama veya yeniden iletim temizleme yapılmaz.
- Şifreli HTTPS/TLS trafiğinin payload'ı okunabilir HTTP içeriği sunmaz.
- Bu araç yalnızca temel paket yapısını öğrenmek içindir; üretim amaçlı paket analizi için Wireshark veya tcpdump daha uygundur.
