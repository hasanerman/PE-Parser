# PE Parser & Analyzer

A high-performance, native Win32 GUI Portable Executable (PE) analysis tool written in C++20 for Windows. The application features an immersive dark theme based on the Catppuccin Mocha palette.

## Project Background

I built this tool to provide a clean, fast, and dependency-free static analysis environment for Windows executable files (both PE32 and PE32+). Unlike modern tools that rely heavily on large web-based wrappers or heavyweight UI frameworks, this project is built entirely on the native Win32 API. It uses memory mapping (MapViewOfFile) for extremely fast static parsing and has zero external dependencies.

---

## Key Features

### 1. Immersive Dark Theme (Catppuccin Mocha)
- The entire GUI is custom-drawn using the Catppuccin Mocha color palette.
- Completely customized flat tab buttons with accent indicator bars.
- Custom-painted, dark-themed buttons and dialog elements.
- Dark-themed ListView columns and header controls, eliminating standard Windows light gray artifacts.
- Proportional status bar displaying system and file metrics.

### 2. Comprehensive Header Analysis
- DOS Header: Validation of MZ signature and recovery of PE header offset.
- File Header: Parsing machine type, number of sections, characteristics flags, and compilation timestamp.
- Optional Header: Resolution of major/minor linker, operating system, and subsystem versions, entry point address, and memory layout parameters.
- Security Mitigations: Static check for ASLR (Dynamic Base), DEP/NX (NX Compat), Control Flow Guard (CFG), High Entropy VA, and Force Integrity.

### 3. Section and Entropy Analysis
- Individual section properties listed alongside computed Shannon entropy.
- Sections with high entropy (greater than 7.2) are highlighted, indicating packing or encryption.
- Writable and Executable (W+X) sections are flagged immediately as high-risk.

### 4. Imports & Exports with Live Filtering
- Import Address Table (IAT) walker showing DLL names and imported functions.
- Export Address Table (EAT) parser showing exported function names, ordinals, RVAs, and forwarders.
- Real-time search/filter bars integrated into both panels, allowing instant query resolution across thousands of functions.
- Highlighted import references for high-risk Win32 API calls (known process injection, evasion, or hook techniques).

### 5. String Extraction & Network Indicator Scanner
- Scans binary sections and headers for printable ASCII and UTF-16 Unicode strings (minimum length of 4 characters).
- Filters extracted strings using pattern matching to identify IPv4 addresses, URLs, and domains.
- Lists the exact section, file offset, and RVA of each string.
- Live search filtering and one-click toggle to isolate only network indicators.

### 6. Version and PDB Debug Information
- Resolves RT_VERSION resources dynamically using Windows Version APIs to display company name, product version, file description, and copyright metadata.
- Parses the debug directory for CodeView (RSDS/NB10) blocks to extract compiler GUIDs, age, and local PDB build paths.

### 7. Overlay Exporter
- Automatically computes the physical boundaries of the PE file vs the actual file size.
- Detects appended overlay payloads and displays their offset and size.
- Includes a dedicated "Save Overlay" feature to dump the payload to a separate binary file.

### 8. Structural Validation & JSON Export
- Verifies header fields and reports mismatching PE checksum values.
- Performs suspicious structural checks, warning of empty section names or anomalies.
- Hand-built JSON exporter utility to dump all parsed structures into a clean JSON file for integration into external scripts.

---

## Technical Details

- Language Standard: C++20
- Graphics Library: Native Win32 API (GDI)
- Libraries Linked: Dwmapi.lib, UxTheme.lib, Comctl32.lib, Imagehlp.lib, Version.lib
- Loading Strategy: MapViewOfFile memory mapping

---

## Build Instructions

1. Open the project in Visual Studio 2022.
2. Select the configuration (Debug or Release) and the target platform (x86 or x64).
3. Ensure the project standard is set to C++20.
4. Build the solution.

================================================================================

# PE Parser & Analyzer (Türkçe)

Windows için C++20 ile yazılmış, yüksek performanslı ve yerel (native) Win32 GUI tabanlı bir Portable Executable (PE) analiz aracıdır. Arayüzün tamamı Catppuccin Mocha renk paletine dayalı karanlık bir temayla tasarlanmıştır.

## Proje Amacı

Bu aracı, Windows çalıştırılabilir dosyaları (PE32 ve PE32+) üzerinde hızlı ve bağımlılıksız statik analiz yapabilmek amacıyla geliştirdim. Ağır UI kütüphaneleri veya web tabanlı arayüz çerçeveleri yerine doğrudan Win32 API kullanarak işletim sistemi mimarisine yakın, yüksek performanslı bir yapı kurdum. Dosya yükleme işleminde MapViewOfFile bellek eşlemesi kullandığım için dosya okuma ve analiz işlemleri son derece hızlı gerçekleşmektedir.

---

## Öne Çıkan Özellikler

### 1. Bütünsel Karanlık Tema (Catppuccin Mocha)
- Tüm GUI pencereleri Catppuccin Mocha renk paletine uygun olarak özel olarak çizilir.
- Tamamen özelleştirilmiş flat tab (sekme) butonları ve mor renkli aktiflik göstergeleri.
- Yuvarlatılmış köşelere sahip, özel çizim karanlık butonlar ve girdi alanları.
- ListView başlık sütunları dahil her şey karanlık temayla çizilerek Windows'un klasik gri renk uyumsuzlukları giderilmiştir.
- Dosya ve mimari detaylarını gösteren orantılı durum çubuğu.

### 2. Başlık Analizi (Header Parsing)
- DOS Başlığı: Magic byte (MZ) doğrulaması ve PE başlığı offsetinin tespiti.
- Dosya Başlığı: Makine mimarisi, bölüm sayısı, karakteristik bayraklar ve derleme zaman damgasının çözümlenmesi.
- İsteğe Bağlı (Optional) Başlık: Giriş noktası (Address of Entry Point), Image Base değeri, alt sistem (subsystem), OS/bağlayıcı sürümleri ve bellek hizalama parametrelerinin dökümü.
- Güvenlik Önlemleri Kontrolü: ASLR, DEP/NX, Control Flow Guard (CFG), High Entropy VA ve Force Integrity desteklerinin statik analizi.

### 3. Bölüm (Section) ve Entropi Analizi
- Dosya bölümlerinin ham ve sanal adresleri, boyutları ve Shannon entropi değerleri.
- Entropisi yüksek (7.2 ve üzeri) olan paketlenmiş veya şifrelenmiş bölümler sarı renkli uyarıyla gösterilir.
- Hem yazılabilir hem çalıştırılabilir (W+X) durumda olan tehlikeli bölümler kırmızı renkli kritik bayrakla vurgulanır.

### 4. Canlı Filtrelemeli Imports & Exports
- IAT (Import Address Table) tablosundan içeri aktarılan DLL ve API fonksiyonlarının tam dökümü.
- EAT (Export Address Table) tablosundan dışarıya sunulan fonksiyon isimleri, RVA adresleri ve forwarder yönlendirmeleri.
- Sekmelerin üstüne eklenen arama kutuları sayesinde binlerce fonksiyon arasından anlık arama ve filtreleme yapabilme kolaylığı.
- İşletim sistemi manipülasyonu, enjeksiyon veya tespit atlatma amacıyla kullanılan yüksek riskli Win32 API fonksiyonlarının otomatik işaretlenmesi.

### 5. String Ayıklayıcı ve Ağ Göstergesi Tarayıcı
- PE içerisindeki ASCII ve UTF-16 Unicode metinleri (minimum 4 karakter) otomatik tarar.
- Ayıklanan metinler içindeki IPv4 adreslerini, URL yapılarını ve alan adlarını filtreler.
- Metnin bulunduğu dosya offsetini, sanal adresini (RVA) ve ait olduğu bölüm adını gösterir.
- Canlı arama kutusu ve tek tıklamayla sadece ağ göstergelerini (URL/IP) izole etme seçeneği.

### 6. Sürüm Bilgileri ve PDB Sembol Yolları
- RT_VERSION kaynak dosyalarını otomatik çözerek üretici firma, ürün adı, açıklama ve telif hakkı bilgilerini listeler.
- Debug tablosundaki CodeView (RSDS/NB10) girdilerini parse ederek derleyicinin oluşturduğu PDB yolunu, GUID değerini ve yaş bilgisini çıkarır.

### 7. Overlay Kaydedici (Dump Overlay)
- PE dosyasının bölümlerinin bittiği yer ile dosyanın diski kapladığı fiziksel boyut farkını hesaplayarak overlay verilerini tespit eder.
- Overlay verisinin başlangıç offsetini ve boyutunu raporlar.
- Toolbar ve menüdeki buton sayesinde overlay verisini `.bin` uzantılı ayrı bir dosya olarak kaydetme imkanı sunar.

### 8. Yapısal Doğrulama ve JSON Dışa Aktarma
- PE Checksum doğrulama (Header checksum vs Gerçek checksum karşılaştırması).
- Boş bölüm isimleri veya alışılmadık bölüm sayıları gibi anomalileri raporlama.
- Elde edilen tüm analiz verilerini, harici betiklerle veya diğer araçlarla kolayca entegre edebilmenizi sağlayan yerleşik JSON dışa aktarma aracı.

---

## Teknik Özellikler

- Dil Standardı: C++20
- Grafik Kütüphanesi: Yerel Win32 API (GDI)
- Kullanılan Kütüphaneler: Dwmapi.lib, UxTheme.lib, Comctl32.lib, Imagehlp.lib, Version.lib
- Dosya Okuma Stratejisi: MapViewOfFile bellek eşlemesi

---

## Derleme Talimatları

1. Projeyi Visual Studio 2022 ile açın.
2. Derleme yapılandırmasını (Debug veya Release) ve hedef platformu (x86 veya x64) seçin.
3. Proje dil standardının C++20 olarak ayarlandığından emin olun.
4. Çözümü derleyin (Build).
