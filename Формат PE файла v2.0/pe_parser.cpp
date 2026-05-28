/*
 * Лабораторная работа №1 — PE Analyzer
 * Анализатор заголовка PE-файла (Windows)
 */

#include <cstring>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

void initConsoleUtf8();

#pragma pack(push, 1)

struct IMAGE_DOS_HEADER {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t e_lfanew;
};

struct IMAGE_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_NT_HEADERS32 {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

struct IMAGE_EXPORT_DIRECTORY {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;
    uint32_t AddressOfNames;
    uint32_t AddressOfNameOrdinals;
};

struct IMAGE_IMPORT_DESCRIPTOR {
    union {
        uint32_t Characteristics;
        uint32_t OriginalFirstThunk;
    };
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
};

#pragma pack(pop)

constexpr int DIR_EXPORT = 0;
constexpr int DIR_IMPORT = 1;
constexpr int DIR_RESOURCE = 2;
constexpr int DIR_BASERELOC = 5;

constexpr uint16_t IMAGE_DOS_SIGNATURE = 0x5A4D;
constexpr uint32_t IMAGE_NT_SIGNATURE = 0x00004550;
constexpr uint16_t IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B;
constexpr uint16_t IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B;

constexpr uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000;
constexpr uint32_t IMAGE_SCN_MEM_READ = 0x40000000;
constexpr uint32_t IMAGE_SCN_MEM_WRITE = 0x80000000;

struct FlagDesc16 {
    uint16_t mask;
    const char* description;
};

struct FlagDesc32 {
    uint32_t mask;
    const char* description;
};

static const FlagDesc16 kFileCharacteristics[] = {
    {0x0001, "Отсутствуют релокации."},
    {0x0002, "Файл образа действителен и может быть запущен."},
    {0x0004, "Удалена отладочная информация (номера строк)."},
    {0x0008, "Удалены локальные символы."},
    {0x0010, "Агрессивная оптимизация рабочего набора."},
    {0x0020, "Приложение может обрабатывать > 2 ГБ-адресов."},
    {0x0100, "32-разрядная машина."},
    {0x2000, "Файл является DLL."},
    {0x4000, "Только однопроцессорная система."},
};

static const FlagDesc16 kDllCharacteristics[] = {
    {0x0020, "Может обрабатывать 64-разрядное виртуальное адресное пространство."},
    {0x0040, "DLL может быть перемещена при загрузке (ASLR)."},
    {0x0080, "Проверка целостности кода."},
    {0x0100, "Совместима с NX (DEP)."},
    {0x0200, "Изоляция (Isolation Aware)."},
    {0x0400, "Не использует SEH."},
    {0x4000, "Control Flow Guard (Guard CF)."},
    {0x8000, "Terminal Server aware."},
};

class PeParser {
public:
    explicit PeParser(std::string path) : path_(std::move(path)) {}

    bool load() {
        std::ifstream file(path_, std::ios::binary | std::ios::ate);
        if (!file) {
            std::cerr << "Не удалось открыть файл: " << path_ << std::endl;
            return false;
        }
        const auto fileSize = file.tellg();
        if (fileSize <= 0) {
            std::cerr << "Файл пуст." << std::endl;
            return false;
        }
        data_.resize(static_cast<size_t>(fileSize));
        file.seekg(0);
        file.read(reinterpret_cast<char*>(data_.data()), fileSize);
        return file.good();
    }

    void analyze() const {
        if (!parseNtHeaders()) return;

        printBanner();
        printGeneralInfo();
        printFileCharacteristics();
        printOptionalHeaderInfo();
        printDllCharacteristics();
        printRelocations();
        printResources();
        printSectionsTable();
        printImports();
        printExports();
    }

private:
    std::string path_;
    std::vector<uint8_t> data_;
    mutable bool is64_ = false;
    mutable uint32_t optionalHeaderOffset_ = 0;
    mutable uint16_t numberOfSections_ = 0;
    mutable uint32_t sectionTableOffset_ = 0;
    mutable IMAGE_FILE_HEADER fileHeader_{};

    const uint8_t* base() const { return data_.data(); }
    size_t size() const { return data_.size(); }

    template <typename T>
    const T* atOffset(size_t offset) const {
        if (offset + sizeof(T) > size()) return nullptr;
        return reinterpret_cast<const T*>(base() + offset);
    }

    const char* rvaToCString(uint32_t rva) const {
        const uint32_t off = rvaToFileOffset(rva);
        if (off == 0 || off >= size()) return nullptr;
        return reinterpret_cast<const char*>(base() + off);
    }

    uint32_t rvaToFileOffset(uint32_t rva) const {
        const auto* sections = atOffset<IMAGE_SECTION_HEADER>(sectionTableOffset_);
        if (!sections) return 0;
        for (uint16_t i = 0; i < numberOfSections_; ++i) {
            const auto& s = sections[i];
            const uint32_t vsize =
                s.Misc.VirtualSize > s.SizeOfRawData ? s.Misc.VirtualSize : s.SizeOfRawData;
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + vsize) {
                return s.PointerToRawData + (rva - s.VirtualAddress);
            }
        }
        return 0;
    }

    static std::string fileBaseName(const std::string& path) {
        const auto pos = path.find_last_of("\\/");
        return pos == std::string::npos ? path : path.substr(pos + 1);
    }

    static std::string hex32(uint32_t v, int width = 8) {
        std::ostringstream os;
        os << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(width) << v;
        return os.str();
    }

    static std::string hex64(uint64_t v) {
        std::ostringstream os;
        os << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << v;
        return os.str();
    }

    static std::string hex16(uint16_t v) {
        std::ostringstream os;
        os << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(4) << v;
        return os.str();
    }

    static std::string bytesStr(uint32_t n) {
        return std::to_string(n) + " bytes";
    }

    static std::string machineShort(uint16_t machine) {
        switch (machine) {
            case 0x014C: return "x86";
            case 0x8664: return "AMD64";
            case 0x01C4: return "ARM";
            case 0xAA64: return "ARM64";
            default: return "Unknown";
        }
    }

    static std::string sectionFlags(uint32_t ch) {
        std::string s;
        if (ch & IMAGE_SCN_MEM_EXECUTE) s += 'E';
        if (ch & IMAGE_SCN_MEM_READ) s += 'R';
        if (ch & IMAGE_SCN_MEM_WRITE) s += 'W';
        return s.empty() ? "-" : s;
    }

    static void printFlagList16(uint16_t value, const FlagDesc16* table, size_t count) {
        for (size_t i = 0; i < count; ++i) {
            if (value & table[i].mask) {
                std::cout << "  " << hex16(table[i].mask) << " - " << table[i].description << std::endl;
            }
        }
    }

    bool parseNtHeaders() const {
        const auto* dos = atOffset<IMAGE_DOS_HEADER>(0);
        if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) {
            std::cerr << "Неверный DOS-заголовок." << std::endl;
            return false;
        }
        const auto* nt = atOffset<IMAGE_NT_HEADERS32>(static_cast<size_t>(dos->e_lfanew));
        if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) {
            std::cerr << "Неверный PE-заголовок." << std::endl;
            return false;
        }
        fileHeader_ = nt->FileHeader;
        optionalHeaderOffset_ = static_cast<uint32_t>(dos->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
        const uint16_t magic = *reinterpret_cast<const uint16_t*>(base() + optionalHeaderOffset_);
        is64_ = (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
        numberOfSections_ = fileHeader_.NumberOfSections;
        sectionTableOffset_ = optionalHeaderOffset_ + fileHeader_.SizeOfOptionalHeader;
        return true;
    }

    const IMAGE_DATA_DIRECTORY* getDataDirectory(int index) const {
        if (is64_) {
            const auto* opt = atOffset<IMAGE_OPTIONAL_HEADER64>(optionalHeaderOffset_);
            if (!opt || index >= 16) return nullptr;
            return &opt->DataDirectory[index];
        }
        const auto* opt = atOffset<IMAGE_OPTIONAL_HEADER32>(optionalHeaderOffset_);
        if (!opt || index >= 16) return nullptr;
        return &opt->DataDirectory[index];
    }

    void printBanner() const {
        std::cout << "========================================" << std::endl;
        std::cout << "           PE-Analyzer" << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << std::endl;
    }

    void printGeneralInfo() const {
        std::cout << "Название анализируемого файла: " << fileBaseName(path_) << std::endl;
        std::cout << "Архитектура программы:         " << machineShort(fileHeader_.Machine) << std::endl;
        std::cout << std::endl;
    }

    void printFileCharacteristics() const {
        std::cout << "Характеристики:" << std::endl;
        printFlagList16(fileHeader_.Characteristics, kFileCharacteristics,
                        sizeof(kFileCharacteristics) / sizeof(kFileCharacteristics[0]));
        std::cout << std::endl;
    }

    void printOptionalHeaderInfo() const {
        if (is64_) {
            const auto* opt = atOffset<IMAGE_OPTIONAL_HEADER64>(optionalHeaderOffset_);
            if (!opt) return;
            std::cout << "Тип файла:                     64-разрядный (поле Magic: "
                      << hex16(opt->Magic) << ")" << std::endl;
            std::cout << "Адрес точки входа:             " << hex32(opt->AddressOfEntryPoint) << std::endl;
            std::cout << "Базовый адрес загрузки:        " << hex64(opt->ImageBase) << std::endl;
            std::cout << "Виртуальное выравнивание:      " << hex32(opt->SectionAlignment) << std::endl;
            std::cout << "Физическое выравнивание:       " << hex32(opt->FileAlignment) << std::endl;
            std::cout << "Размер образа в памяти:        " << bytesStr(opt->SizeOfImage) << std::endl;
        } else {
            const auto* opt = atOffset<IMAGE_OPTIONAL_HEADER32>(optionalHeaderOffset_);
            if (!opt) return;
            std::cout << "Тип файла:                     32-разрядный (поле Magic: "
                      << hex16(opt->Magic) << ")" << std::endl;
            std::cout << "Адрес точки входа:             " << hex32(opt->AddressOfEntryPoint) << std::endl;
            std::cout << "Базовый адрес загрузки:        " << hex32(opt->ImageBase) << std::endl;
            std::cout << "Виртуальное выравнивание:      " << hex32(opt->SectionAlignment) << std::endl;
            std::cout << "Физическое выравнивание:       " << hex32(opt->FileAlignment) << std::endl;
            std::cout << "Размер образа в памяти:        " << bytesStr(opt->SizeOfImage) << std::endl;
        }
        std::cout << std::endl;
    }

    void printDllCharacteristics() const {
        uint16_t dllCh = 0;
        if (is64_) {
            const auto* opt = atOffset<IMAGE_OPTIONAL_HEADER64>(optionalHeaderOffset_);
            if (opt) dllCh = opt->DllCharacteristics;
        } else {
            const auto* opt = atOffset<IMAGE_OPTIONAL_HEADER32>(optionalHeaderOffset_);
            if (opt) dllCh = opt->DllCharacteristics;
        }
        if (dllCh == 0) return;
        std::cout << "DLL-характеристики:" << std::endl;
        printFlagList16(dllCh, kDllCharacteristics,
                        sizeof(kDllCharacteristics) / sizeof(kDllCharacteristics[0]));
        std::cout << std::endl;
    }

    void printRelocations() const {
        const auto* dir = getDataDirectory(DIR_BASERELOC);
        if (dir && dir->VirtualAddress != 0 && dir->Size != 0) {
            std::cout << "Файл содержит релокации." << std::endl;
            std::cout << std::endl;
        }
    }

    void printResources() const {
        const auto* dir = getDataDirectory(DIR_RESOURCE);
        if (dir && dir->VirtualAddress != 0 && dir->Size != 0) {
            std::cout << "Файл содержит ресурсы." << std::endl;
            std::cout << std::endl;
        }
    }

    void printSectionsTable() const {
        const auto* sections = atOffset<IMAGE_SECTION_HEADER>(sectionTableOffset_);
        if (!sections) return;

        std::cout << "Секции:" << std::endl;
        std::cout << std::left
                  << std::setw(4) << "#"
                  << std::setw(10) << "Имя"
                  << std::setw(14) << "Вирт. размер"
                  << std::setw(14) << "Вирт. адрес"
                  << std::setw(14) << "Физ. размер"
                  << std::setw(14) << "Физ. смещение"
                  << "Флаги" << std::endl;
        std::cout << std::string(72, '-') << std::endl;

        for (uint16_t i = 0; i < numberOfSections_; ++i) {
            const auto& s = sections[i];
            char name[9] = {};
            std::memcpy(name, s.Name, 8);

            std::cout << std::left << std::setw(4) << i
                      << std::setw(10) << name
                      << std::setw(14) << bytesStr(s.Misc.VirtualSize)
                      << std::setw(14) << hex32(s.VirtualAddress)
                      << std::setw(14) << bytesStr(s.SizeOfRawData)
                      << std::setw(14) << hex32(s.PointerToRawData)
                      << sectionFlags(s.Characteristics) << std::endl;
        }
        std::cout << std::endl;
    }

    void printImports() const {
        std::cout << "Импорты:" << std::endl;
        const auto* dir = getDataDirectory(DIR_IMPORT);
        if (!dir || dir->VirtualAddress == 0 || dir->Size == 0) {
            std::cout << "  Таблица импортов не найдена." << std::endl;
            std::cout << std::endl;
            return;
        }

        bool any = false;
        uint32_t descRva = dir->VirtualAddress;
        for (;;) {
            const uint32_t descOff = rvaToFileOffset(descRva);
            if (descOff == 0) break;
            const auto* desc = atOffset<IMAGE_IMPORT_DESCRIPTOR>(descOff);
            if (!desc) break;
            if (desc->OriginalFirstThunk == 0 && desc->FirstThunk == 0 && desc->Name == 0) break;

            const char* dllName = rvaToCString(desc->Name);
            if (dllName) {
                std::cout << "  " << dllName << std::endl;
                any = true;
            }
            descRva += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        }
        if (!any) {
            std::cout << "  Таблица импортов не найдена." << std::endl;
        }
        std::cout << std::endl;
    }

    void printExports() const {
        std::cout << "Экспорты:" << std::endl;
        const auto* dir = getDataDirectory(DIR_EXPORT);
        if (!dir || dir->VirtualAddress == 0 || dir->Size == 0) {
            std::cout << "  Таблица экспортов не найдена." << std::endl;
            std::cout << std::endl;
            return;
        }

        const uint32_t off = rvaToFileOffset(dir->VirtualAddress);
        const auto* exp = atOffset<IMAGE_EXPORT_DIRECTORY>(off);
        if (!exp || exp->NumberOfNames == 0) {
            std::cout << "  Таблица экспортов не найдена." << std::endl;
            std::cout << std::endl;
            return;
        }

        const auto* namesRva = reinterpret_cast<const uint32_t*>(
            base() + rvaToFileOffset(exp->AddressOfNames));
        if (!namesRva) {
            std::cout << "  Таблица экспортов не найдена." << std::endl;
            std::cout << std::endl;
            return;
        }

        constexpr uint32_t kMaxList = 30;
        if (exp->NumberOfNames > kMaxList) {
            std::cout << "  Таблица экспортов присутствует (" << exp->NumberOfNames
                      << " функций, список сокращён):" << std::endl;
            for (uint32_t i = 0; i < kMaxList; ++i) {
                const char* name = rvaToCString(namesRva[i]);
                if (name) std::cout << "  " << name << std::endl;
            }
            std::cout << "  ..." << std::endl;
        } else {
            for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
                const char* name = rvaToCString(namesRva[i]);
                if (name) std::cout << "  " << name << std::endl;
            }
        }
        std::cout << std::endl;
    }
};

int main(int argc, char* argv[]) {
    initConsoleUtf8();

    if (argc < 2) {
        std::cout << "Использование: pe_parser.exe <файл.exe|dll>" << std::endl;
        std::cout << "Пример:        pe_parser.exe files\\PE2.exe" << std::endl;
        return 1;
    }

    for (int i = 1; i < argc; ++i) {
        if (i > 1) {
            std::cout << std::endl << std::string(40, '=') << std::endl << std::endl;
        }
        PeParser parser(argv[i]);
        if (!parser.load()) return 1;
        parser.analyze();
    }

    std::cout << "Нажмите любую клавишу для выхода..." << std::endl;
    system("pause");
    return 0;
}
