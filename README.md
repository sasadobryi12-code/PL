### Задания к экзамену/ознакомительной практике

## 1 задание CrackMe 11.exe

<img width="1156" height="115" alt="image" src="https://github.com/user-attachments/assets/5f0fd9a3-b412-43bb-8576-162f9f5f4cef" />

1. RegOpenKeyExA / RegQueryValueExA
Открывает ветку реестра HKEY_CURRENT_USER\Software\wiXEjablA1 и читает значение 6pZhi.
Скорее всего, там хранятся входные данные (пароль/флаг)
2. sub_4017D2
<img width="1042" height="359" alt="image" src="https://github.com/user-attachments/assets/5ec3ce41-2af8-4a3d-af88-a47dd1a28a1f" />
она там очень большая и длинная
Функция реализует кастомный Base64-декодер с алфавитом, генерируемым XORом фиксированных данных с ключом 0x91. Входные 3 байта преобразуются в 4 символа выходной строки.
3. sub_401706
<img width="414" height="376" alt="image" src="https://github.com/user-attachments/assets/e667674a-2d87-4cc8-b753-10bfd2ed94a5" />
Функция рекурсивно строит эталонную строку, используя 12 итераций и данные из глобальных таблиц unk_405060, unk_4050E0 и массива индексов dword_405020. Результат — 120 байт (12×10).
4.byte_404020
![Uploading image.png…]()
В main именно с ним сравнивается результат sub_4017D2 (после преобразования ввода).
byte_404020 — это уже готовая строка, которую должна выдать sub_4017D2 при правильном вводе.

# Флаг получить легко, тут нужен скрипт который сделает все в обратную сторону:
```python
def hex_to_bytes(hex_str):
    return list(bytes.fromhex(hex_str))

# Данные из программы
unk_405060 = hex_to_bytes(
    "DF90C0A17B2EFC2A7BB340A50879607E81C9C7B9336CBA3C9BF54473620364C9C344D319A3152C20A3D719A4EA824DF7D7C9BC4A78C8C860B398D5504D1CA1BF37A83914029055E9B13E60D25413D49DF22C611C17C726582E74E87A37E8F7848C211A258B813EF446CAAFBED068356BD576E7D45184D50E"
)
unk_4050E0 = hex_to_bytes(
    "BFF621FF406220DC25051F0577D1CACDEDA421BCE062BD21EB745FE55A16F0898256D3AAD70769C8E3EE607B3AF8E7FFE8A7B288CD2A4EABEB83733D010CDBE27BA4A0F846352902A6DECD5CF8EB435AE3584FE6DA8A65DF88F221D6205CC91AD5B18AC4342BCA3A14793862956F60E11E7B2D0604EE8A43"
)

byte_404020 = [
    0x6D, 0x42, 0x0B, 0x81, 0x5F, 0x0B, 0xF9, 0xF5, 0xC7, 0x45,
    0x58, 0x1B, 0x28, 0xA0, 0x78, 0x35, 0x9A, 0xEC, 0xED, 0x71,
    0x65, 0x27, 0x14, 0x83, 0x6A, 0x21, 0xB4, 0x8C, 0xF9, 0x6E,
    0x76, 0x02, 0x2A, 0xC7, 0x59, 0x1A, 0x96, 0xFF, 0xE1, 0x30,
    0x67, 0x34, 0x31, 0x8E, 0x69, 0x27, 0x14, 0x83, 0x6A, 0x21,
    0xB4, 0x8C, 0xF9, 0x6E,
]

def generate_custom_alphabet():
    """Генерирует кастомный Base64 алфавит, как в sub_4017D2"""
    Str = [
        -48, -45, -46, -43, -44, -41, -42, -39, -40, -37, -38, -35,
        -36, -33, -34, -63, -64, -61, -62, -59, -60, -57, -58, -55,
        -56, -53, -16, -13, -14, -11, -12, -9, -10, -7, -8, -5, -6,
        -3, -4, -1, -2, -31, -32, -29, -30, -27, -28, -25, -26, -23,
        -24, -21, -95, -96, -93, -94, -91, -92, -89, -90, -87, -88,
        -70, -66
    ]
    # XOR с 0x91 и приведение к unsigned char (0-255)
    alphabet = [(c ^ 0x91) & 0xFF for c in Str]
    return bytes(alphabet)

def custom_base64_decode(encoded_str, alphabet):
    """
    Декодирует строку, закодированную кастомным Base64.
    Работает как стандартный Base64, но с нестандартным алфавитом.
    """
    # Создаём таблицу обратного преобразования
    reverse_alphabet = {ch: i for i, ch in enumerate(alphabet)}
    reverse_alphabet[ord('=')] = 0  # Padding
    
    # Убираем символы не из алфавита (должно быть ровно 4*n символов)
    encoded_str = encoded_str.rstrip('=')
    
    result = bytearray()
    
    # Обрабатываем по 4 символа
    for i in range(0, len(encoded_str), 4):
        chunk = encoded_str[i:i+4]
        # Преобразуем 4 символа в 24 бита
        n = 0
        for j, ch in enumerate(chunk):
            if ch in reverse_alphabet:
                n |= reverse_alphabet[ch] << (18 - j * 6)
        # Извлекаем 3 байта
        result.append((n >> 16) & 0xFF)
        if len(chunk) > 2:
            result.append((n >> 8) & 0xFF)
        if len(chunk) > 3:
            result.append(n & 0xFF)
    
    return bytes(result)

def decode_sub_401706():
    """
    Реверсивная операция для sub_401706 (декодирование byte_404020)
    """
    data = bytearray(byte_404020)
    
    # Обратный проход (с 11 до 0, как в оригинале)
    for r in range(11, -1, -1):
        start = r * 10
        # Восстанавливаем ключ раунда (как XOR двух таблиц)
        round_key = []
        for i in range(10):
            if start + i < len(unk_405060) and start + i < len(unk_4050E0):
                round_key.append(unk_405060[start + i] ^ unk_4050E0[start + i])
            else:
                round_key.append(0)
        
        # XOR с ключом раунда (на каждый байт данных)
        for i in range(len(data)):
            data[i] ^= round_key[i % 10]
    
    return bytes(data)

def main():
    # Получаем закодированную строку из реверсированной sub_401706
    encoded_bytes = decode_sub_401706()
    
    # Выводим как строку (это должна быть Base64 строка с кастомным алфавитом)
    print(f"Закодированные данные (байты): {encoded_bytes[:50]}...")
    print(f"Как строка: {encoded_bytes.decode('utf-8', errors='ignore')}")
    
    # Генерируем кастомный алфавит
    custom_alphabet = generate_custom_alphabet()
    print(f"\nКастомный Base64 алфавит: {custom_alphabet}")
    
    # Декодируем кастомный Base64
    try:
        # Находим, где начинается Base64 строка в байтах
        # (скорее всего, это читаемые ASCII символы)
        b64_str = encoded_bytes.decode('ascii', errors='ignore')
        # Оставляем только символы из алфавита и '='
        b64_str = ''.join(ch for ch in b64_str if ch in custom_alphabet.decode() + '=')
        
        print(f"\nBase64 строка для декодирования: {b64_str[:100]}...")
        
        # Декодируем
        decoded = custom_base64_decode(b64_str, custom_alphabet)
        print(f"\nФЛАГ: {decoded.decode('utf-8', errors='ignore')}")
    except Exception as e:
        print(f"Ошибка: {e}")

if __name__ == "__main__":
    main()
```
