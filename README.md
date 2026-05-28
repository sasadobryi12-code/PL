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
