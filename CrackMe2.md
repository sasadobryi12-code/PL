## CrackMe2


### Логика:


### Основной код располагается тут(sub_4017BD):
<img width="818" height="908" alt="image" src="https://github.com/user-attachments/assets/af23c3e4-5581-4e2b-bcdc-85618de63281" />

### Ожидаемый формат:
### Строка из 32 шестнадцатеричных символов (0-9, A-F, a-f)
### Дефис после каждых 8 символов
### Пример: XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX
### Проверка:
### Цикл по 32 hex-символам, дефисы на позициях 8, 17, 26
### При нарушении — переход к ошибке

<img width="856" height="616" alt="image" src="https://github.com/user-attachments/assets/fe5e6d72-90b4-4da4-b82a-9500356880dc" />

### Функция строит таблицу декодирования, которая позже используется в sub_401764:
### Сначала создаются несколько таких таблиц из разных пар строк
### Затем sub_401764 применяет их к данным для декодирования
### Это позволяет "зашифровать" глобальные строки и константы, чтобы усложнить статический анализ

<img width="896" height="298" alt="image" src="https://github.com/user-attachments/assets/3142c26f-91d1-4f9a-9705-b90f97518300" />

### Назначение
### Применение таблицы декодирования к 5-байтовому буферу (преобразование строки через XOR с табличным ключом)
### Входные параметры
### a1 — массив из 30 байт (таблица ключей, полученная из sub_4016FD)
### a2 — 5-байтовый буфер (обрабатываемая строка, модифицируется на месте)

<img width="1583" height="350" alt="image" src="https://github.com/user-attachments/assets/a33bdb15-a88d-468d-a781-b7e522ea0567" />

### Побитовое исключающее ИЛИ (XOR) двух байтов, реализованное через битовые операции.
### Математическая формула
### Для одного бита:
### result_bit = (a2_bit & ~a1_bit) | (a1_bit & ~a2_bit) = a1_bit XOR a2_bit

<img width="931" height="149" alt="image" src="https://github.com/user-attachments/assets/216f0719-444b-4014-88f6-0e6d2015e5b1" />
### Если все совпадает он выдает "Activation complited !", "GOOD_JOB"
### Если нет, значит что-то неправильно

### Код:
```python
def ctypes_int32(val):
    return val & 0xFFFFFFFF

def solve_keygen():
    # Эталонные константы из .data секции (то, с чем сравнивается после цикла)
    # Это КОНЕЧНЫЕ значения после всех раундов
    v5 = 0x8C5568DE  # dword_404024
    v6 = 0x18091993  # dword_404020
    v7 = 0x34645DC1  # dword_40401C
    v8 = 0x00000801  # dword_404018 (2049 раундов)
    
    # Константы из цикла (из вашего кода в sub_4017BD)
    CONST_ADD_1 = 860690713
    CONST_ADD_2 = 1326378232
    CONST_XOR_1 = 0xDD1960A0
    CONST_XOR_2 = 0x4759D2B4
    CONST_ADD_3 = 2019380008
    CONST_ADD_4 = 1090794179
    
    # v10 - это результат strtoul(&::String, 0, 16)
    # В вашем коде v10 объявлен как unsigned __int16
    # Из примера видно, что он не используется как hex-число, поэтому v10 = 0
    v10 = 0
    
    print(f"Начинаем обратный цикл на {v8} итераций...")
    print(f"Исходные (конечные) значения:")
    print(f"  v5 = 0x{v5:08X}")
    print(f"  v6 = 0x{v6:08X}")
    print(f"  v7 = 0x{v7:08X}")
    print(f"  v8 = 0x{v8:04X}")
    print()
    
    # Прямой цикл в оригинале:
    # v12 = (v6 ^ v5) + 860690713
    # v13 = (v12 ^ (v7 + 1326378232)) + v10
    # v14 = v13 ^ (v12 >> 3)
    # v5 = (v14 + 1090794179) ^ 0xDD1960A0
    # v6 = (v13 + (v10 ^ v6)) ^ 0x4759D2B4
    # v7 = (v12 ^ (v14 + 1090794179)) + 2019380008
    
    # Обратный цикл (реверсим):
    for r in range(v8):
        # Шаг 1: из v5 = (v14 + 1090794179) ^ 0xDD1960A0
        # находим v14
        v14 = ctypes_int32((v5 ^ CONST_XOR_1) - CONST_ADD_4)
        
        # Шаг 2: из v7 = (v12 ^ (v14 + 1090794179)) + 2019380008
        # находим v12
        v12 = ctypes_int32(ctypes_int32(v7 - CONST_ADD_3) ^ ctypes_int32(v14 + CONST_ADD_4))
        
        # Шаг 3: из v14 = v13 ^ (v12 >> 3)
        # находим v13
        v13 = ctypes_int32(v14 ^ (v12 >> 3))
        
        # Шаг 4: из v6 = (v13 + (v10 ^ v6)) ^ 0x4759D2B4
        # находим старый v6
        v6 = ctypes_int32(ctypes_int32(v6 ^ CONST_XOR_2) - v13) ^ v10
        
        # Шаг 5: из v13 = (v12 ^ (v7 + 1326378232)) + v10
        # находим старый v7
        v7 = ctypes_int32(ctypes_int32(v13 - v10) ^ v12) - CONST_ADD_2
        
        # Шаг 6: из v12 = (v6 ^ v5) + 860690713
        # находим старый v5
        v5 = ctypes_int32(ctypes_int32(v12 - CONST_ADD_1) ^ v6)
        
        # Для отладки - показываем каждые 500 итераций
        if (r + 1) % 500 == 0 or r < 5:
            print(f"Итерация {r+1:4d}: v5=0x{v5:08X}, v6=0x{v6:08X}, v7=0x{v7:08X}")
    
    print()
    print("=" * 50)
    print(f"Начальные значения (флаг):")
    print(f"  v5 = 0x{v5:08X}")
    print(f"  v6 = 0x{v6:08X}")
    print(f"  v7 = 0x{v7:08X}")
    print(f"  v8 = 0x{v8:04X}")
    print()
    
    # Формируем флаг в формате XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX
    flag = f"{v5:08X}-{v6:08X}-{v7:08X}-{v8:08X}"
    print(f"FLAG: {flag}")
    print()
    print("Введите этот ключ в программу для активации.")
    
    return flag

if __name__ == "__main__":
    print("Crackme-52 Keygen")
    print("=" * 50)
    print()
    solve_keygen()
```

<img width="842" height="493" alt="image" src="https://github.com/user-attachments/assets/7490ab17-c40f-4cc7-b0ac-56f2ac4b8d26" />

### Flag: 6CBF8091-E61B300E--EDEFCEC-00000801
