#define WIN32_LEAN_AND_MEAN
#include <windows.h>

void initConsoleUtf8() {
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
}
