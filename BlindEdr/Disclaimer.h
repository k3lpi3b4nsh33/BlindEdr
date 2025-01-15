#pragma once

#include <Windows.h>
#include <stdio.h>

BOOL showDisclaimer() {
    // Save original console cursor info
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_CURSOR_INFO cursorInfo;
    GetConsoleCursorInfo(hConsole, &cursorInfo);
    BOOL originalCursorVisible = cursorInfo.bVisible;

    // Hide cursor for smooth refresh
    cursorInfo.bVisible = FALSE;
    SetConsoleCursorInfo(hConsole, &cursorInfo);

    printf("\n"                                                                            );
    printf("===========================================================================\n" );
    printf("                            LEGAL DISCLAIMER                                \n");
    printf("===========================================================================\n" );
    printf("\n"                                                                            );
    printf("This software is provided 'as-is' without any express or implied warranty.\n"  );
    printf("In no event will the authors be held liable for any damages arising from\n"    );
    printf("the use of this software. This is for educational purposes only.\n"            );
    printf("\n"                                                                            );
    printf("By using this software you agree that:\n"                                      );
    printf("1. You will only use it on systems you own or have permission to test.\n"      );
    printf("2. You accept all responsibility for any consequences that arise from use.\n"  );
    printf("3. You will not use this software for any malicious purposes.\n"               );
    printf("4. You understand this tool may cause system instability.\n"                   );
    printf("\n"                                                                            );
    printf("===========================================================================\n" );
    printf("\n"                                                                            );

    // Get current cursor position for countdown
    COORD cursorPos;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(hConsole, &csbi)) {
        cursorPos.X = 0;
        cursorPos.Y = csbi.dwCursorPosition.Y;
    } else {
        // Fallback if we can't get the cursor position
        cursorPos.X = 0;
        cursorPos.Y = 20;  // Reasonable default value
    }

    // Countdown loop with dynamic refresh
    for (int i = 5; i > 0; i--) {
        SetConsoleCursorPosition(hConsole, cursorPos);
        printf("Please wait %d seconds before accepting...", i);
        Sleep(1000);
    }

    // Clear countdown line and show prompt
    SetConsoleCursorPosition(hConsole, cursorPos);
    printf("                                           \r"); 
    printf("Do you accept these terms? (y/n): ");

    // Restore original cursor visibility
    cursorInfo.bVisible = originalCursorVisible;
    SetConsoleCursorInfo(hConsole, &cursorInfo);

    // Flush any input during countdown
    FlushConsoleInputBuffer(GetStdHandle(STD_INPUT_HANDLE));

    // Get user response
    char response;
    response = getchar();
    while (getchar() != '\n');  // Clear input buffer

    return (response == 'y' || response == 'Y');
}