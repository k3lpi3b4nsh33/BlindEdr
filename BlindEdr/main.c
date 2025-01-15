#include "Common.h"
#include "Structs.h"
#include "RemoveCallBacks.h"
#include "IatCamo.h"
#include "Disclaimer.h"

#include <stdio.h>
#include <Windows.h>

int main(int argc, char* argv[]) {
    if (!showDisclaimer()) {
        printf("Terms not accepted. Exiting...\n");
        return 1;
    }

    // Check if arguments are provided
    if (argc != 1) {
        printf("Usage: %s\n", argv[0]);
        printf("Please select mode when prompted.\n");
        return 1;
    }

    IatCamouflage();

    // Get operation mode from user
    printf("\nSelect operation mode:\n");
    printf("1. Blind mode (Clear callbacks and save state)\n");
    printf("2. Restore mode (Restore previous state)\n");
    printf("\nEnter choice (1/2): ");

    char choice;
    scanf_s(" %c", &choice, 1);
    while (getchar() != '\n');

    // Initialize system context
    if (!NyxInitializeContext()) {
        printf("Failed to initialize system context\n");
        return 1;
    }

    int result = 0;
    __try {
        switch (choice) {
        case '1':
            // Backup mode
            if (!BlindEdr()) {
                result = 1;
            }
            break;

        case '2':
            // Restore mode
            if (!restoreBlindness()) {
                printf("Failed to restore system state\n");
                result = 1;
            }
            break;

        default:
            printf("Invalid choice: %c\n", choice);
            result = 1;
            break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("Exception occurred: 0x%x\n", GetExceptionCode());
        result = 1;
    }

    return result;
}

