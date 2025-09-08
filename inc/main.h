#pragma once
#include <windows.h>

/*
1. (0x1000 - 1)
	0x0FFF
	Bitmask for the lowest 12 bits.

2. (0x1003) & (0x0FFF)
	0x0003
	Offset within the current page.

3. (0x1000 - 0x0003)
	0x0FFD
	We need to add 4093 bytes to reach the next page boundary.

4. (0x0FFD % 0x1000)
	If we get 0, it means we are already aligned, otherwise we need to add a certain amount to reach the next page.

5. (0x1003) + (0x0FFD)
	0x2000
	Reaching the next page boundary.
*/
#define SIZE_OF_PAGE 0x1000
#define PAGE_ALIGN(x) (((ULONG_PTR)x) + ((SIZE_OF_PAGE - (((ULONG_PTR)x) & (SIZE_OF_PAGE - 1))) % SIZE_OF_PAGE))

#define MAX_LIB_NAME_SIZE 64
#define IMP_FUNC_PREFIX_LEN 6

typedef struct _SECTION_MAP {
	PVOID addr;
	ULONG size;
} SECTION_MAP, * PSECTION_MAP;

typedef struct _OBJECT_CTX {
	ULONG_PTR objectFileAddr; // Raw in memory.

	PVOID memoryAddr;
	ULONG size;

	PIMAGE_SYMBOL imageSymbol; // Symbol table.
	PIMAGE_FILE_HEADER fileHeader;
	PIMAGE_SECTION_HEADER sectionHeader;
	
	PVOID* symbolMapAddr; // Symbol function array.

	// The sections array.
	// Contains the base address and size of the copied section in the newly allocated memory.
	PSECTION_MAP sectionMap; 
} OBJECT_CTX, * POBJECT_CTX;