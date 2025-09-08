#include <windows.h>
#include <stdio.h>

#include "../inc/main.h"
#include "../inc/beaconApi.h"

/*

*/
BOOL symbolsExecution(POBJECT_CTX objectCtx, PSTR entryFuncName, PBYTE argsAddr, ULONG argsSize) {
	DWORD numberOfSymbols = objectCtx->fileHeader->NumberOfSymbols;

	for (int i = 0; i < numberOfSymbols; i++) {
		PIMAGE_SYMBOL imageSymbol = &objectCtx->imageSymbol[i];

		PSTR symbol = NULL;

		if (imageSymbol->N.Name.Short) {
			symbol = (PSTR)imageSymbol->N.ShortName;
		}
		else {
			DWORD numberOfSymbols = objectCtx->fileHeader->NumberOfSymbols;
			symbol = (PSTR)((ULONG_PTR)(objectCtx->imageSymbol + numberOfSymbols) + (ULONG_PTR)imageSymbol->N.Name.Long);
		}

		if (ISFCN(imageSymbol->Type) && strcmp(symbol, entryFuncName) == 0) {
			SHORT sectionNumber = imageSymbol->SectionNumber - 1;

			PVOID sectionAddress = objectCtx->sectionMap[sectionNumber].addr;
			ULONG sectionSize = objectCtx->sectionMap[sectionNumber].size;

			ULONG oldProtection = { 0 };
			if (!VirtualProtect(sectionAddress, sectionSize, PAGE_EXECUTE_READ, &oldProtection)) {
				printf("[!] VirtualProtect Failed with Error: %ld\n", GetLastError());
				break;
			}

			VOID(*MAIN_FUNCTION)(PBYTE, ULONG) = NULL;

			// getchar();

			MAIN_FUNCTION = (PVOID)((ULONG_PTR)sectionAddress + imageSymbol->Value);
			MAIN_FUNCTION(argsAddr, argsSize);

			if (!VirtualProtect(sectionAddress, sectionSize, oldProtection, &oldProtection)) {
				printf("[!] VirtualProtect Failed with Error: %ld\n", GetLastError());
				break;
			}

			return TRUE;
		}
	}
	return FALSE;
}

/*

*/
VOID performRelocations(WORD relocationType, PVOID relocationAddress, PVOID sectionAddress) {
	PUINT32 pReloc = (PUINT32)relocationAddress;
	ULONG_PTR target = (ULONG_PTR)sectionAddress;
	ULONG_PTR current = (ULONG_PTR)relocationAddress;

	switch (relocationType) {
	case IMAGE_REL_AMD64_REL32:
		*pReloc = (*pReloc) + (ULONG)(target - current - 4);
		break;

	case IMAGE_REL_AMD64_REL32_1:
		*pReloc = (*pReloc) + (ULONG)(target - current - 5);
		break;

	case IMAGE_REL_AMD64_REL32_2:
		*pReloc = (*pReloc) + (ULONG)(target - current - 6);
		break;

	case IMAGE_REL_AMD64_REL32_3:
		*pReloc = (*pReloc) + (ULONG)(target - current - 7);
		break;

	case IMAGE_REL_AMD64_REL32_4:
		*pReloc = (*pReloc) + (ULONG)(target - current - 8);
		break;

	case IMAGE_REL_AMD64_REL32_5:
		*pReloc = (*pReloc) + (ULONG)(target - current - 9);
		break;

	case IMAGE_REL_AMD64_ADDR64:
		*(PUINT64)relocationAddress = (*(PUINT64)relocationAddress) + (ULONG64)target;
		break;
	}
}

/*
Coming from resolveSymbol(...),
resolve the symbol by retrieving a beacon API function pointer.
*/
PVOID retrieveBeaconApiSymbols(PSTR symbolToResolve) {
	PVOID symbolResolved = { 0 };

	if (strcmp("BeaconDataParse", symbolToResolve) == 0) {
		symbolResolved = BeaconDataParse;
	}
	else if (strcmp("BeaconDataInt", symbolToResolve) == 0) {
		symbolResolved = BeaconDataInt;
	}
	else if (strcmp("BeaconDataShort", symbolToResolve) == 0) {
		symbolResolved = BeaconDataShort;
	}
	else if (strcmp("BeaconDataLength", symbolToResolve) == 0) {
		symbolResolved = BeaconDataLength;
	}
	else if (strcmp("BeaconDataExtract", symbolToResolve) == 0) {
		symbolResolved = BeaconDataExtract;
	}
	else if (strcmp("BeaconOutput", symbolToResolve) == 0) {
		symbolResolved = BeaconOutput;
	}
	else if (strcmp("BeaconPrintf", symbolToResolve) == 0) {
		symbolResolved = BeaconPrintf;
	}

	return symbolResolved;
}

/*
Coming from resolveSymbol(...),
resolve the (imported) symbol by getting a handle to a module,
and loading a function from that module.
	Note: The symbol's syntax is MODULE$function.
*/
PVOID resolveInternalExternalSymbols(PSTR symbolToResolve) {
	PCHAR dollarSignPosition = strchr(symbolToResolve, '$');

	if (!dollarSignPosition) {
		return NULL;
	}

	// Library (e.g., kernel32.dll).
	SIZE_T libraryNameLength = dollarSignPosition - symbolToResolve;
	CHAR libraryName[MAX_LIB_NAME_SIZE] = { 0 };

	memcpy(libraryName, symbolToResolve, libraryNameLength);

	HMODULE moduleHandle = GetModuleHandleA(libraryName); // Module is already loaded?

	if (!moduleHandle) {
		moduleHandle = LoadLibraryA(libraryName); // Module is not already loaded, so load it.
		if (!moduleHandle) {
			printf("[!] Module not found: %s\n", libraryName);
			return NULL;
		}
	}

	// Function (e.g., CreateFileA).
	PCHAR functionName = dollarSignPosition + 1;
	PVOID symbolResolved = (PVOID)GetProcAddress(moduleHandle, functionName);

	if (!symbolResolved) {
		printf("[!] Function not found inside of %s: %s\n", libraryName, functionName);
		return NULL;
	}

	return symbolResolved;
}

/*
Check if a symbol represents a beacon API function, else directly resolve the symbol.
*/
PVOID resolveSymbol(PSTR symbolToResolve) {
	PVOID symbolResolved = { 0 };

	if (!symbolToResolve) {
		return NULL;
	}

	symbolToResolve += IMP_FUNC_PREFIX_LEN; // Pass the prefix __imp_ for 64-bit.

	// Check if it's an imported Beacon API.
	if (strncmp("Beacon", symbolToResolve, 6) == 0) {
		symbolResolved = retrieveBeaconApiSymbols(symbolToResolve);
	}
	else { // Resolve if it's an internal or external function.
		symbolResolved = resolveInternalExternalSymbols(symbolToResolve);
	}

	printf(" -> %s @ %p\n", symbolToResolve, symbolResolved);

	return symbolResolved;
}

/*

*/
BOOL processSections(POBJECT_CTX objectCtx) {
	WORD numberOfSections = objectCtx->fileHeader->NumberOfSections;
	PIMAGE_RELOCATION imageRelocation = NULL;
	ULONG functionIndex = 0;
	
	for (int i = 0; i < numberOfSections; i++) {
		DWORD pointerToRelocations = objectCtx->sectionHeader[i].PointerToRelocations;
		imageRelocation = (PIMAGE_RELOCATION)(objectCtx->objectFileAddr + pointerToRelocations);

		DWORD numberOfRelocations = objectCtx->sectionHeader[i].NumberOfRelocations;
		for (int j = 0; j < numberOfRelocations; j++) {
			DWORD symbolTableIndex = imageRelocation->SymbolTableIndex;
			PIMAGE_SYMBOL imageSymbol = &objectCtx->imageSymbol[symbolTableIndex];

			PSTR symbol = NULL;

			if (imageSymbol->N.Name.Short) {
				symbol = (PSTR)imageSymbol->N.ShortName;
			}
			else {
				DWORD numberOfSymbols = objectCtx->fileHeader->NumberOfSymbols;
				symbol = (PSTR)((ULONG_PTR)(objectCtx->imageSymbol + numberOfSymbols) + (ULONG_PTR)imageSymbol->N.Name.Long);
			}

			PVOID relocationAddress = (PVOID)((ULONG_PTR)objectCtx->sectionMap[i].addr + imageRelocation->VirtualAddress);
			PVOID symbolResolved = NULL;

			if (strncmp("__imp_", symbol, IMP_FUNC_PREFIX_LEN) == 0) {
				symbolResolved = resolveSymbol(symbol);
				if (!symbolResolved) {
					printf("[!] resolveSymbol failed to resolve symbol: %s\n", symbol);
					return FALSE;
				}
			}

			// symbolResolved is set if it's an imported function.
			if (imageRelocation->Type == IMAGE_REL_AMD64_REL32 && symbolResolved) {
				objectCtx->symbolMapAddr[functionIndex] = symbolResolved;
				ULONG_PTR symbolMapAddress = (ULONG_PTR)&objectCtx->symbolMapAddr[functionIndex];
				
				// Instruction Pointer (IP) offset: [CALL][OFFSET]
				// ULONG_PTR ripOffset = (ULONG_PTR)relocationAddress - sizeof(UINT32);
 
				PUINT32 pRelocationAddress = (PUINT32)relocationAddress;
				*pRelocationAddress = (UINT32)(symbolMapAddress - (ULONG_PTR)relocationAddress - sizeof(UINT32));

				functionIndex++;
			}
			else {
				// -1 because our SECTION_MAP array starts from 0, 
				// but the SectionNumber from IMAGE_SYMBOL starts from 1.
				SHORT sectionNumber = imageSymbol->SectionNumber - 1;
				PVOID sectionAddress = objectCtx->sectionMap[sectionNumber].addr;

				WORD relocationType = imageRelocation->Type;

				performRelocations(relocationType, relocationAddress, sectionAddress);
			}

			imageRelocation = (PVOID)((ULONG_PTR)imageRelocation + sizeof(IMAGE_RELOCATION));
		}
	}

	return TRUE;
}

/*
Copy the object file's section into the allocated virtual memory region (given by allocateMemory(...))
*/
BOOL copySectionsInMemory(POBJECT_CTX objectCtx) {
	WORD numberOfSections = objectCtx->fileHeader->NumberOfSections;

	PVOID memoryAddr = objectCtx->memoryAddr;

	for (int i = 0; i < numberOfSections; i++) {
		DWORD sizeOfRawData = objectCtx->sectionHeader[i].SizeOfRawData;

		objectCtx->sectionMap[i].addr = memoryAddr;
		objectCtx->sectionMap[i].size = sizeOfRawData;
		
		DWORD pointerToRawData = objectCtx->sectionHeader[i].PointerToRawData;

		memcpy(
			memoryAddr,
			(PVOID)(objectCtx->objectFileAddr + (ULONG_PTR)pointerToRawData),
			sizeOfRawData
		);

		printf(" -> %-8s @ %p [%ld bytes]\n", (PSTR)objectCtx->sectionHeader[i].Name, memoryAddr, sizeOfRawData);

		memoryAddr = (PVOID)PAGE_ALIGN(((ULONG_PTR)memoryAddr + (ULONG)sizeOfRawData));
	}

	objectCtx->symbolMapAddr = memoryAddr;

	return TRUE;
}

/*
Handy function to allocate virtual memory to store an array of SECTION_MAP structure.
	Note: The size of the array is the number of sections in the object file.
*/
BOOL sectionMapsMemoryAllocation(POBJECT_CTX objectCtx) {
	WORD sectionMaps = objectCtx->fileHeader->NumberOfSections * sizeof(SECTION_MAP);
	objectCtx->sectionMap = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sectionMaps);

	if (!objectCtx->sectionMap) {
		printf("[!] HeapAlloc Failed with Error: %ld\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

/*
Find the size of the raw object file's sections and imported symbols (i.e., starts with __imp_).
*/
ULONG objectVirtualSize(POBJECT_CTX objectCtx) {
	ULONG alignedSizeOfRawData = 0;
	WORD numberOfSections = objectCtx->fileHeader->NumberOfSections;

	for (int i = 0; i < numberOfSections; i++) {
		DWORD sizeOfRawData = objectCtx->sectionHeader[i].SizeOfRawData;
		alignedSizeOfRawData += PAGE_ALIGN(sizeOfRawData);
	}

	PIMAGE_RELOCATION imageRelocation = NULL;

	for (int i = 0; i < numberOfSections; i++) {
		DWORD pointerToRelocations = objectCtx->sectionHeader[i].PointerToRelocations;
		imageRelocation = (PIMAGE_RELOCATION)(objectCtx->objectFileAddr + pointerToRelocations);

		DWORD numberOfRelocations = objectCtx->sectionHeader[i].NumberOfRelocations;

		for (int j = 0; j < numberOfRelocations; j++) {
			DWORD symbolTableIndex = imageRelocation->SymbolTableIndex;
			PIMAGE_SYMBOL imageSymbol = &objectCtx->imageSymbol[symbolTableIndex];

			PSTR symbol = NULL;

			if (imageSymbol->N.Name.Short) {
				symbol = (PSTR)imageSymbol->N.ShortName;
			}
			else {
				DWORD numberOfSymbols = objectCtx->fileHeader->NumberOfSymbols;
				symbol = (PSTR)((ULONG_PTR)(objectCtx->imageSymbol + numberOfSymbols) + (ULONG_PTR)imageSymbol->N.Name.Long);
			}

			if (strncmp("__imp_", symbol, IMP_FUNC_PREFIX_LEN) == 0) {
				alignedSizeOfRawData += sizeof(PVOID);
			}

			imageRelocation = (PVOID)((ULONG_PTR)imageRelocation + sizeof(IMAGE_RELOCATION));
		}	
	}

	return PAGE_ALIGN(alignedSizeOfRawData);
}

/*
Allocate a virtual memory the size of the raw object file's sections and imported symbols.
*/
BOOL allocateMemory(POBJECT_CTX objectCtx) {
	objectCtx->size = objectVirtualSize(objectCtx);

	printf("[*] Virtual Size [%d bytes]\n", objectCtx->size);
	objectCtx->memoryAddr = VirtualAlloc(NULL, objectCtx->size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (!objectCtx->memoryAddr) {
		printf("[!] VirtualAlloc Failed with Error: %ld\n", GetLastError());
		goto _END_OF_FUNC;
	}

	printf("[*] Allocated object file @ %p [%ld bytes]\n", objectCtx->memoryAddr, objectCtx->size);

	return TRUE;

_END_OF_FUNC:
	if (objectCtx->memoryAddr) {
		VirtualFree(objectCtx->memoryAddr, 0, MEM_RELEASE);
		objectCtx->memoryAddr = NULL;
	}

	return FALSE;
}

/*
Act as a mini-linker performing operations to load an raw object file (already from virtual memory).
*/
BOOL objectLoader(PVOID objectFileAddr, PSTR entryFuncName, PBYTE argsAddr, ULONG argsSize) {
	OBJECT_CTX objectCtx = { 0 };

	objectCtx.objectFileAddr = objectFileAddr;

	objectCtx.fileHeader = (PIMAGE_FILE_HEADER)objectFileAddr;
	WORD arch = objectCtx.fileHeader->Machine;
	
	if (arch != IMAGE_FILE_MACHINE_AMD64) {
		printf("[*] Object file is not 64-bit");
		exit(1);
	}

	DWORD pointerToSymbolTable = objectCtx.fileHeader->PointerToSymbolTable;
	objectCtx.imageSymbol = (PIMAGE_SYMBOL)(objectCtx.objectFileAddr + (ULONG_PTR)pointerToSymbolTable);

	printf("[*] First imageSymbol: %p\n", objectCtx.imageSymbol);

	objectCtx.sectionHeader = (PIMAGE_SECTION_HEADER)(objectCtx.objectFileAddr + sizeof(IMAGE_FILE_HEADER));

	allocateMemory(&objectCtx);
	sectionMapsMemoryAllocation(&objectCtx);
	copySectionsInMemory(&objectCtx);
	
	processSections(&objectCtx);
	symbolsExecution(&objectCtx, entryFuncName, argsAddr, argsSize);

	return TRUE;
}

/*
Read a raw object file from disk, and put it into virtual memory.
*/
BOOL ReadFileFromDisk(LPCSTR objectFileName, PBYTE* objectFileAddr, PDWORD objectFileSize) {
	LPVOID _objectFileAddr = NULL;

	HANDLE handle = CreateFileA(objectFileName, GENERIC_READ, 0x00, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (handle == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed With Error: %ld \n", GetLastError());
		goto _END_OF_FUNC;
	}

	DWORD _objectFileSize = GetFileSize(handle, NULL);
	if (_objectFileSize == INVALID_FILE_SIZE) {
		printf("[!] GetFileSize Failed With Error: %ld \n", GetLastError());
		goto _END_OF_FUNC;
	}

	_objectFileAddr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, _objectFileSize);
	if (!_objectFileAddr) {
		printf("[!] HeapAlloc Failed With Error: %ld \n", GetLastError());
		goto _END_OF_FUNC;
	}

	DWORD numberOfBytesRead = NULL;

	BOOL isReadFile = ReadFile(handle, _objectFileAddr, _objectFileSize, &numberOfBytesRead, NULL);

	if (!isReadFile) {
		printf("[!] ReadFile Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	*objectFileSize = _objectFileSize;
	*objectFileAddr = (PBYTE)_objectFileAddr;

_END_OF_FUNC:
	if (handle != INVALID_HANDLE_VALUE) {
		CloseHandle(handle);
	}

	if (_objectFileAddr && !*objectFileAddr) {
		HeapFree(GetProcessHeap(), 0x00, _objectFileAddr);
	}

	return (*objectFileSize && *objectFileAddr) ? TRUE : FALSE;
}

int main(int argc, char** argv) {
	if (argc < 3) {
		printf("Usage: %s <object_file.o> <entry_func_name>\n", argv[0]);
		printf("Example: %s whoami.x64.o go\n", argv[0]);
		return 1;
	}

	PSTR objectFilePath = argv[1];
	PSTR entryFuncName = argv[2];

	printf("[*] Loading object file: %s\n", objectFilePath);
	printf("[*] The following entry function name will be called object file: %s\n", entryFuncName);

	PBYTE objectFileAddr = { 0 };
	ULONG objectFileSize = { 0 };

	BOOL readFileSuccess = ReadFileFromDisk(objectFilePath, (PBYTE*)&objectFileAddr, &objectFileSize);

	if (!readFileSuccess) {
		printf("[!] Failed to load file: %s\n", objectFilePath);
		goto END;
	}

	printf("[*] Object file loaded @ %p [%ld bytes]\n", objectFileAddr, objectFileSize);

	BOOL objectLoadSuccess = objectLoader(objectFileAddr, entryFuncName, NULL, 0);

	if (!objectLoadSuccess) {
		printf("[!] Failed to execute object file\n");
		goto END;
	}

	return 0;

END:
	return 1;
}