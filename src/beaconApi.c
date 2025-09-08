#include "../inc/beaconApi.h"

void BeaconDataParse(dataParser* dataParser, char* bufferCurrent, int size) {
	if (dataParser == NULL) {
		return;
	}

	dataParser->bufferStart = bufferCurrent;
	dataParser->bufferCurrent = bufferCurrent + 4; // 4-bytes' CS metadata (0xBEEF) magic number

	dataParser->remainingBytes = size - 4;
	dataParser->totalBytes = size - 4;
}

int BeaconDataInt(dataParser* dataParser) {
	int fourBytesValue = 0;

	if (dataParser->remainingBytes < 4) {
		return 0;
	}

	memcpy(&fourBytesValue, dataParser->bufferCurrent, 4);

	dataParser->bufferCurrent += 4;
	dataParser->remainingBytes -= 4;

	return fourBytesValue;
}

short BeaconDataShort(dataParser* dataParser) {
	short twoBytesValue = 0;

	if (dataParser->remainingBytes < 2) {
		return 0;
	}

	memcpy(&twoBytesValue, dataParser->bufferCurrent, 2);

	dataParser->bufferCurrent += 2;
	dataParser->remainingBytes -= 2;

	return twoBytesValue;
}

int BeaconDataLength(dataParser* dataParser) {
	return dataParser->remainingBytes;
}

char* BeaconDataExtract(dataParser* dataParser, int* size) {
	int remainingBytes = 0;
	char* extractedData = NULL;

	// remainingBytes prefixed binary blob, going to assume uint32_t for this.
	if (dataParser->remainingBytes < 4) {
		return NULL;
	}

	memcpy(&remainingBytes, dataParser->bufferCurrent, 4);

	dataParser->bufferCurrent += 4;
	extractedData = dataParser->bufferCurrent;

	if (extractedData == NULL) {
		return NULL;
	}

	dataParser->remainingBytes -= 4;

	dataParser->remainingBytes -= remainingBytes;
	dataParser->bufferCurrent += remainingBytes;

	if (size != NULL && extractedData != NULL) {
		*size = remainingBytes;
	}

	return extractedData;
}

void BeaconOutput(int type, char* data, int len) {
	puts(data);
}

void BeaconPrintf(int type, char* format, ...) {
	va_list vaList = { 0 }; // Pointer to an array of arguments.
	va_start(vaList, format); // Initializes the va_list to point to the first variable argument.

	// printf-like function that accepts a va_list instead of individual arguments.
	// It processes the format string and uses the va_list to access each argument as needed.
	vprintf(format, vaList);
	va_end(vaList); // Cleans up the va_list. It's required for proper cleanup.
}