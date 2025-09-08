#pragma once

#include <Windows.h>
#include <stdio.h>

typedef struct {
	// Maintains a reference to where the buffer originally began.
	char* bufferStart;
	// This is the "cursor" that moves forward as you extract data.
	char* bufferCurrent;
	// Decremented each time data is extracted.
	// Used for bounds checking to prevent reading past the end of the buffer.
	int remainingBytes;
	// The initial total size, remains constant throughout parsing.
	int totalBytes;
} dataParser;

// dataParser parser to extract arguments from the specified buffer.
void BeaconDataParse(dataParser* parser, char* buffer, int size);

// Extracts a 32-bit integer.
int BeaconDataInt(dataParser* parser);

// Extracts a 16-bit integer.
short BeaconDataShort(dataParser* parser);

// Retrieves the amount of dataParser left to parse.
int BeaconDataLength(dataParser* parser);

// Extracts a length prefixed binary blob.
// The size argument may be NULL.
// If an address is provided, the size is populated with the number of bytes extracted.
char* BeaconDataExtract(dataParser* parser, int* size);

// Printing types
#define CALLBACK_OUTPUT 0x0
#define CALLBACK_OUTPUT_OEM 0x1e
#define CALLBACK_OUTPUT_UTF8 0x20
#define CALLBACK_ERROR 0x0d

void BeaconOutput(int type, char* dataParser, int len);
void BeaconPrintf(int type, char* fmt, ...);