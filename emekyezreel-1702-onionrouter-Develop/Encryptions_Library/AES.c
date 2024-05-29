#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#define AES_BLOCK_SIZE 16
#define AES_NUMBER_OF_ROUNDS 10 // Number of rounds for AES-128

static unsigned char substituteByte(unsigned char byte);
static unsigned char invSubstituteByte(unsigned char byte);
static void substituteBlock(unsigned char* block, int blockSize);
static void invSubstituteBlock(unsigned char* block, int blockSize);
static void g(char* word, int round);
static void expand_key(char key[], char* keys);
static void addRoundKey(char* block, const char* roundKey);
static void shiftRows(char* block);
static unsigned char galMul2(unsigned char a);
static unsigned char galMul3(unsigned char a);
static void mixColumns(char* block);
static void addPadding(char* message, int* length);
static void removePadding(char* data, int* length);
static void inverseShiftRow(char* block);
static unsigned char galMul(unsigned char a, unsigned char n);
static void InvMixColumns(char* block);
char* AES_encrypt(unsigned char* text, char* key, int len);
char* AES_decrypt(unsigned char* text, char* key, int len);

const unsigned char sBox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};
const unsigned char invSBox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};
const unsigned char Rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

// get a byte and return the byte it should be substitute to
static unsigned char substituteByte(unsigned char byte) 
{
    return sBox[byte];
}

static unsigned char invSubstituteByte(unsigned char byte)
{
    return invSBox[byte];
}
/*
get a block of bytes and substitute each byte by the substitution Box
*/
static void substituteBlock(unsigned char* block, int blockSize)
{
    int i;
    for (i = 0; i < blockSize; i++)
    {
        block[i] = substituteByte(block[i]);
    }
}

static void invSubstituteBlock(unsigned char* block, int blockSize)
{
    int i;
    for (i = 0; i < blockSize; i++)
    {
        block[i] = invSubstituteByte(block[i]);
    }
}

/*
implement the g function for the aes expanding key
*/
static void g(char* word, int round)
{
    int i;
	// Shift each character to the left
	char temp = word[0];
	for (i = 0; i < 3; i++) 
	{
		word[i] = word[i + 1];
	}
	word[3] = temp;

    //substitue each byte by the substitution Box
    substituteBlock(word, 4);

    // xor with round constant
    word[0] ^= Rcon[round];
}

/*
expand the origin aes key
*/
static void expand_key(char key[], char* keys)
{
    int i = 0, j = 0;
    char temp[4];
    memcpy(keys, key, 16);

    for (i = 4; i < 4 * 11; i++)
    {
        memcpy(temp, keys + (i - 1) * 4, 4);

        if (i % 4 == 0)
        {
            g(temp, i / 4 - 1);
        }

        for (j = 0; j < 4; j++)
        {
            keys[i * 4 + j] = keys[(i - 4) * 4 + j] ^ temp[j];
        }
    }
}

/*
Encryption
*/

/*
XOR the block with the round key
*/
static void addRoundKey(char* block, const char* roundKey)
{
    int col, row;
    for (col = 0; col < 4; col++) 
    {
        for (row = 0; row < 4; row++) 
        {
            block[col * 4 + row] ^= roundKey[col * 4 + row];
        }
    }
}


/*
this function should shift the rows
for an expected result like this:
 | 0 4 8 12  | 0 4 8 12
 | 1 5 9 13  | 5 9 13 1
 | 2 6 10 14 | 10 14 2 6
 | 3 7 11 15 | 15 3 7 11
*/

static void shiftRows(char* block)
{
    int row, shift, col;
    for (row = 1; row < 4; row++)
    {
        for (shift = 0; shift < row; shift++)
        {
            // Perform left shift
            char temp = block[row];
            for (col = row; col < 16; col += 4)
            {
                block[col] = block[col + 4];
            }
            block[row + 12] = temp;
        }
    }
}

static unsigned char galMul2(unsigned char a)
{
    return (a << 1) ^ ((a & 0x80) ? 0x1B : 0x00);
}

static unsigned char galMul3(unsigned char a) 
{
    return galMul2(a) ^ a;
}

/*
multipling the block with metrix:
2 3 1 1
1 2 3 1
1 1 2 3
3 1 1 2
*/
static void mixColumns(char* block) 
{
    int col, i;
    unsigned char tmp[16];

    for (col = 0; col < 4; col++) 
    {
        int i = col * 4; // Starting index of the column
        tmp[i] = galMul2(block[i]) ^ galMul3(block[i + 1]) ^ block[i + 2] ^ block[i + 3];
        tmp[i + 1] = block[i] ^ galMul2(block[i + 1]) ^ galMul3(block[i + 2]) ^ block[i + 3];
        tmp[i + 2] = block[i] ^ block[i + 1] ^ galMul2(block[i + 2]) ^ galMul3(block[i + 3]);
        tmp[i + 3] = galMul3(block[i]) ^ block[i + 1] ^ block[i + 2] ^ galMul2(block[i + 3]);
    }

    // Copy the result back to the block
    for (i = 0; i < 16; i++) 
    {
        block[i] = tmp[i];
    }
}

static void addPadding(char* message, int* length) 
{                   
    int i;
    if (*length % 16 == 0)
    {
        return;
    }

    int padding = AES_BLOCK_SIZE - (*length % AES_BLOCK_SIZE);

    for (i = 0; i < padding; i++)
    {
        message[*length + i] = (char)padding;
    }

    *length += padding;
}

// Function to unpad the decrypted data
static void removePadding(char* data, int* length) 
{
    int i = 0;
    if (*length == 0) 
    {
        return;
    }

    unsigned char last_byte = data[*length - 1];

    // Check if the padding is valid
    if (last_byte <= *length) 
    {
        for (i = *length - last_byte; i < *length; i++) 
        {
            if (data[i] != last_byte)
            {
                // Invalid padding
                return;
            }
        }

        // Valid padding, update the length
        *length -= last_byte;
    }
}

/*
inversing shift rows is the same as doing it tree times
*/
static void inverseShiftRow(char* block)
{
    shiftRows(block);
    shiftRows(block);
    shiftRows(block);
}

static unsigned char galMul(unsigned char a, unsigned char n) 
{
    int i;
    unsigned char result = 0;
    for (i = 0; i < 8; ++i)
    {
        if ((n & 1) == 1)
        {
            result ^= a;
        }
        unsigned char high_bit = a & 0x80;
        a <<= 1;
        if (high_bit == 0x80) {
            a ^= 0x1B;  // This corresponds to the irreducible polynomial for AES
        }
        n >>= 1;
    }
    return result;
}

static void InvMixColumns(char* block)
{
    int col, i;
    unsigned char tmp[16];

    for (col = 0; col < 4; col++)
    {
        int i = col * 4; // Starting index of the column
        tmp[i] = galMul(block[i], 0x0E) ^ galMul(block[i + 1], 0x0B) ^ galMul(block[i + 2], 0x0D) ^ galMul(block[i + 3], 0x09);
        tmp[i + 1] = galMul(block[i], 0x09) ^ galMul(block[i + 1], 0x0E) ^ galMul(block[i + 2], 0x0B) ^ galMul(block[i + 3], 0x0D);
        tmp[i + 2] = galMul(block[i], 0x0D) ^ galMul(block[i + 1], 0x09) ^ galMul(block[i + 2], 0x0E) ^ galMul(block[i + 3], 0x0B);
        tmp[i + 3] = galMul(block[i], 0x0B) ^ galMul(block[i + 1], 0x0D) ^ galMul(block[i + 2], 0x09) ^ galMul(block[i + 3], 0x0E);
    }

    // Copy the result back to the block
    for (i = 0; i < 16; i++)
    {
        block[i] = tmp[i];
    }
}

char* AES_encrypt(unsigned char* text, char* key, int len)
{
    int b, round;
    // expand key to 10 round keys
    char roundKeys[176];
    expand_key(key, roundKeys);

    // add padding to the text if neccecary
    int length = len;
    char* paddedMessage = (char*)malloc(length + AES_BLOCK_SIZE);
    memcpy(paddedMessage, text, length);

    addPadding(paddedMessage, &length);

    // split the text to 16 bytes blocks to perform the encryption on each block separately
    int numBlocks = length / AES_BLOCK_SIZE;  
    char block[AES_BLOCK_SIZE];
    char* encryptedMessage = (char*)malloc(length);

    for (b = 0; b < numBlocks; b++)
    {
        memcpy(block, paddedMessage + (b * AES_BLOCK_SIZE), AES_BLOCK_SIZE);
        addRoundKey(block, roundKeys); // Initial round key addition

        // repete the same steps for each round key
        for (round = 1; round < AES_NUMBER_OF_ROUNDS; round++)
        {
            substituteBlock(&block, AES_BLOCK_SIZE);
            shiftRows(&block);
            mixColumns(&block);
            addRoundKey(&block, roundKeys + round * AES_BLOCK_SIZE);
        }

        // in the final time we skip the mix columns step
        substituteBlock(&block, AES_BLOCK_SIZE);
        shiftRows(&block);
        addRoundKey(&block, roundKeys + AES_NUMBER_OF_ROUNDS * AES_BLOCK_SIZE);

        memcpy(encryptedMessage + b * AES_BLOCK_SIZE, block, AES_BLOCK_SIZE);
    }
    free(paddedMessage);
    return encryptedMessage;
}

char* AES_decrypt(unsigned char* text, char* key, int len)
{
    int b, round, i;
    // expand key to 10 round keys
    char roundKeys[176];
    expand_key(key, roundKeys);

    int length = len;
    char* message = (char*)malloc(length + AES_BLOCK_SIZE);
    memcpy(message, text, len);
    
    // split the text to 16 bytes blocks to perform the encryption on each block separately
    int numBlocks = length / AES_BLOCK_SIZE;

    char block[AES_BLOCK_SIZE];
    char* decryptedMessage = (char*)malloc(length + 1);

    for (b = 0; b < numBlocks; b++)
    {
        memcpy(block, message + (b * AES_BLOCK_SIZE), AES_BLOCK_SIZE);
        addRoundKey(block, roundKeys + AES_NUMBER_OF_ROUNDS * AES_BLOCK_SIZE); // Initial round key addition
        // repete the same steps for each round key
        for (round = AES_NUMBER_OF_ROUNDS; round > 1; round--)
        {
            inverseShiftRow(&block);
            invSubstituteBlock(&block, AES_BLOCK_SIZE);
            addRoundKey(&block, roundKeys + (round - 1) * AES_BLOCK_SIZE);
            InvMixColumns(&block);
        }

        // in the final time we skip the mix columns step
        inverseShiftRow(&block);
        invSubstituteBlock(&block, AES_BLOCK_SIZE);
        addRoundKey(&block, roundKeys);

        memcpy(decryptedMessage + b * AES_BLOCK_SIZE, block, AES_BLOCK_SIZE);
    }
    free(message);
    //removePadding(decryptedMessage, &length);
    //decryptedMessage[length] = '\0';
    return decryptedMessage;
}
