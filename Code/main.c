/*
 * Advanced Encryption Standard
 * Based on the document FIPS PUB 197
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "aes.h"

int main() {

	char *inputMessage = NULL;
    size_t bufsize = 0;
    ssize_t messageLen;
    uint8_t *plainBuffer;
    uint8_t *cipherBuffer;
    uint8_t *decryptedBuffer;
    size_t numBlocks, paddedSize;
    size_t i, j;

    // Fixed 256-bit key (example key)
    uint8_t key[] = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f
    };

    // Prompt the user for an arbitrarily long message.
    printf("Enter your message:\n");
    messageLen = getline(&inputMessage, &bufsize, stdin);
    if (messageLen < 0) {
        fprintf(stderr, "Error reading the message.\n");
        free(inputMessage);
        return 1;
    }
    // Remove newline character if present.
    if (inputMessage[messageLen - 1] == '\n') {
        inputMessage[messageLen - 1] = '\0';
        messageLen--;
    }

    // Calculate number of 16-byte blocks needed and padded size.
    numBlocks = (messageLen + 15) / 16;
    paddedSize = numBlocks * 16;

    // Allocate buffers for processing.
    plainBuffer = calloc(paddedSize, 1);
    cipherBuffer = malloc(paddedSize);
    decryptedBuffer = malloc(paddedSize);
    if (!plainBuffer || !cipherBuffer || !decryptedBuffer) {
        fprintf(stderr, "Memory allocation error.\n");
        free(inputMessage);
        free(plainBuffer);
        free(cipherBuffer);
        free(decryptedBuffer);
        return 1;
    }

    // Copy the input message into the plainBuffer and zero pad.
    memcpy(plainBuffer, inputMessage, messageLen);

    // Initialize the expanded key.
    uint8_t *expandedKey = aes_init(sizeof(key));
    aes_key_expansion(key, expandedKey);

    // Encrypt each 16-byte block.
    for (i = 0; i < numBlocks; i++) {
        aes_cipher(plainBuffer + (i * 16), cipherBuffer + (i * 16), expandedKey);
    }

    // Display the cipher text in hexadecimal.
    printf("\nEncrypted cipher text (hex):\n");
    for (i = 0; i < paddedSize; i++) {
        printf("%02x ", cipherBuffer[i]);
        if ((i+1) % 16 == 0)
            printf("\n");
    }

    // Decrypt each 16-byte block.
    for (i = 0; i < numBlocks; i++) {
        aes_inv_cipher(cipherBuffer + (i * 16), decryptedBuffer + (i * 16), expandedKey);
    }

    // Display the decrypted plain text (only the original message length).
    printf("\nDecrypted plain text:\n");
    for (i = 0; i < messageLen; i++) {
        printf("%c", decryptedBuffer[i]);
    }
    printf("\n");

    // Cleanup.
    free(inputMessage);
    free(plainBuffer);
    free(cipherBuffer);
    free(decryptedBuffer);
    free(expandedKey);

    return 0;
}
