#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_INPUT_LENGTH 128
#define AES_KEY_SIZE 16  // AES-128 uses a 16-byte key.
#define AES_IV_SIZE 16   // AES uses a 16-byte IV.
#define AES_BLOCK_SIZE 16 // Defines the AES block size as 16 bytes.

// Function to handle OpenSSL errors
void handleErrors() 
{
    ERR_print_errors_fp(stderr); // Print OpenSSL errors to stderr
    exit(1); // Exit the program with an error code
}

// Function to convert hexadecimal string to binary data
int hex2bin(const char *hex, unsigned char *bin, int bin_max_len) 
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1; // Invalid hexadecimal length

    size_t bin_len = hex_len / 2;
    if (bin_len > bin_max_len) return -2; // Binary data exceeds maximum length

    for (size_t i = 0; i < bin_len; i++) 
    {
        sscanf(&hex[i * 2], "%2hhx", &bin[i]); // Convert two hexadecimal characters to a byte
    }
    return bin_len; // Return the length of binary data
}

// Function to convert binary data to hexadecimal string
void bin2hex(const unsigned char *bin, int bin_len, char *hex) 
{
    for (int i = 0; i < bin_len; i++) 
    {
        sprintf(&hex[i * 2], "%02x", bin[i]); // Format each byte as two hexadecimal characters
    }
}

// Function to encrypt plaintext
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) 
{
    // Initialize an EVP cipher context
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors(); // Initialize the cipher context

    // Set up the cipher context for AES-128 in CBC mode
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors(); // Set encryption parameters

    // Encrypt the input plaintext and store the result in the ciphertext buffer
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors(); // Encrypt the plaintext
    ciphertext_len = len; // Update ciphertext length

    // Finalize the encryption process and store any remaining ciphertext
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors(); // Finalize encryption
    ciphertext_len += len; // Update ciphertext length

    // Free the allocated EVP cipher context
    EVP_CIPHER_CTX_free(ctx);

    // Return the total length of the ciphertext
    return ciphertext_len;
}

// Function to decrypt ciphertext
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) 
{
    // Create an encryption context
    EVP_CIPHER_CTX *ctx;
    
    // Variables to store lengths
    int len;
    int plaintext_len;

    // Initialize the encryption context
    if (!(ctx = EVP_CIPHER_CTX_new())) 
        handleErrors();  // Error handling function

    // Set up decryption parameters (AES-128 in CBC mode)
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();  // Handle errors if decryption initialization fails

    // Update the context with the encrypted data
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();  // Handle errors during the decryption process
    plaintext_len = len;

    // Finalize the decryption process, handling any remaining data
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) 
        handleErrors();  // Handle errors during the finalization
    plaintext_len += len;

    // Free the encryption context
    EVP_CIPHER_CTX_free(ctx);

    // Return the length of the decrypted plaintext
    return plaintext_len;
}

int main(void) 
{
    unsigned char key[AES_KEY_SIZE], iv[AES_IV_SIZE];
    unsigned char input[MAX_INPUT_LENGTH], output[MAX_INPUT_LENGTH + AES_BLOCK_SIZE];
    char hex_output[2 * sizeof(output) + 1];
    char action;

    // Prompt the user to choose encryption or decryption
    printf("Do you want to encrypt (e) or decrypt (d)? ");
    if (scanf(" %c", &action) != 1) 
    {
        handleErrors(); // Handle input error
    }

    getchar(); // Remove newline from input buffer

    if (action == 'e') 
    {
        // Generate random key and IV
        if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) 
        {
            handleErrors(); // Handle error generating random bytes
        }

        // Read plaintext from user
        printf("Enter the plaintext to encrypt: ");
        if (fgets((char *)input, MAX_INPUT_LENGTH, stdin) == NULL) 
        {
            handleErrors(); // Handle input error
        }
        input[strcspn((char *)input, "\n")] = 0; // Remove newline

        int input_len = strlen((char *)input);
        int ciphertext_len = encrypt(input, input_len, key, iv, output);

        // Print key, IV, and ciphertext in hexadecimal format
        printf("Key: ");
        bin2hex(key, sizeof(key), hex_output);
        printf("%s\n", hex_output);

        printf("IV: ");
        bin2hex(iv, sizeof(iv), hex_output);
        printf("%s\n", hex_output);

        printf("Ciphertext: ");
        bin2hex(output, ciphertext_len, hex_output);
        printf("%s\n", hex_output);
    } 
    else if (action == 'd') 
    {
        // Prompt for key, IV, and ciphertext in hexadecimal format
        printf("Enter the key in hex: ");
        scanf("%64s", hex_output);
        if (hex2bin(hex_output, key, sizeof(key)) != AES_KEY_SIZE) 
        {
            fprintf(stderr, "Invalid key.\n");
            return 1;
        }

        printf("Enter the IV in hex: ");
        scanf("%64s", hex_output);
        if (hex2bin(hex_output, iv, sizeof(iv)) != AES_IV_SIZE) 
        {
            fprintf(stderr, "Invalid IV.\n");
            return 1;
        }

        printf("Enter the ciphertext in hex: ");
        scanf("%256s", hex_output);
        int output_len = hex2bin(hex_output, output, sizeof(output));
        if (output_len < 0) 
        {
            fprintf(stderr, "Invalid ciphertext.\n");
            return 1;
        }

        // Decrypt ciphertext and print decrypted plaintext
        int plaintext_len = decrypt(output, output_len, key, iv, input);
        input[plaintext_len] = '\0'; // Null-terminate the decrypted string
        printf("Decrypted text: %s\n", input);
    } 
    else 
    {
        fprintf(stderr, "Invalid action.\n");
        return 1;
    }

    return 0;
}
