#include <stdio.h>
#include <stdlib.h>
#include "tables.h"
#include <string.h>

#define len(x) (sizeof(x) / sizeof(x[0]))

void keyex_core(unsigned char *in, unsigned char i)
{
    //rotate left
    unsigned char tmp = in[0];
    in[0] = in[1];
    in[1] = in[2];
    in[2] = in[3];
    in[3] = tmp;
    //sbox
    in[0] = sbox[in[0]];
    in[1] = sbox[in[1]];
    in[2] = sbox[in[2]];
    in[3] = sbox[in[3]];

    in[0] ^= rcon[i];
}

void key_expansion(unsigned char *key, unsigned char *expanded, int aes_keylen)
{

    unsigned char temp[4];
    /* c is 16 because the first sub-key is the user-supplied key */

    unsigned char c; //byte
    int c_count;
    unsigned char i = 1; //rcon iter
    int bytesize;
    unsigned char a;

    if (aes_keylen == 128)
    {
        c_count = 16;
        c = 16; //byte
        bytesize = 176;
    }
    else if (aes_keylen == 192)
    {
        c_count = 24;
        c = 24; //byte
        bytesize = 208;
    }
    else if (aes_keylen == 256)
    {
        c_count = 32;
        c = 32; //byte
        bytesize = 240;
    }

    for (int j = 0; j < c_count; j++)
    {
        expanded[j] = key[j];
    }

    while (c < bytesize)
    {
        /* Copy the temporary variable over from the last 4-byte
                 * block */
        for (a = 0; a < 4; a++)
            temp[a] = expanded[a + c - 4];

        if (c % c_count == 0)
        {
            keyex_core(temp, i);
            i++;
        }

        if (aes_keylen == 256)
        {
            if (c % c_count == 16)
            {
                for (a = 0; a < 4; a++)
                    temp[a] = sbox[temp[a]];
            }
        }

        for (a = 0; a < 4; a++)
        {
            expanded[c] = expanded[c - c_count] ^ temp[a];
            c++;
        }
    }
}

void sub_bytes(unsigned char *state)
{
    for (int i = 0; i < 16; i++)
    {
        state[i] = sbox[state[i]];
    }
}

void shift_rows(unsigned char *state)
{
    unsigned char tmp[16];

    tmp[0] = state[0];
    tmp[1] = state[5];
    tmp[2] = state[10];
    tmp[3] = state[15];
    tmp[4] = state[4];
    tmp[5] = state[9];
    tmp[6] = state[14];
    tmp[7] = state[3];
    tmp[8] = state[8];
    tmp[9] = state[13];
    tmp[10] = state[2];
    tmp[11] = state[7];
    tmp[12] = state[12];
    tmp[13] = state[1];
    tmp[14] = state[6];
    tmp[15] = state[11];

    for (int i = 0; i < 16; i++)
        state[i] = tmp[i];
}

void mix_columns(unsigned char *state)
{
    unsigned char tmp[16];
    tmp[0] = (unsigned char)(mul2[state[0]] ^ mul3[state[1]] ^ state[2] ^ state[3]);
    tmp[1] = (unsigned char)(state[0] ^ mul2[state[1]] ^ mul3[state[2]] ^ state[3]);
    tmp[2] = (unsigned char)(state[0] ^ state[1] ^ mul2[state[2]] ^ mul3[state[3]]);
    tmp[3] = (unsigned char)(mul3[state[0]] ^ state[1] ^ state[2] ^ mul2[state[3]]);

    tmp[4] = (unsigned char)(mul2[state[4]] ^ mul3[state[5]] ^ state[6] ^ state[7]);
    tmp[5] = (unsigned char)(state[4] ^ mul2[state[5]] ^ mul3[state[6]] ^ state[7]);
    tmp[6] = (unsigned char)(state[4] ^ state[5] ^ mul2[state[6]] ^ mul3[state[7]]);
    tmp[7] = (unsigned char)(mul3[state[4]] ^ state[5] ^ state[6] ^ mul2[state[7]]);

    tmp[8] = (unsigned char)(mul2[state[8]] ^ mul3[state[9]] ^ state[10] ^ state[11]);
    tmp[9] = (unsigned char)(state[8] ^ mul2[state[9]] ^ mul3[state[10]] ^ state[11]);
    tmp[10] = (unsigned char)(state[8] ^ state[9] ^ mul2[state[10]] ^ mul3[state[11]]);
    tmp[11] = (unsigned char)(mul3[state[8]] ^ state[9] ^ state[10] ^ mul2[state[11]]);

    tmp[12] = (unsigned char)(mul2[state[12]] ^ mul3[state[13]] ^ state[14] ^ state[15]);
    tmp[13] = (unsigned char)(state[12] ^ mul2[state[13]] ^ mul3[state[14]] ^ state[15]);
    tmp[14] = (unsigned char)(state[12] ^ state[13] ^ mul2[state[14]] ^ mul3[state[15]]);
    tmp[15] = (unsigned char)(mul3[state[12]] ^ state[13] ^ state[14] ^ mul2[state[15]]);

    for (int i = 0; i < 16; i++)
        state[i] = tmp[i];
}
void add_round_key(unsigned char *state, const unsigned char *roundKey)
{
    for (int i = 0; i < 16; i++)
    {
        state[i] ^= roundKey[i];
    }
}

void aes_encrypt_body(const unsigned char *plaintext, unsigned char *key, int rounds, unsigned char *state)
{
    for (int i = 0; i < 16; i++)
        state[i] = plaintext[i];

    add_round_key(state, key);

    int i;
    for (i = 0; i < rounds; i++)
    {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, key + 16 * (i + 1));
    }

    //last round without mix_columns
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, key + 16 * (rounds + 1));
}

void aes_encrypt(const unsigned char *plaintext, unsigned char *key, int aes_keylen, unsigned char *state)
{
    int rounds;
    unsigned char *expanded_key;
    if (aes_keylen == 128)
    {
        rounds = 9;
        expanded_key = (unsigned char *)calloc(176, sizeof(unsigned char));
    }
    else if (aes_keylen == 192)
    {
        rounds = 11;
        expanded_key = (unsigned char *)calloc(208, sizeof(unsigned char));
    }
    else if (aes_keylen == 256)
    {
        rounds = 13;
        expanded_key = (unsigned char *)calloc(240, sizeof(unsigned char));
    }
    else
    {
        printf("AES key length should be 128,192 or 256 bit");
        return;
    }
    key_expansion(key, expanded_key, aes_keylen);
    aes_encrypt_body(plaintext, expanded_key, rounds, state);
    free(expanded_key);
}

void inv_mix_columns(unsigned char *state)
{
    unsigned char tmp[16];
    tmp[0] = (unsigned char)(mul14[state[0]] ^ mul11[state[1]] ^ mul13[state[2]] ^ mul9[state[3]]);
    tmp[1] = (unsigned char)(mul9[state[0]] ^ mul14[state[1]] ^ mul11[state[2]] ^ mul13[state[3]]);
    tmp[2] = (unsigned char)(mul13[state[0]] ^ mul9[state[1]] ^ mul14[state[2]] ^ mul11[state[3]]);
    tmp[3] = (unsigned char)(mul11[state[0]] ^ mul13[state[1]] ^ mul9[state[2]] ^ mul14[state[3]]);

    tmp[4] = (unsigned char)(mul14[state[4]] ^ mul11[state[5]] ^ mul13[state[6]] ^ mul9[state[7]]);
    tmp[5] = (unsigned char)(mul9[state[4]] ^ mul14[state[5]] ^ mul11[state[6]] ^ mul13[state[7]]);
    tmp[6] = (unsigned char)(mul13[state[4]] ^ mul9[state[5]] ^ mul14[state[6]] ^ mul11[state[7]]);
    tmp[7] = (unsigned char)(mul11[state[4]] ^ mul13[state[5]] ^ mul9[state[6]] ^ mul14[state[7]]);

    tmp[8] = (unsigned char)(mul14[state[8]] ^ mul11[state[9]] ^ mul13[state[10]] ^ mul9[state[11]]);
    tmp[9] = (unsigned char)(mul9[state[8]] ^ mul14[state[9]] ^ mul11[state[10]] ^ mul13[state[11]]);
    tmp[10] = (unsigned char)(mul13[state[8]] ^ mul9[state[9]] ^ mul14[state[10]] ^ mul11[state[11]]);
    tmp[11] = (unsigned char)(mul11[state[8]] ^ mul13[state[9]] ^ mul9[state[10]] ^ mul14[state[11]]);

    tmp[12] = (unsigned char)(mul14[state[12]] ^ mul11[state[13]] ^ mul13[state[14]] ^ mul9[state[15]]);
    tmp[13] = (unsigned char)(mul9[state[12]] ^ mul14[state[13]] ^ mul11[state[14]] ^ mul13[state[15]]);
    tmp[14] = (unsigned char)(mul13[state[12]] ^ mul9[state[13]] ^ mul14[state[14]] ^ mul11[state[15]]);
    tmp[15] = (unsigned char)(mul11[state[12]] ^ mul13[state[13]] ^ mul9[state[14]] ^ mul14[state[15]]);

    for (int i = 0; i < 16; i++)
        state[i] = tmp[i];
}

void inv_sub_bytes(unsigned char *state)
{
    for (int i = 0; i < 16; i++)
    {
        state[i] = inv_sbox[state[i]];
    }
}

void inv_shift_rows(unsigned char *state)
{
    unsigned char tmp[16];

    tmp[0] = state[0];
    tmp[1] = state[13];
    tmp[2] = state[10];
    tmp[3] = state[7];
    tmp[4] = state[4];
    tmp[5] = state[1];
    tmp[6] = state[14];
    tmp[7] = state[11];
    tmp[8] = state[8];
    tmp[9] = state[5];
    tmp[10] = state[2];
    tmp[11] = state[15];
    tmp[12] = state[12];
    tmp[13] = state[9];
    tmp[14] = state[6];
    tmp[15] = state[3];

    for (int i = 0; i < 16; i++)
        state[i] = tmp[i];
}

void aes_decrypt_body(const unsigned char *ciphertext, unsigned char *key, int rounds, unsigned char *state)
{

    for (int i = 0; i < 16; i++)
        state[i] = ciphertext[i];

    add_round_key(state, key + 16 * (rounds + 1));
    inv_shift_rows(state);
    inv_sub_bytes(state);

    for (int i = rounds; i >= 1; i--)
    {
        add_round_key(state, key + 16 * i);
        inv_mix_columns(state);
        inv_shift_rows(state);
        inv_sub_bytes(state);
    }

    add_round_key(state, key);
}

void aes_decrypt(const unsigned char *ciphertext, unsigned char *key, int aes_keylen, unsigned char *state)
{
    int rounds;
    unsigned char *expanded_key;
    if (aes_keylen == 128)
    {
        rounds = 9;
        expanded_key = (unsigned char *)calloc(176, sizeof(unsigned char));
    }
    else if (aes_keylen == 192)
    {
        rounds = 11;
        expanded_key = (unsigned char *)calloc(208, sizeof(unsigned char));
    }
    else if (aes_keylen == 256)
    {
        rounds = 13;
        expanded_key = (unsigned char *)calloc(240, sizeof(unsigned char));
    }
    else
    {
        printf("AES key length should be 128,192 or 256 bit");
        return;
    }
    key_expansion(key, expanded_key, aes_keylen);
    aes_decrypt_body(ciphertext, expanded_key, rounds, state);
    free(expanded_key);
}

unsigned char *aes_cbc_encrypt(unsigned char *message, unsigned char *key, int aes_keylen, int *size)
{
    int tmp = *size;
    *size = *size % 16 != 0 ? ((*size / 16) + 1) * 16 : *size;

    unsigned char *padedplaintext = (unsigned char *)calloc(*size, sizeof(unsigned char));
    memcpy(padedplaintext, message, tmp);

    unsigned char IV[16] = {0};

    for (int i = 0; i < (*size) / 16; i++)
    {
        add_round_key(padedplaintext + 16 * i, IV);
        aes_encrypt(padedplaintext + 16 * i, key, aes_keylen, IV);
        memcpy(padedplaintext + 16 * i, IV, 16);
    }

    return padedplaintext;
}

unsigned char *aes_cbc_decrypt(unsigned char *ciphertext, unsigned char *key, int aes_keylen, int *size)
{
    int tmp = *size;
    *size = (*size) % 16 != 0 ? (((*size) / 16) + 1) * 16 : *size;

    unsigned char *padedplaintext = (unsigned char *)calloc(*size, sizeof(unsigned char));

    unsigned char IV[16] = {0};

    for (int i = 0; i < (*size) / 16; i++)
    {
        aes_decrypt(ciphertext + 16 * i, key, aes_keylen, padedplaintext + 16 * i);
        add_round_key(padedplaintext + 16 * i, IV);
        memcpy(IV, ciphertext + 16 * i, 16);
    }

    return padedplaintext;
}

unsigned char *aes_ofb_encrypt(unsigned char *message, unsigned char *key, int aes_keylen, int *size)
{
    int tmp = *size;
    *size = *size % 16 != 0 ? ((*size / 16) + 1) * 16 : *size;

    unsigned char *padedplaintext = (unsigned char *)calloc(*size, sizeof(unsigned char));
    memcpy(padedplaintext, message, tmp);

    unsigned char IV[16] = {0};

    for (int i = 0; i < (*size) / 16; i++)
    {
        aes_encrypt(IV, key, aes_keylen, IV);
        add_round_key(padedplaintext + 16 * i, IV);
    }

    return padedplaintext;
}

unsigned char *aes_ofb_decrypt(unsigned char *message, unsigned char *key, int aes_keylen, int *size)
{
    int tmp = *size;
    *size = *size % 16 != 0 ? ((*size / 16) + 1) * 16 : *size;

    unsigned char *padedplaintext = (unsigned char *)calloc(*size, sizeof(unsigned char));
    memcpy(padedplaintext, message, tmp);

    unsigned char IV[16] = {0};

    for (int i = 0; i < (*size) / 16; i++)
    {
        aes_encrypt(IV, key, aes_keylen, IV);
        add_round_key(padedplaintext + 16 * i, IV);
    }

    return padedplaintext;
}

int read_file_create_hash(const char *filename, unsigned char *key)
{
    FILE *fp;
    unsigned char *buffer;
    long numbytes;
    fp = fopen(filename, "rb");

    /* quit if the file does not exist */
    if (fp == NULL)
        return 1;

    /* Get the number of bytes */
    fseek(fp, 0L, SEEK_END);
    numbytes = ftell(fp);

    /* grab sufficient memory for the 
buffer to hold the text */
    buffer = (char *)calloc(numbytes, sizeof(char));

    /* memory error */
    if (buffer == NULL)
        return 1;
    fseek(fp, 0L, SEEK_SET);
    /* copy all the text into the buffer */
    fread(buffer, sizeof(unsigned char), numbytes, fp);

    int tmp = numbytes;

    unsigned char *ciphertext = aes_cbc_encrypt(buffer, key, 128, &tmp);

    unsigned char *hash = (unsigned char *)malloc(16);

    memcpy(hash, ciphertext + tmp - 16, 16);
    printf("added hash= ");
    for (int i = 0; i < 16; i++)
    {
        printf("%.2x", hash[i]);
    }
    printf("\n");
    fclose(fp);
    fp = fopen(filename, "ab");

    fwrite(hash, sizeof(unsigned char), 16, fp);

    fclose(fp);
    return 0;
}

int check_hash(char *filename, unsigned char *key)
{
    FILE *fp;
    unsigned char *buffer;
    long numbytes;
    fp = fopen(filename, "rb");

    /* quit if the file does not exist */
    if (fp == NULL)
        return 1;

    /* Get the number of bytes */
    fseek(fp, 0L, SEEK_END);
    numbytes = ftell(fp) - 16;
    if (numbytes <= 0)
    {
        printf("there is no hash");
        return -1;
    }
    /* grab sufficient memory for the 
buffer to hold the text */
    buffer = (char *)calloc(numbytes, sizeof(char));

    /* memory error */
    if (buffer == NULL)
        return 1;
    fseek(fp, 0L, SEEK_SET);
    /* copy all the text into the buffer */
    fread(buffer, sizeof(unsigned char), numbytes, fp);

    unsigned char *hash = (unsigned char *)malloc(16);
    fread(hash, sizeof(unsigned char), 16, fp);

    int tmp = numbytes;

    unsigned char *ciphertext = aes_cbc_encrypt(buffer, key, 128, &tmp);
    unsigned char *hashcontrol = (unsigned char *)malloc(16);
    memcpy(hashcontrol, ciphertext + tmp - 16, 16);

    for (int i = 0; i < 16; i++)
    {
        if (hash[i] != hashcontrol[i])
        {
            printf("\nFile content has changed!\n");
            return 1;
        }
    }

    printf("\nFile content has not changed\n");

    fclose(fp);

    return 0;
}

void test_a_b()
{
    unsigned char message[] = "Hello World Test";
    unsigned char out1[16], out2[16];
    unsigned char key_128[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    printf("AES ENCRYPTION TEST-128bit key\n");
    printf("Plaintext: %s\n", message);
    aes_encrypt(message, key_128, 128, out1);
    printf("ciphertext hex:  ");
    for (int i = 0; i < 16; i++)
    {
        printf("%.2x ", out1[i]);
    }
    printf("\nciphertext ascii:  ");
    for (int i = 0; i < 16; i++)
    {
        printf("%c", out1[i]);
    }

    aes_decrypt(out1, key_128, 128, out2);

    printf("\ndecrypted hex:  ");
    for (int i = 0; i < 16; i++)
    {
        printf("%.2x ", out2[i]);
    }
    printf("\ndecrypted ascii:  ");
    for (int i = 0; i < 16; i++)
    {
        printf("%c", out2[i]);
    }

    unsigned char key_192[24] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24};

    printf("\n\nAES ENCRYPTION TEST-192bit key\n");
    printf("Plaintext: %s\n", message);
    aes_encrypt(message, key_192, 192, out1);
    printf("ciphertext hex:  ");
    for (int i = 0; i < 16; i++)
    {
        printf("%.2x ", out1[i]);
    }
    printf("\nciphertext ascii:  ");
    for (int i = 0; i < 16; i++)
    {
        printf("%c", out1[i]);
    }

    aes_decrypt(out1, key_192, 192, out2);

    printf("\ndecrypted hex:  ");
    for (int i = 0; i < 16; i++)
    {
        printf("%.2x ", out2[i]);
    }
    printf("\ndecrypted ascii:  ");
    for (int i = 0; i < 16; i++)
    {
        printf("%c", out2[i]);
    }

    unsigned char key_256[36] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36};

    printf("\n\nAES ENCRYPTION TEST-256bit key\n");
    printf("Plaintext: %s\n", message);
    aes_encrypt(message, key_256, 256, out1);
    printf("ciphertext hex:  ");
    for (int i = 0; i < 16; i++)
    {
        printf("%.2x ", out1[i]);
    }
    printf("\nciphertext ascii:  ");
    for (int i = 0; i < 16; i++)
    {
        printf("%c", out1[i]);
    }

    aes_decrypt(out1, key_256, 256, out2);

    printf("\ndecrypted hex:  ");
    for (int i = 0; i < 16; i++)
    {
        printf("%.2x ", out2[i]);
    }
    printf("\ndecrypted ascii:  ");
    for (int i = 0; i < 16; i++)
    {
        printf("%c", out2[i]);
    }

    printf("\n\n----------AES CBC MODE TEST-128bit key----------\n");

    unsigned char message1[] = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.";
    int size = sizeof(message1) / sizeof(message1[0]);
    printf("Plaintext: \n");
    for (int i = 0; i < size; i++)
    {
        if (i != 0 && i % 72 == 0)
            printf("\n");
        printf("%c", message1[i]);
    }
    printf("\n");
    unsigned char *ciphertext = aes_cbc_encrypt(message1, key_128, 128, &size);
    printf("\n\nCiphertext hex: \n\n");
    for (int i = 0; i < size; i++)
    {
        if (i != 0 && i % 32 == 0)
            printf("\n");
        printf("%.2x", ciphertext[i]);
    }
    printf("\n\nDecrypted ascii: \n");
    unsigned char *plaintext = aes_cbc_decrypt(ciphertext, key_128, 128, &size);
    printf("\n");
    for (int i = 0; i < size; i++)
    {
        if (i != 0 && i % 32 == 0)
            printf("\n");
        printf("%c", plaintext[i]);
    }
    printf("\n\n----------AES CBC MODE TEST-192bit key----------\n");
    size = sizeof(message1) / sizeof(message1[0]);

    printf("\n");
    ciphertext = aes_cbc_encrypt(message1, key_192, 192, &size);
    printf("\n\nCiphertext hex: \n\n");
    for (int i = 0; i < size; i++)
    {
        if (i != 0 && i % 32 == 0)
            printf("\n");
        printf("%.2x", ciphertext[i]);
    }
    printf("\n\nDecrypted ascii: \n");
    plaintext = aes_cbc_decrypt(ciphertext, key_192, 192, &size);
    printf("\n");
    for (int i = 0; i < size; i++)
    {
        if (i != 0 && i % 32 == 0)
            printf("\n");
        printf("%c", plaintext[i]);
    }

    printf("\n\n----------AES CBC MODE TEST-256bit key----------\n");
    size = sizeof(message1) / sizeof(message1[0]);

    printf("\n");
    ciphertext = aes_cbc_encrypt(message1, key_256, 256, &size);
    printf("\n\nCiphertext hex: \n\n");
    for (int i = 0; i < size; i++)
    {
        if (i != 0 && i % 32 == 0)
            printf("\n");
        printf("%.2x", ciphertext[i]);
    }
    printf("\n\nDecrypted ascii: \n");
    plaintext = aes_cbc_decrypt(ciphertext, key_256, 256, &size);
    printf("\n");
    for (int i = 0; i < size; i++)
    {
        if (i != 0 && i % 32 == 0)
            printf("\n");
        printf("%c", plaintext[i]);
    }

    printf("\n\n----------AES OFB MODE TEST-128bit key----------\n");

    size = sizeof(message1) / sizeof(message1[0]);
    printf("Plaintext: \n");
    for (int i = 0; i < size; i++)
    {
        if (i != 0 && i % 72 == 0)
            printf("\n");
        printf("%c", message1[i]);
    }
    printf("\n");
    ciphertext = aes_ofb_encrypt(message1, key_128, 128, &size);
    printf("\n\nCiphertext hex: \n\n");
    for (int i = 0; i < size; i++)
    {
        if (i != 0 && i % 32 == 0)
            printf("\n");
        printf("%.2x", ciphertext[i]);
    }
    printf("\n\nDecrypted ascii: \n");
    plaintext = aes_ofb_decrypt(ciphertext, key_128, 128, &size);
    printf("\n");
    for (int i = 0; i < size; i++)
    {
        if (i != 0 && i % 32 == 0)
            printf("\n");
        printf("%c", plaintext[i]);
    }
    printf("\n\n----------AES OFB MODE TEST-192bit key----------\n");
    size = sizeof(message1) / sizeof(message1[0]);

    printf("\n");
    ciphertext = aes_ofb_encrypt(message1, key_192, 192, &size);
    printf("\n\nCiphertext hex: \n\n");
    for (int i = 0; i < size; i++)
    {
        if (i != 0 && i % 32 == 0)
            printf("\n");
        printf("%.2x", ciphertext[i]);
    }
    printf("\n\nDecrypted ascii: \n");
    plaintext = aes_ofb_decrypt(ciphertext, key_192, 192, &size);
    printf("\n");
    for (int i = 0; i < size; i++)
    {
        if (i != 0 && i % 32 == 0)
            printf("\n");
        printf("%c", plaintext[i]);
    }

    printf("\n\n----------AES OFB MODE TEST-256bit key----------\n");
    size = sizeof(message1) / sizeof(message1[0]);

    printf("\n");
    ciphertext = aes_ofb_encrypt(message1, key_256, 256, &size);
    printf("\n\nCiphertext hex: \n\n");
    for (int i = 0; i < size; i++)
    {
        if (i != 0 && i % 32 == 0)
            printf("\n");
        printf("%.2x", ciphertext[i]);
    }
    printf("\n\nDecrypted ascii: \n");
    plaintext = aes_ofb_decrypt(ciphertext, key_256, 256, &size);
    printf("\n");
    for (int i = 0; i < size; i++)
    {
        if (i != 0 && i % 32 == 0)
            printf("\n");
        printf("%c", plaintext[i]);
    }
}

void test_c_d()
{
    unsigned char key_128[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    read_file_create_hash("aa.txt", key_128);
    check_hash("aa.txt", key_128);
}

int main()
{
    test_a_b();
    test_c_d();
    return 0;
}