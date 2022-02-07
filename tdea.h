typedef unsigned long long ui64;
typedef unsigned int ui32;
typedef unsigned char ui8;

typedef struct
{
  ui32 data[32];
} TDEA_DESKEY;

// Single DES ECB encryption/decryption
ui64 DES_Encrypt(ui64 key, ui64 data);
ui64 DES_Decrypt(ui64 key, ui64 data);
