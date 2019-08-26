// DESFire AES access library
// (c) Copyright 2019 Andrews & Arnold Adrian Kennard
/*
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifdef	ESP_PLATFORM
#include <esp_system.h>
#include <esp32/aes.h>
#include "esp_log.h"
#else
#include <stdio.h>
#include <err.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include <string.h>
#include <ctype.h>

#include "desfireaes.h"

//#define DEBUG ESP_LOG_INFO

#ifdef DEBUG
static void
dump (const char *prefix, unsigned int len, unsigned char *data)
{
#ifdef ESP_PLATFORM
   ESP_LOG_BUFFER_HEX_LEVEL (prefix, data, len, DEBUG);
#else
   int n;
   fprintf (stderr, "%-10s", prefix);
   for (n = 0; n < len; n++)
      fprintf (stderr, " %02X", data[n]);
   fprintf (stderr, "\n");
#endif
}
#else
#define dump(p,l,d)
#endif

// Random
#ifdef	ESP_PLATFORM
#define	fill_random	esp_fill_random
#else
void
fill_random (unsigned char *buf, size_t size)
{                               // Create our random A value
   int f = open ("/dev/urandom", O_RDONLY);
   if (f < 0)
      err (1, "random");
   if (read (f, buf, size) != size)
      err (1, "random");
   close (f);
}
#endif

// Decrypt, updating iv
#ifdef ESP_PLATFORM
#define decrypt(ctx,cipher,keylen,key,iv,out,in,len) aes_decrypt(keylen,key,iv,out,in,len)
static const char *
aes_decrypt (int keylen, const unsigned char *key, unsigned char *iv, unsigned char *out, const unsigned char *in, int len)
{
   if (len <= 0)
      return NULL;
   len = (len + 15) / 16 * 16;
   //ESP_LOG_BUFFER_HEX_LEVEL ("AES Dec", key, keylen, ESP_LOG_INFO);
   //ESP_LOG_BUFFER_HEX_LEVEL ("AES In ", in, len, ESP_LOG_INFO);
   esp_aes_context ctx;
   esp_aes_init (&ctx);
   esp_err_t err = esp_aes_setkey (&ctx, key, keylen * 8);
   if (!err)
      err = esp_aes_crypt_cbc (&ctx, ESP_AES_DECRYPT, len, iv, in, out);
   esp_aes_free (&ctx);
   if (err)
      return esp_err_to_name (err);
   //ESP_LOG_BUFFER_HEX_LEVEL ("AES Out", out, len, ESP_LOG_INFO);
   return NULL;
}
#else
static const char *
decrypt (EVP_CIPHER_CTX * ctx, const EVP_CIPHER * cipher, int keylen, const unsigned char *key, unsigned char *iv,
         unsigned char *out, const unsigned char *in, int len)
{
   len = (len + keylen - 1) / keylen * keylen;
   unsigned char newiv[keylen];
   memcpy (newiv, in + len - keylen, keylen);
   if (EVP_DecryptInit_ex (ctx, cipher, NULL, key, iv) != 1)
      return "Decrypt error";
   EVP_CIPHER_CTX_set_padding (ctx, 0);
   int n;
   if (EVP_DecryptUpdate (ctx, out, &n, in, len) != 1)
      return "Decrypt error";
   if (EVP_DecryptFinal_ex (ctx, out + n, &n) != 1)
      return "Decrypt error";
   memcpy (iv, newiv, keylen);
   return NULL;
}
#endif

// Encrypt, updating iv
#ifdef	ESP_PLATFORM
#define encrypt(ctx,cipher,keylen,key,iv,out,in,len) aes_encrypt(keylen,key,iv,out,in,len)
static const char *
aes_encrypt (int keylen, const unsigned char *key, unsigned char *iv, unsigned char *out, const unsigned char *in, int len)
{
   if (len <= 0)
      return NULL;
   len = (len + 15) / 16 * 16;
   //ESP_LOG_BUFFER_HEX_LEVEL ("AES Enc", key, keylen, ESP_LOG_INFO);
   //ESP_LOG_BUFFER_HEX_LEVEL ("AES In ", in, len, ESP_LOG_INFO);
   esp_aes_context ctx;
   esp_aes_init (&ctx);
   esp_err_t err = esp_aes_setkey (&ctx, key, keylen * 8);
   if (!err)
   {
      unsigned char *o = out;
      if (!out)
         o = malloc (len);      // TODO may be better to do the CBC a block at a time with lower level calls, 
      err = esp_aes_crypt_cbc (&ctx, ESP_AES_ENCRYPT, len, iv, in, o);
      if (!out)
         free (o);
   }
   esp_aes_free (&ctx);
   //if(out)ESP_LOG_BUFFER_HEX_LEVEL ("AES Out", out, len, ESP_LOG_INFO);
   if (err)
      return esp_err_to_name (err);
   return NULL;
}
#else
static const char *
encrypt (EVP_CIPHER_CTX * ctx, const EVP_CIPHER * cipher, int keylen, const unsigned char *key, unsigned char *iv,
         unsigned char *out, const unsigned char *in, int len)
{
   len = (len + keylen - 1) / keylen * keylen;
   if (EVP_EncryptInit_ex (ctx, cipher, NULL, key, iv) != 1)
      return "Encrypt error";
   unsigned char *o = out;
   if (!out)
      o = malloc (len);         // TODO may be better to do the CBC a block at a time with lower level calls, 
   EVP_CIPHER_CTX_set_padding (ctx, 0);
   int n;
   if (EVP_EncryptUpdate (ctx, o, &n, in, len) != 1 || EVP_EncryptFinal_ex (ctx, o + n, &n) != 1)
   {
      if (!out)
         free (o);
      return "Encrypt error";
   }
   if (!out)
      free (o);
   memcpy (iv, in + len - keylen, keylen);
   return NULL;
}
#endif

// Simplify buffer loading
#define wbuf1(v) buf[n++]=(v)
#define wbuf2(v) buf[n++]=(v);buf[n++]=(v)>>8
#define wbuf3(v) buf[n++]=(v);buf[n++]=(v)>>8;buf[n++]=(v)>>16
#define wbuf4(v) buf[n++]=(v);buf[n++]=(v)>>8;buf[n++]=(v)>>16;buf[n++]=(v)>>24
#define buf2(n) buf[(n)]+(buf[(n)+1]<<8)
#define buf3(n) buf[(n)]+(buf[(n)+1]<<8)+(buf[(n)+2]<<16)
#define buf4(n) buf[(n)]+(buf[(n)+1]<<8)+(buf[(n)+2]<<16)+(buf[(n)+3]<<24)

unsigned int
df_hex (unsigned int max, unsigned char *dst, const char *src)
{                               // get hex data, return bytes
   unsigned int p = 0;
   while (p < max)
   {
      while (*src && !isalnum ((int) (*src)))
         src++;                 // Skip separators
      if (!*src || !isxdigit ((int) (*src)))
         return p;
      int v = (*src & 15) + (isalpha ((int) (*src)) ? 9 : 0);
      src++;
      if (isxdigit ((int) (*src)))
      {
         v = (v << 4) + (*src & 15) + (isalpha ((int) (*src)) ? 9 : 0);
         src++;
      }
      if (dst)
         dst[p] = v;
      p++;
   }
   return p;
}

static void
cmac (df_t * d, unsigned int len, unsigned char *data)
{                               // Process CMAC
   dump ("CMAC of", len, data);
   unsigned char temp[d->keylen];       // For last block
   int last = len - (len % d->keylen ? : len ? d->keylen : 0);
   int p = len - last;
   if (p)
      memcpy (temp, data + last, p);
   if (p && p < d->keylen)
   {                            // pad
      temp[p++] = 0x80;
      while (p < d->keylen)
         temp[p++] = 0;
      for (p = 0; p < d->keylen; p++)
         temp[p] ^= d->sk2[p];
   } else
      for (p = 0; p < d->keylen; p++)
         temp[p] ^= d->sk1[p];
   if (last)
      encrypt (d->ctx, d->cipher, d->keylen, d->sk0, d->cmac, NULL, data, last);
   if (last < len)
      encrypt (d->ctx, d->cipher, d->keylen, d->sk0, d->cmac, NULL, temp, len - last);
   dump ("CMAC", d->keylen, d->cmac);
}

unsigned int
crc (unsigned int len, unsigned char *data)
{
   dump ("CRC", len, data);
   unsigned int poly = 0xEDB88320;
   unsigned int crc = 0xFFFFFFFF;
   int n,
     b;
   for (n = 0; n < len; n++)
   {
      crc ^= data[n];
      for (b = 0; b < 8; b++)
         if (crc & 1)
            crc = (crc >> 1) ^ poly;
         else
            crc >>= 1;
   }
   return crc;
}

void
add_crc (unsigned int len, unsigned char *src, unsigned char *dst)
{
   unsigned int c = crc (len, src);
   dst[0] = c;
   dst[1] = c >> 8;
   dst[2] = c >> 16;
   dst[3] = c >> 24;
}

#define TXMAX 55
const char *
df_dx (df_t * d, unsigned char cmd, unsigned int max, unsigned char *buf, unsigned int len, unsigned char txenc,
       unsigned char rxenc, unsigned int *rlen)
{                               // Data exchange, see include file for more details
   if (rlen)
      *rlen = 0;                // default
   unsigned char tmp[17];
   if (!buf)
   {
      buf = tmp;
      max = sizeof (tmp);
   }
   // Set command
   if (cmd)
      buf[0] = cmd;
   else
      cmd = buf[0];
   dump ("Tx", len, buf);
   if (cmd == 0xAA || cmd == 0x1A || cmd == 0x0A || cmd == 0x5A)
      d->keylen = 0;
   if (d->keylen)
   {                            // Authenticated
      if (txenc == 0xFF)
      {                         // Append CMAC
         if (len + 8 > max)
            return "Tx no space";
         cmac (d, len, buf);    // CMAC update
         memcpy (buf + len, d->cmac, 8);
         len += 8;
         dump ("Tx(cmac)", len, buf);
      } else if (txenc)
      {                         // Encrypt
         if (((len + 4) | 15) + 1 > max)
            return "Tx no space";
         if (cmd != 0xC4)
         {                      // Add CRC (C4 is special case as multiple CRCs and padding)
            add_crc (len, buf, buf + len);
            len += 4;
         }
         // Padding
         while ((len - txenc) % d->keylen)
            buf[len++] = 0;
         dump ("Pre enc", len, buf);
         encrypt (d->ctx, d->cipher, d->keylen, d->sk0, d->cmac, buf + txenc, buf + txenc, len - txenc);
         dump ("Tx(enc)", len, buf);
      } else
         cmac (d, len, buf);    // CMAC update
   }
   // Send buf
   if (len > TXMAX)
   {                            // Multi part
      unsigned char *p = buf,
         *e = buf + len;
      while (e - p >= TXMAX)
      {                         // Send initial parts
         if (p > buf)
            *--p = 0xAF;
         dump ("Tx(raw)", TXMAX, p);
         int b = d->dx (d->obj, TXMAX, p, 1);
         if (b < 0)
            return "Dx fail";
         dump ("Rx(raw)", b, p);
         if (!b)
         {
            d->keylen = 0;
            return "";          // Card gone
         }
         if (*p != 0xAF)
         {
            d->keylen = 0;
            return "Tx expected AF";
         }
         p += TXMAX;
      }
      memcpy (buf + 1, p, e - p);
      buf[0] = 0xAF;
      len = e - p + 1;
   }
   {                            // Receive data
      unsigned char *p = buf,
         *e = buf + max;
      while (p < e)
      {
         dump ("Tx(raw)", len, p);
         int b = d->dx (d->obj, len, p, e - p);
         if (b < 0)
            return "Dx fail";
         dump ("Rx(raw)", b, p);
         if (!b)
         {
            d->keylen = 0;
            return "";          // Card gone
         }
         if (p > buf)
         {                      // Move status back
            *buf = *p;
            memmove (p, p + 1, --b);
         }
         p += b;
         if (*buf != 0xAF || cmd == 0xAA || cmd == 0x1A || cmd == 0x0A)
            break;              // done
         if (p == e)
            return "Rx No space";
         len = 1;               // Next part to send
         *p = 0xAF;
      }
      len = p - buf;
   }
   // Post process
   if (d->keylen)
   {
      if (rxenc)
      {                         // Encrypted
         if (len != ((rxenc + 3) | 15) + 2)
            return "Rx Bad encrypted length";
         decrypt (d->ctx, d->cipher, d->keylen, d->sk0, d->cmac, buf + 1, buf + 1, len - 1);
         dump ("Dec", len, buf);
         unsigned int c = buf4 (rxenc);
         buf[rxenc] = buf[0];   // Status at end of playload
         if (c != crc (rxenc, buf + 1))
            return "Rx CRC fail";
      } else if (len > 1)
      {                         // Check CMAC
         if (len < 9)
            return "Bad rx CMAC len";
         len -= 8;
         unsigned char c1 = buf[len];
         buf[len] = buf[0];     // status on end
         cmac (d, len, buf + 1);        // CMAC update
         if (c1 != d->cmac[0] || memcmp (d->cmac + 1, buf + len + 1, 7))
            return "Rx CMAC fail";
      }
   } else if (rxenc && len != rxenc)
      return "Rx unexpected length";
   if (!rxenc && !rlen && len != 1)
      return "Unexpected data response";
   if (rlen)
      *rlen = len;              // Set so response can be checked even if error
   // Check response
   if (*buf && *buf != 0xAF)
   {
      if (*buf == 0x0C)
         return "No change";
      if (*buf == 0x0E)
         return "Out of EEPROM";
      if (*buf == 0x1C)
         return "Illegal command";
      if (*buf == 0x1E)
         return "Integrity error";
      if (*buf == 0x40)
         return "No such file";
      if (*buf == 0x7E)
         return "Length error";
      if (*buf == 0x97)
         return "Crypto error";
      if (*buf == 0x9D)
         return "Permission denied";
      if (*buf == 0x9E)
         return "Parameter error";
      if (*buf == 0xA0)
         return "Application not found";
      if (*buf == 0xAE)
         return "Authentication error";
      if (*buf == 0xBE)
         return "Boundary error";
      if (*buf == 0xC1)
         return "Card integrity error";
      if (*buf == 0xCA)
         return "Command aborted";
      if (*buf == 0xCD)
         return "Card disabled";
      if (*buf == 0xCE)
         return "Count error";
      if (*buf == 0xDE)
         return "Duplicate error";
      if (*buf == 0xEE)
         return "EEPROM error";
      if (*buf == 0xF0)
         return "File not found";
      if (*buf == 0xF1)
         return "File integrity found";
      return "Rx status error response";
   }
   dump ("Rx", len, buf);
   return NULL;
}

const char *
df_init (df_t * d, void *obj, df_dx_func_t * dx)
{                               // Initialise
   memset (d, 0, sizeof (*d));
   d->obj = obj;
   d->dx = dx;
#ifndef	ESP_PLATFORM
   if (!(d->ctx = EVP_CIPHER_CTX_new ()))
      return "Unable to make CTX";
#endif
   return NULL;
}

const char *
df_select_application (df_t * d, unsigned char aid[3])
{                               // Select an AID (NULL means AID 0)
   unsigned char buf[17] = { };
   if (aid)
      memcpy (buf + 1, aid, 3);
   const char *e = df_dx (d, 0x5A, sizeof (buf), buf, 4, 0, 0, NULL);
   if (e || !aid)
      memset (d->aid, 0, sizeof (d->aid));
   else
      memcpy (d->aid, aid, sizeof (d->aid));
   d->keylen = 0;
   return e;
}

const char *
df_get_version (df_t * d, unsigned char ver[28])
{
   unsigned char buf[64];
   unsigned int rlen;
   const char *e = df_dx (d, 0x60, sizeof (buf), buf, 1, 0, 0, &rlen);
   if (e)
      return e;
   if (rlen != 29)
      return "Bad length for Get Version";
   if (ver)
      memcpy (ver, buf + 1, rlen - 1);
   return NULL;
}

const char *
df_get_key_settings (df_t * d, unsigned char keyno, unsigned char *setting, unsigned char *keynos)
{
   unsigned int rlen;
   unsigned char buf[17];
   unsigned int n = 1;
   wbuf1 (keyno);
   const char *e = df_dx (d, 0x45, sizeof (buf), buf, n, 0, 0, &rlen);
   if (e)
      return e;
   if (rlen != 2)
      return "Bad length for Get Key Settings";
   if (setting)
      *setting = buf[1];
   if (keynos)
      *keynos = buf[2];
   return e;
}

const char *
df_get_key_version (df_t * d, unsigned char keyno, unsigned char *version)
{
   unsigned int rlen;
   unsigned char buf[17];
   unsigned int n = 1;
   wbuf1 (keyno);
   const char *e = df_dx (d, 0x64, sizeof (buf), buf, n, 0, 0, &rlen);
   if (e)
      return e;
   if (rlen != 2)
      return "Bad length for get Key Version";
   if (version)
      *version = buf[1];
   return e;
}

const char *
df_authenticate_general (df_t * d, unsigned char keyno, unsigned char keylen, unsigned char *key
#ifndef	ESP_PLATFORM
                         , const EVP_CIPHER * cipher
#endif
   )
{                               // Authenticate for specified key len
   unsigned char zero[keylen];
   if (!key)
   {
      key = zero;
      memset (key, 0, keylen);
   }
   d->keylen = 0;
   d->keyno = keyno;
   const char *e;
   unsigned int rlen;
   unsigned char buf[64];
   unsigned int n = 1;
   wbuf1 (keyno);
   if ((e = df_dx (d, keylen == 8 ? 0x1A : 0xAA, sizeof (buf), buf, n, 0, 0, &rlen)))
      return e;
   if (rlen != keylen + 1)
      return "Bad response length for auth";
   fill_random (d->sk1, keylen);
   // Decode B value
   memset (d->cmac, 0, keylen);
   decrypt (d->ctx, cipher, keylen, key, d->cmac, d->sk2, buf + 1, keylen);
   // Make response A+B'
   memcpy (buf + 1, d->sk1, keylen);
   memcpy (buf + keylen + 1, d->sk2 + 1, keylen - 1);
   buf[keylen * 2] = d->sk2[0];
   // Encrypt response
   encrypt (d->ctx, cipher, keylen, key, d->cmac, buf + 1, buf + 1, keylen * 2);
   // Send response
   if ((e = df_dx (d, 0xAF, sizeof (buf), buf, 1 + keylen * 2, 0, 0, &rlen)))
      return e;
   if (rlen != keylen + 1)
      return "Bad response length for auth";
   // Decode reply A'
   if ((e = decrypt (d->ctx, cipher, keylen, key, d->cmac, buf + 1, buf + 1, keylen)))
      return e;
   // Check A'
   if (memcmp (buf + 1, d->sk1 + 1, keylen - 1) || buf[keylen] != d->sk1[0])
      return "Auth failed";
   // Mark as logged in
#ifndef ESP_PLATFORM
   d->cipher = cipher;
#endif
   d->keylen = keylen;
   dump ("A", keylen, d->sk1);
   dump ("B", keylen, d->sk2);
   memcpy (d->sk0 + 0, d->sk1 + 0, 4);
   memcpy (d->sk0 + 4, d->sk2 + 0, 4);
   if (keylen > 8)
   {
      memcpy (d->sk0 + 8, d->sk1 + 12, 4);
      memcpy (d->sk0 + 12, d->sk2 + 12, 4);
   }
   // Make SK1
   memset (d->cmac, 0, keylen);
   memset (d->sk1, 0, keylen);
   if ((e = encrypt (d->ctx, cipher, keylen, d->sk0, d->cmac, d->sk1, d->sk1, keylen)))
      return e;
   // Shift SK1
   unsigned char xor = 0;
   if (d->sk1[0] & 0x80)
      xor = (keylen == 8 ? 0x1B : 0x87);
   for (n = 0; n < keylen - 1; n++)
      d->sk1[n] = (d->sk1[n] << 1) | (d->sk1[n + 1] >> 7);
   d->sk1[keylen - 1] <<= 1;
   d->sk1[keylen - 1] ^= xor;
   // Make SK2
   memcpy (d->sk2, d->sk1, keylen);
   // Shift SK2
   xor = 0;
   if (d->sk2[0] & 0x80)
      xor = (keylen == 8 ? 0x1B : 0x87);
   for (n = 0; n < keylen - 1; n++)
      d->sk2[n] = (d->sk2[n] << 1) | (d->sk2[n + 1] >> 7);
   d->sk2[keylen - 1] <<= 1;
   d->sk2[keylen - 1] ^= xor;
   // Reset CMAC
   memset (d->cmac, 0, keylen);
   dump ("SK0", keylen, d->sk0);
   dump ("SK1", keylen, d->sk1);
   dump ("SK2", keylen, d->sk2);
   return NULL;
}

const char *
df_authenticate (df_t * d, unsigned char keyno, unsigned char key[16])
{                               // Authenticate with a key (AES)
   return df_authenticate_general (d, keyno, 16, key
#ifndef	ESP_PLATFORM
                                   , EVP_aes_128_cbc ()
#endif
      );
}

#ifndef	ESP_PLATFORM
const char *
df_des_authenticate (df_t * d, unsigned char keyno, unsigned char key[8])
{                               // Authenticate with DES - used to convert card to AES
   return df_authenticate_general (d, keyno, 8, key, EVP_des_cbc ());
}
#endif

const char *
df_change_file_settings (df_t * d, unsigned char fileno, unsigned char comms, unsigned short oldaccess, unsigned short access)
{                               // Change settings for current key
   if (!d->keylen)
      return "Not authenticated";
   unsigned char buf[32];
   unsigned int n = 1;
   wbuf1 (fileno);
   wbuf1 (comms);
   wbuf2 (access);
   return df_dx (d, 0x5F, sizeof (buf), buf, n, (oldaccess & 15) == 14 ? 0 : 2, 0, NULL);
}

const char *
df_change_key_settings (df_t * d, unsigned char settings)
{                               // Change settings for current key
   if (!d->keylen)
      return "Not authenticated";
   unsigned char buf[32];
   unsigned int n = 1;
   wbuf1 (settings);
   return df_dx (d, 0x54, sizeof (buf), buf, n, 1, 0, NULL);
}

const char *
df_set_configuration (df_t * d, unsigned char settings)
{                               // Change settings for current key
   if (!d->keylen)
      return "Not authenticated";
   unsigned char buf[32];
   unsigned int n = 1;
   wbuf1 (0);
   wbuf1 (settings);
   return df_dx (d, 0x5C, sizeof (buf), buf, n, 2, 0, NULL);
}

const char *
df_change_key (df_t * d, unsigned char keyno, unsigned char version, unsigned char old[16], unsigned char key[16])
{
   const char *e;
   unsigned char zero[16] = { 0 };
   if (!key)
      key = zero;
   if (!old)
      old = zero;
   unsigned char buf[64] = { 0 };
   int n;
   buf[0] = 0xC4;
   buf[1] = keyno;
   keyno &= 15;
   memcpy (buf + 2, key, 16);
   buf[18] = version;
   add_crc (19, buf, buf + 19);
   if (keyno != d->keyno)
   {                            // Changing different key
      for (n = 0; n < 16; n++)
         buf[2 + n] ^= old[n];
      add_crc (16, key, buf + 23);
      n = 27;
   } else
      n = 23;
   if ((e = df_dx (d, buf[0], sizeof (buf), buf, n, 2, 0, NULL)))
      return e;
   if (keyno == d->keyno)
      d->keylen = 0;            // No longer secure;
   return NULL;
}

const char *
df_format (df_t * d, unsigned char key[16])
{                               // Format card, and set AES master key all zeros with key version 01. key is existing master AES key
   unsigned char zero[16] = {
      0
   };
   if (!key)
      key = zero;
   const char *e;
   if ((d->keylen || d->aid[0] || d->aid[1] || d->aid[1]) && (e = df_select_application (d, NULL)))
      return e;
   unsigned char version;
   if ((e = df_get_key_version (d, 0, &version)))
      return e;
   if (!version)
   {                            // DES!
#ifdef	ESP_PLATFORM
      return "Needs conversion from DES to AES";
#else
      if ((e = df_des_authenticate (d, 0, key)))
         return e;
      if ((e = df_dx (d, 0xFC, 0, NULL, 1, 0, 0, NULL)))
         return e;
      // Auth again as we did not track CMAC so cannot do key change without
      if ((e = df_des_authenticate (d, 0, key)))
         return e;
      if ((e = df_change_key (d, 0x80, 1, NULL, NULL)))
         return e;
#endif
   } else
   {                            // AES
      if ((e = df_authenticate (d, 0, key)))
         return e;
      if ((e = df_dx (d, 0xFC, 0, NULL, 1, 0, 0, NULL)))
         return e;
      if (memcmp (key, zero, 16) && (e = df_change_key (d, 0, 1, key, NULL)))
         return e;
   }
   return NULL;
}

const char *
df_commit (df_t * d)
{                               // Commit
   return df_dx (d, 0xC7, 0, NULL, 1, 0, 0, NULL);
}

const char *
df_abort (df_t * d)
{                               // Abort
   return df_dx (d, 0xA7, 0, NULL, 1, 0, 0, NULL);
}

const char *
df_get_application_ids (df_t * d, unsigned int *num, unsigned int space, unsigned char *aids)
{
   if (num)
      *num = 0;
   unsigned int rlen;
   unsigned char buf[1000];
   const char *e = df_dx (d, 0x6A, sizeof (buf), buf, 1, 0, 0, &rlen);
   if (e)
      return e;
   rlen--;
   if (rlen % 3)
      return "Bad application list";
   if (num)
      *num = rlen / 3;
   if (rlen > space)
      rlen = space;
   if (aids)
      memcpy (aids, buf + 1, rlen);
   return NULL;
}

const char *
df_delete_application (df_t * d, unsigned char aid[3])
{
   unsigned char buf[32] = { 0 };
   memcpy (buf, aid, 3);
   return df_dx (d, 0xDA, sizeof (buf), buf, 3, 0, 0, NULL);
}

const char *
df_create_application (df_t * d, unsigned char aid[3], unsigned char settings, unsigned char keys)
{
   unsigned char buf[32];
   memcpy (buf + 1, aid, 3);
   buf[4] = settings;
   buf[5] = (0x80 | keys);      // Always AES
   return df_dx (d, 0xCA, sizeof (buf), buf, 6, 0, 0, NULL);
}

const char *
df_write_data (df_t * d, unsigned char fileno, char type, unsigned char comms, unsigned int offset,
               unsigned int len, const void *data)
{
   if (type != 'D' && type != 'B' && type != 'L' && type != 'C')
      return "Bad file type";
   unsigned char buf[len + 32];
   unsigned int n = 1;
   wbuf1 (fileno);
   wbuf3 (offset);
   wbuf3 (len);
   memcpy (buf + n, data, len);
   n += len;
   return df_dx (d, type == 'D'
                 || type == 'B' ? 0x3D : 0x3B, sizeof (buf), buf, n, (comms & DF_MODE_ENC) ? 8 : (comms & DF_MODE_CMAC) ? 0xFF : 0,
                 0, NULL);
}

const char *
df_delete_file (df_t * d, unsigned char fileno)
{
   unsigned char buf[32];
   unsigned int n = 1;
   wbuf1 (fileno);
   return df_dx (d, 0xDF, sizeof (buf), buf, n, 0, 0, NULL);
}

const char *
df_get_uid (df_t * d, unsigned char uid[7])
{
   if (!d->keylen)
      return "Not authenticated";
   unsigned char buf[64];
   const char *e = df_dx (d, 0x51, sizeof (buf), buf, 1, 0, 8, NULL);
   if (e)
      return e;
   if (uid)
      memcpy (uid, buf + 1, 7);
   return NULL;

}

const char *
df_free_memory (df_t * d, unsigned int *mem)
{
   unsigned int rlen;
   unsigned char buf[32];
   const char *e = df_dx (d, 0x6E, sizeof (buf), buf, 1, 0, 0, &rlen);
   if (e)
      return e;
   if (rlen != 4)
      return "Bad response size for free memory";
   if (mem)
      *mem = buf3 (1);
   return NULL;
}

const char *
df_get_file_ids (df_t * d, unsigned long long *ids)
{
   unsigned int rlen;
   unsigned char buf[128];
   const char *e = df_dx (d, 0x6F, sizeof (buf), buf, 1, 0, 0, &rlen);
   if (e)
      return e;
   if (!ids)
      return NULL;
   rlen--;
   unsigned long long i = 0;
   while (rlen--)
      if (buf[1 + rlen] < 64)
         i |= (1 << buf[1 + rlen]);
   *ids = i;
   return NULL;
}

const char *
df_create_file (df_t * d, unsigned char fileno, char type, unsigned char comms, unsigned short access,
                unsigned int size, unsigned int min, unsigned int max, unsigned int recs, unsigned int value, unsigned char lc)
{                               // Create file
   unsigned char buf[32];
   unsigned int n = 1;
   wbuf1 (fileno);
   wbuf1 (comms);
   wbuf2 (access);
   if (type == 'V')
   {                            // Value file
      wbuf4 (min);
      wbuf4 (max);
      wbuf4 (value);
      wbuf1 (lc);
      return df_dx (d, 0xCC, sizeof (buf), buf, n, 0, 0, NULL);
   }
   if (type == 'C' || type == 'L')
   {                            // Cyclic or linear
      wbuf3 (size);
      wbuf3 (recs);
      return df_dx (d, type == 'C' ? 0xC0 : 0xC1, sizeof (buf), buf, n, 0, 0, NULL);
   }
   if (type == 'D' || type == 'B')
   {                            // Data or backup
      wbuf3 (size);
      return df_dx (d, type == 'D' ? 0xCD : 0xCB, sizeof (buf), buf, n, 0, 0, NULL);
   }
   return "Unknown file type";
}

const char *
df_get_file_settings (df_t * d, unsigned char fileno, char *type, unsigned char *comms,
                      unsigned short *access, unsigned int *size, unsigned int *min, unsigned int *max,
                      unsigned int *recs, unsigned int *limited, unsigned char *lc)
{                               // Get file settings
   if (type)
      *type = 0;
   if (comms)
      *comms = 0;
   if (access)
      *access = 0;
   if (size)
      *size = 0;
   if (min)
      *min = 0;
   if (max)
      *max = 0;
   if (limited)
      *limited = 0;
   if (recs)
      *recs = 0;
   if (lc)
      *lc = 0;
   unsigned int rlen;
   unsigned char buf[128];
   unsigned int n = 1;
   wbuf1 (fileno);
   const char *e = df_dx (d, 0xF5, sizeof (buf), buf, n, 0, 0, &rlen);
   if (e)
      return e;
   if (rlen < 8 || rlen > 18)
      return "Bad file setting length";
   const char typecode[] = "DBVLC";
   if (type && buf[1] < sizeof (typecode))
      *type = typecode[buf[1]];
   if (comms)
      *comms = buf[2];
   if (access)
      *access = buf2 (3);
   if (size && buf[1] != 2)
      *size = buf3 (5);
   if (min && buf[1] == 2)
      *min = buf4 (5);
   if (max && buf[1] == 2)
      *max = buf4 (9);
   if (max && buf[1] >= 3)
      *max = buf3 (8);
   if (recs && buf[1] >= 3)
      *recs = buf3 (11);
   if (limited && buf[1] == 2)
      *limited = buf4 (13);
   if (lc)
      *lc = buf[17];
   return NULL;
}

const char *
df_read_data (df_t * d, unsigned char fileno, unsigned char comms, unsigned int offset, unsigned int len, unsigned char *data)
{
   unsigned int rlen;
   unsigned char buf[len + 32];
   unsigned int n = 1;
   wbuf1 (fileno);
   wbuf3 (offset);
   wbuf3 (len);
   const char *e = df_dx (d, 0xBD, sizeof (buf), buf, n, 0, (comms & DF_MODE_ENC) ? len : 0, &rlen);
   if (e)
      return e;
   if (rlen != len + 1)
      return "Bad rx read file len";
   if (data)
      memcpy (data, buf + 1, len);
   return NULL;
}

const char *
df_read_records (df_t * d, unsigned char fileno, unsigned char comms, unsigned int record,
                 unsigned int recs, unsigned int rsize, unsigned char *data)
{
   unsigned int rlen;
   unsigned char buf[recs * rsize + 32];
   unsigned int n = 1;
   wbuf1 (fileno);
   wbuf3 (record);
   wbuf3 (recs);
   const char *e = df_dx (d, 0xBB, sizeof (buf), buf, n, 0, (comms & DF_MODE_ENC) ? recs * rsize : 0, &rlen);
   if (e)
      return e;
   if (rlen != recs * rsize + 1)
      return "Bad rx read record len";
   if (data)
      memcpy (data, buf + 1, recs * rsize);
   return NULL;
}

const char *
df_get_value (df_t * d, unsigned char fileno, unsigned char comms, unsigned int *value)
{
   unsigned int rlen;
   unsigned char buf[32];
   unsigned int n = 1;
   wbuf1 (fileno);
   const char *e = df_dx (d, 0x6C, sizeof (buf), buf, n, 0, (comms & DF_MODE_ENC) ? 4 : 0, &rlen);
   if (e)
      return e;
   if (rlen != 5)
      return "Bad rx read value len";
   if (value)
      *value = buf4 (1);
   return NULL;
}
