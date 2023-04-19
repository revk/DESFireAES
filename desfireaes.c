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
#include <aes/esp_aes.h>
#include "esp_log.h"
#include "esp_random.h"
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
//#define DEBUG_CMAC

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
static void
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
#define decrypt(ctx,cipher,blocklen,key,iv,out,in,len) aes_decrypt(key,iv,out,in,len)
static const char *
aes_decrypt (const unsigned char *key, unsigned char *iv, unsigned char *out, const unsigned char *in, int len)
{ // Always AES
   if (len <= 0)
      return NULL;
   len = (len + 15) / 16 * 16;
   //ESP_LOG_BUFFER_HEX_LEVEL ("AES Dec", key, 16, ESP_LOG_INFO);
   //ESP_LOG_BUFFER_HEX_LEVEL ("AES In ", in, len, ESP_LOG_INFO);
   esp_aes_context ctx;
   esp_aes_init (&ctx);
   esp_err_t err = esp_aes_setkey (&ctx, key, 16 * 8);
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
decrypt (EVP_CIPHER_CTX * ctx, const EVP_CIPHER * cipher, int blocklen, const unsigned char *key, unsigned char *iv,
         unsigned char *out, const unsigned char *in, int len)
{
   len = (len + blocklen - 1) / blocklen * blocklen;
   unsigned char newiv[blocklen];
   memcpy (newiv, in + len - blocklen, blocklen);
   if (EVP_DecryptInit_ex (ctx, cipher, NULL, key, iv) != 1)
      return "Decrypt error";
   EVP_CIPHER_CTX_set_padding (ctx, 0);
   int n;
   if (EVP_DecryptUpdate (ctx, out, &n, in, len) != 1)
      return "Decrypt error";
   if (EVP_DecryptFinal_ex (ctx, out + n, &n) != 1)
      return "Decrypt error";
   memcpy (iv, newiv, blocklen);
   return NULL;
}
#endif

// Encrypt, updating iv
#ifdef	ESP_PLATFORM
#define doencrypt(ctx,cipher,blocklen,key,iv,out,in,len) aes_encrypt(key,iv,out,in,len)
static const char *
aes_encrypt (const unsigned char *key, unsigned char *iv, unsigned char *out, const unsigned char *in, int len)
{ // Always AES
   if (len <= 0)
      return NULL;
   len = (len + 15) / 16 * 16;
   //ESP_LOG_BUFFER_HEX_LEVEL ("AES Enc", key, 16, ESP_LOG_INFO);
   //ESP_LOG_BUFFER_HEX_LEVEL ("AES In ", in, len, ESP_LOG_INFO);
   esp_aes_context ctx;
   esp_aes_init (&ctx);
   esp_err_t err = esp_aes_setkey (&ctx, key, blocklen * 8);
   if (!err)
   {
      unsigned char *o = out;
      if (!out)
         o = malloc (len);     
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
doencrypt (EVP_CIPHER_CTX * ctx, const EVP_CIPHER * cipher, int blocklen, const unsigned char *key, unsigned char *iv,
           unsigned char *out, const unsigned char *in, int len)
{
   len = (len + blocklen - 1) / blocklen * blocklen;
   if (EVP_EncryptInit_ex (ctx, cipher, NULL, key, iv) != 1)
      return "Encrypt error";
   unsigned char *o = out;
   if (!out)
      o = malloc (len);       
   EVP_CIPHER_CTX_set_padding (ctx, 0);
   int n;
   if (EVP_EncryptUpdate (ctx, o, &n, in, len) != 1 || EVP_EncryptFinal_ex (ctx, o + n, &n) != 1)
   {
      if (!out)
         free (o);
      return "Encrypt error";
   }
   memcpy (iv, o + len - blocklen, blocklen);
   if (!out)
      free (o);
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
#ifdef DEBUG_CMAC
   dump ("CMAC of", len, data);
#endif
   unsigned char temp[d->blocklen];     // For last block
   int last = len - (len % d->blocklen ? : len ? d->blocklen : 0);
   int p = len - last;
   if (p)
      memcpy (temp, data + last, p);
   if (p && p < d->blocklen)
   {                            // pad
      temp[p++] = 0x80;
      while (p < d->blocklen)
         temp[p++] = 0;
      for (p = 0; p < d->blocklen; p++)
         temp[p] ^= d->sk2[p];
   } else
      for (p = 0; p < d->blocklen; p++)
         temp[p] ^= d->sk1[p];
   if (last)
      doencrypt (d->ctx, d->cipher, d->blocklen, d->sk0, d->cmac, NULL, data, last);
   if (last < len)
      doencrypt (d->ctx, d->cipher, d->blocklen, d->sk0, d->cmac, NULL, temp, len - last);
#ifdef DEBUG_CMAC
   dump ("CMAC", d->blocklen, d->cmac);
#endif
}

unsigned int
df_crc (unsigned int len, const unsigned char *data)
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

static int
add_crc (unsigned int len, const unsigned char *src, unsigned char *dst)
{
   unsigned int c = df_crc (len, src);
   dst[0] = c;
   dst[1] = c >> 8;
   dst[2] = c >> 16;
   dst[3] = c >> 24;
   return 4;                    // Len
}

const char *
df_err (unsigned char c)
{                               // Error code name
   switch (c)
   {
   case 0x00:
      return "OK";
   case 0x0C:
      return "No change";
   case 0x0E:
      return "Out of EEPROM";
   case 0x1C:
      return "Illegal command";
   case 0x1E:
      return "Integrity error";
   case 0x40:
      return "No such file";
   case 0x7E:
      return "Length error";
   case 0x97:
      return "Crypto error";
   case 0x9D:
      return "Permission denied";
   case 0x9E:
      return "Parameter error";
   case 0xA0:
      return "Application not found";
   case 0xAE:
      return "Authentication error";
   case 0xAF:
      return "More";
   case 0xBE:
      return "Boundary error";
   case 0xC1:
      return "Card integrity error";
   case 0xCA:
      return "Command aborted";
   case 0xCD:
      return "Card disabled";
   case 0xCE:
      return "Count error";
   case 0xDE:
      return "Duplicate error";
   case 0xEE:
      return "EEPROM error";
   case 0xF0:
      return "File not found";
   case 0xF1:
      return "File integrity found";
   }
   return "Rx status error response";
}

#define TXMAX 55
const char *
df_dx (df_t * d, unsigned char cmd, unsigned int max, unsigned char *buf, unsigned int len, unsigned char txenc,
       unsigned char rxenc, unsigned int *rlen, const char *name)
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
      d->blocklen = 0;
   if (d->blocklen)
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
            len += add_crc (len, buf, buf + len);       // Add CRC (C4 is special case as multiple CRCs and padding)
         // Padding
         while ((len - txenc) % d->blocklen)
            buf[len++] = 0;
         dump ("Pre enc", len, buf);
         doencrypt (d->ctx, d->cipher, d->blocklen, d->sk0, d->cmac, buf + txenc, buf + txenc, len - txenc);
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
         const char *errstr = name;
         int b = d->dx (d->obj, TXMAX, p, 1, &errstr);
         if (b < 0)
         {
            if (!errstr || errstr == name)
               errstr = "Dx fail";
            return errstr;
         }
         dump ("Rx(raw)", b, p);
         if (!b)
         {
            d->blocklen = 0;
            return "";          // Card gone
         }
         if (*p != 0xAF)
         {
            d->blocklen = 0;
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
         const char *errstr = name;
         int b = d->dx (d->obj, len, p, e - p, &errstr);
         if (b < 0)
         {
            if (!errstr || errstr == name)
               errstr = "Dx fail";
            return errstr;
         }
         dump ("Rx(raw)", b, p);
         if (!b)
         {
            d->blocklen = 0;
            return "";          // Card gone
         }
         if (p > buf)
         {                      // Move status back
            *buf = *p;
            memmove (p, p + 1, --b);
         }
         if (!b && *buf == 0xAF)
            break;              // we have no data to send
         p += b;
         if (*buf != 0xAF || cmd == 0xAA || cmd == 0x1A || cmd == 0x0A)
            break;              // done
         if (p == e)
            return "Rx No space";
         len = 1;               // Next part to send
         *p = 0xAF;
         name = "More";
      }
      len = p - buf;
   }
   // Post process
   if (d->blocklen)
   {
      if (rxenc)
      {                         // Encrypted
         if (len != ((rxenc + 3) | 15) + 2)
            return "Rx Bad encrypted length";
         decrypt (d->ctx, d->cipher, d->blocklen, d->sk0, d->cmac, buf + 1, buf + 1, len - 1);
         dump ("Dec", len, buf);
         unsigned int c = buf4 (rxenc);
         buf[rxenc] = buf[0];   // Status at end of payload
         if (c != df_crc (rxenc, buf + 1))
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
      d->blocklen = 0;          // Errors kick us out
      return df_err (*buf);
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
df_select_application (df_t * d, const unsigned char aid[3])
{                               // Select an AID (NULL means AID 0)
   unsigned char buf[17] = { };
   if (aid)
      memcpy (buf + 1, aid, 3);
   const char *e = df_dx (d, 0x5A, sizeof (buf), buf, 4, 0, 0, NULL, "Select Application");
   if (e || !aid)
      memset (d->aid, 0, sizeof (d->aid));
   else
      memcpy (d->aid, aid, sizeof (d->aid));
   d->blocklen = 0;
   return e;
}

const char *
df_get_version (df_t * d, unsigned char ver[28])
{
   unsigned char buf[64];
   unsigned int rlen;
   const char *e = df_dx (d, 0x60, sizeof (buf), buf, 1, 0, 0, &rlen, "Get version");
   if (e)
      return e;
   if (rlen != 29)
      return "Bad length for Get Version";
   if (ver)
      memcpy (ver, buf + 1, rlen - 1);
   return NULL;
}

const char *
df_get_key_settings (df_t * d, unsigned char *setting, unsigned char *keynos)
{
   unsigned int rlen;
   unsigned char buf[17];
   unsigned int n = 1;
   const char *e = df_dx (d, 0x45, sizeof (buf), buf, n, 0, 0, &rlen, "Get Key Settings");
   if (e)
      return e;
   if (rlen != 3)
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
   const char *e = df_dx (d, 0x64, sizeof (buf), buf, n, 0, 0, &rlen, "Get Key Version");
   if (e)
      return e;
   if (rlen != 2)
      return "Bad length for get Key Version";
   if (version)
      *version = buf[1];
   return e;
}

const char *
df_authenticate_general (df_t * d, unsigned char keyno, unsigned char blocklen, const unsigned char *key
#ifndef	ESP_PLATFORM
                         , const EVP_CIPHER * cipher
#endif
   )
{                               // Authenticate for specified key len
   unsigned char zero[16] = { 0 };
   if (!key)
      key = zero;
   d->blocklen = 0;
   d->keyno = (keyno & 15);
   const char *e;
   unsigned int rlen;
   unsigned char buf[64];
   unsigned int n = 1;
   wbuf1 (keyno);
   if ((e =
        df_dx (d, blocklen == 8 ? 0x1A : 0xAA, sizeof (buf), buf, n, 0, 0, &rlen,
               blocklen == 8 ? "Authenticate DES" : "Authenticate AES")))
      return e;
   if (rlen != blocklen + 1)
      return "Bad response length for auth";
   fill_random (d->sk1, blocklen);
   // Decode B value
   memset (d->cmac, 0, blocklen);
   decrypt (d->ctx, cipher, blocklen, key, d->cmac, d->sk2, buf + 1, blocklen);
   // Make response A+B'
   memcpy (buf + 1, d->sk1, blocklen);
   memcpy (buf + blocklen + 1, d->sk2 + 1, blocklen - 1);
   buf[blocklen * 2] = d->sk2[0];
   // Encrypt response
   doencrypt (d->ctx, cipher, blocklen, key, d->cmac, buf + 1, buf + 1, blocklen * 2);
   // Send response
   if ((e = df_dx (d, 0xAF, sizeof (buf), buf, 1 + blocklen * 2, 0, 0, &rlen, "Handshake")))
      return e;
   if (rlen != blocklen + 1)
      return "Bad response length for auth";
   // Decode reply A'
   if ((e = decrypt (d->ctx, cipher, blocklen, key, d->cmac, buf + 1, buf + 1, blocklen)))
      return e;
   // Check A'
   if (memcmp (buf + 1, d->sk1 + 1, blocklen - 1) || buf[blocklen] != d->sk1[0])
      return "Auth failed";
   // Mark as logged in
   dump ("A", blocklen, d->sk1);
   dump ("B", blocklen, d->sk2);
   memcpy (d->sk0 + 0, d->sk1 + 0, 4);
   memcpy (d->sk0 + 4, d->sk2 + 0, 4);
   if (blocklen > 8)
   {
      memcpy (d->sk0 + 8, d->sk1 + 12, 4);
      memcpy (d->sk0 + 12, d->sk2 + 12, 4);
   }
#ifndef ESP_PLATFORM
   else
      cipher = EVP_des_cbc ();  // Ongoing is simple DES not 2TDEA
   d->cipher = cipher;
#endif
   d->blocklen = blocklen;
   // Make SK1
   memset (d->cmac, 0, blocklen);
   memset (d->sk1, 0, blocklen);
   if ((e = doencrypt (d->ctx, cipher, blocklen, d->sk0, d->cmac, d->sk1, d->sk1, blocklen)))
      return e;
   // Shift SK1
   unsigned char xor = 0;
   if (d->sk1[0] & 0x80)
      xor = (blocklen == 8 ? 0x1B : 0x87);
   for (n = 0; n < blocklen - 1; n++)
      d->sk1[n] = (d->sk1[n] << 1) | (d->sk1[n + 1] >> 7);
   d->sk1[blocklen - 1] <<= 1;
   d->sk1[blocklen - 1] ^= xor;
   // Make SK2
   memcpy (d->sk2, d->sk1, blocklen);
   // Shift SK2
   xor = 0;
   if (d->sk2[0] & 0x80)
      xor = (blocklen == 8 ? 0x1B : 0x87);
   for (n = 0; n < blocklen - 1; n++)
      d->sk2[n] = (d->sk2[n] << 1) | (d->sk2[n + 1] >> 7);
   d->sk2[blocklen - 1] <<= 1;
   d->sk2[blocklen - 1] ^= xor;
   // Reset CMAC
   memset (d->cmac, 0, blocklen);
   dump ("SK0", blocklen, d->sk0);
   dump ("SK1", blocklen, d->sk1);
   dump ("SK2", blocklen, d->sk2);
   return NULL;
}

const char *
df_authenticate (df_t * d, unsigned char keyno, const unsigned char key[16])
{                               // Authenticate with a key (AES)
   return df_authenticate_general (d, keyno, 16, key
#ifndef	ESP_PLATFORM
                                   , EVP_aes_128_cbc ()
#endif
      );
}

int
df_isauth (df_t * d)
{                               // Is authenticated
   return d->blocklen;          // Set when authentication is complete, and cleared for cases that lose it
}

#ifndef	ESP_PLATFORM
const char *
df_des_authenticate (df_t * d, unsigned char keyno, const unsigned char key[16])
{                               // Authenticate with 3DES - used to convert card to AES
   return df_authenticate_general (d, keyno, 8, key, EVP_des_ede_cbc ());
}
#endif

const char *
df_change_file_settings (df_t * d, unsigned char fileno, unsigned char comms, unsigned short oldaccess, unsigned short access)
{                               // Change settings for current key
   if (!d->blocklen)
      return "Not authenticated";
   unsigned char buf[32];
   unsigned int n = 1;
   wbuf1 (fileno);
   wbuf1 (comms);
   wbuf2 (access);
   return df_dx (d, 0x5F, sizeof (buf), buf, n, (oldaccess & 15) == 14 ? 0 : 2, 0, NULL, "Change File Settings");
}

const char *
df_change_key_settings (df_t * d, unsigned char settings)
{                               // Change settings for current key
   if (!d->blocklen)
      return "Not authenticated";
   unsigned char buf[32];
   unsigned int n = 1;
   wbuf1 (settings);
   return df_dx (d, 0x54, sizeof (buf), buf, n, 1, 0, NULL, "Change Key Settings");
}

const char *
df_set_configuration (df_t * d, unsigned char settings)
{                               // Change settings for current key
   if (!d->blocklen)
      return "Not authenticated";
   unsigned char buf[32];
   unsigned int n = 1;
   wbuf1 (0);
   wbuf1 (settings);
   return df_dx (d, 0x5C, sizeof (buf), buf, n, 2, 0, NULL, "Set Configuration");
}

const char *
df_change_key (df_t * d, unsigned char keyno, unsigned char version, const unsigned char old[16], const unsigned char key[16])
{
   const char *e;
   unsigned char zero[16] = { 0 };
   if (!key)
      key = zero;
   if (!old)
      old = zero;
   unsigned char buf[64] = { 0 };
   int n = 0;
   wbuf1 (0xC4);                // Needs setting as we make the CRCs here not in df_dx
   wbuf1 (keyno);
   keyno &= 15;
   memcpy (buf + n, key, 16);
   n += 16;
   buf[n++] = version;
   n += add_crc (n, buf, buf + n);
   if (keyno != d->keyno)
   {                            // Changing different key
      for (int q = 0; q < 16; q++)
         buf[2 + q] ^= old[q];
      n += add_crc (16, key, buf + n);
   }
   if ((e = df_dx (d, *buf, sizeof (buf), buf, n, 2, 0, NULL, "Change Key")))
      return e;
   if (keyno == d->keyno)
      d->blocklen = 0;          // No longer secure;
   return NULL;
}

const char *
df_format (df_t * d, unsigned char version, const unsigned char key[16])
{                               // Format card
   // Card can be brand new with zero DES key - changed to AES
   // Card can have zero AES key
   // Card can have AES key as provided
   // End result if success is formatted using AES key as provided (or zero AES key)
   // Leaves authenticated with new key as AID 0
   unsigned char zero[24] = {
      0
   };
   const unsigned char *currentkey = NULL;
   const char *e = NULL;
   // Get out of existing application / session first
   if ((d->blocklen || d->aid[0] || d->aid[1] || d->aid[1]) && (e = df_select_application (d, NULL)))
      return e;
   e = "Not formatted";
   // Try supplied key
   if (e && key)
      e = df_authenticate (d, 0, currentkey = key);
   // Try zero AES key
   if (e)
      e = df_authenticate (d, 0, currentkey = zero);
   if (!e)
      e = df_dx (d, 0xFC, 0, NULL, 1, 0, 0, NULL, "Format");    // Not DES, format (does not change key)
#ifndef	ESP_PLATFORM
   else
   {                            // If all else fails, try DES with zero key
      e = df_des_authenticate (d, 0, currentkey = zero);
      if (!e)
         e = df_dx (d, 0xFC, 0, NULL, 1, 0, 0, NULL, "Format"); // Format the card anyway in case DES had stuff
      if (!e)
         e = df_change_key (d, 0x80, 0, NULL, NULL);    // Change to AES
   }
#endif
   if (!e)
      e = df_authenticate (d, 0, currentkey);   // Re-auth after format or change key
   if (!e)
   {                            // Set key if needed
      if (!key)
         key = zero;
      unsigned char currentversion = 0;
      e = df_get_key_version (d, 0, &currentversion);
      if (!e && (currentversion != version || memcmp (currentkey, key, 16)))
         e = df_change_key (d, 0x80, version, currentkey, key);
      if (!e)
         e = df_authenticate (d, 0, key);       // Re-auth after format or change key
   }
   return e;
}

const char *
df_commit (df_t * d)
{                               // Commit
   return df_dx (d, 0xC7, 0, NULL, 1, 0, 0, NULL, "Commit");
}

const char *
df_abort (df_t * d)
{                               // Abort
   return df_dx (d, 0xA7, 0, NULL, 1, 0, 0, NULL, "Abort");
}

const char *
df_get_application_ids (df_t * d, unsigned int *num, unsigned int space, unsigned char *aids)
{
   if (num)
      *num = 0;
   unsigned int rlen;
   unsigned char buf[1000];
   const char *e = df_dx (d, 0x6A, sizeof (buf), buf, 1, 0, 0, &rlen, "Get Application IDs");
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
df_delete_application (df_t * d, const unsigned char aid[3])
{
   unsigned char buf[32] = { 0 };
   memcpy (buf + 1, aid, 3);
   return df_dx (d, 0xDA, sizeof (buf), buf, 4, 0, 0, NULL, "Delete Application");
}

const char *
df_create_application (df_t * d, const unsigned char aid[3], unsigned char settings, unsigned char keys)
{
   unsigned char buf[32];
   memcpy (buf + 1, aid, 3);
   buf[4] = settings;
   buf[5] = (0x80 | keys);      // Always AES
   return df_dx (d, 0xCA, sizeof (buf), buf, 6, 0, 0, NULL, "Create Application");
}

const char *
df_write_data (df_t * d, unsigned char fileno, char type, unsigned char comms, unsigned int offset, unsigned int len,
               const void *data)
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
                 0, NULL, "Write Data");
}

const char *
df_delete_file (df_t * d, unsigned char fileno)
{
   unsigned char buf[32];
   unsigned int n = 1;
   wbuf1 (fileno);
   return df_dx (d, 0xDF, sizeof (buf), buf, n, 0, 0, NULL, "Delete File");
}

const char *
df_get_uid (df_t * d, unsigned char uid[7])
{
   if (!d->blocklen)
      return "Not authenticated";
   unsigned char buf[64];
   const char *e = df_dx (d, 0x51, sizeof (buf), buf, 1, 0, 8, NULL, "Get UID");
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
   const char *e = df_dx (d, 0x6E, sizeof (buf), buf, 1, 0, 0, &rlen, "Free memory");
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
   const char *e = df_dx (d, 0x6F, sizeof (buf), buf, 1, 0, 0, &rlen, "Get File IDs");
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
df_create_file (df_t * d, unsigned char fileno, char type, unsigned char comms, unsigned short access, unsigned int size,
                unsigned int min, unsigned int max, unsigned int recs, unsigned int value, unsigned char lc)
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
      return df_dx (d, 0xCC, sizeof (buf), buf, n, 0, 0, NULL, "Create Value File");
   }
   if (type == 'C' || type == 'L')
   {                            // Cyclic or linear
      wbuf3 (size);
      wbuf3 (recs);
      return df_dx (d, type == 'C' ? 0xC0 : 0xC1, sizeof (buf), buf, n, 0, 0, NULL,
                    type == 'C' ? "Create Cyclic File" : "Create Linear File");
   }
   if (type == 'D' || type == 'B')
   {                            // Data or backup
      wbuf3 (size);
      return df_dx (d, type == 'D' ? 0xCD : 0xCB, sizeof (buf), buf, n, 0, 0, NULL,
                    type == 'D' ? "Create Data File" : "Create Backup File");
   }
   return "Unknown file type";
}

const char *
df_get_file_settings (df_t * d, unsigned char fileno, char *type, unsigned char *comms, unsigned short *access, unsigned int *size,
                      unsigned int *min, unsigned int *max, unsigned int *recs, unsigned int *limited, unsigned char *lc)
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
   const char *e = df_dx (d, 0xF5, sizeof (buf), buf, n, 0, 0, &rlen, "Get File Settings");
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
   const char *e = df_dx (d, 0xBD, sizeof (buf), buf, n, 0, (comms & DF_MODE_ENC) ? 8 : 0, &rlen, "Read Data");
   if (e)
      return e;
   if (rlen != len + 1)
      return "Bad rx read file len";
   if (data)
      memcpy (data, buf + 1, len);
   return NULL;
}

const char *
df_read_records (df_t * d, unsigned char fileno, unsigned char comms, unsigned int record, unsigned int recs, unsigned int rsize,
                 unsigned char *data)
{
   unsigned int rlen;
   unsigned char buf[recs * rsize + 32];
   unsigned int n = 1;
   wbuf1 (fileno);
   wbuf3 (record);
   wbuf3 (recs);
   const char *e = df_dx (d, 0xBB, sizeof (buf), buf, n, 0, (comms & DF_MODE_ENC) ? recs * rsize : 0, &rlen, "Read Records");
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
   const char *e = df_dx (d, 0x6C, sizeof (buf), buf, n, 0, (comms & DF_MODE_ENC) ? 4 : 0, &rlen, "Get Value");
   if (e)
      return e;
   if (rlen != 5)
      return "Bad rx read value len";
   if (value)
      *value = buf4 (1);
   return NULL;
}

const char *
df_credit (df_t * d, unsigned char fileno, unsigned char comms, unsigned int delta)
{
   unsigned char buf[32];
   unsigned int n = 1;
   wbuf1 (fileno);
   wbuf4 (delta);
   return df_dx (d, 0x0C, sizeof (buf), buf, n, (comms & DF_MODE_CMAC) ? 0xFF : 0, 0, NULL, "Credit");
}

const char *
df_limited_credit (df_t * d, unsigned char fileno, unsigned char comms, unsigned int delta)
{
   unsigned char buf[32];
   unsigned int n = 1;
   wbuf1 (fileno);
   wbuf4 (delta);
   return df_dx (d, 0x1C, sizeof (buf), buf, n, (comms & DF_MODE_CMAC) ? 0xFF : 0, 0, NULL, "Limited Credit");
}

const char *
df_debit (df_t * d, unsigned char fileno, unsigned char comms, unsigned int delta)
{
   unsigned char buf[32];
   unsigned int n = 1;
   wbuf1 (fileno);
   wbuf4 (delta);
   return df_dx (d, 0xDC, sizeof (buf), buf, n, (comms & DF_MODE_CMAC) ? 0xFF : 0, 0, NULL, "Debit");
}
