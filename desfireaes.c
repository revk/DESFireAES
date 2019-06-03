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

#include <string.h>
#include <stdio.h>
#include <err.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>

#include "desfireaes.h"

//#define DEBUG

#ifdef DEBUG
static void
dump (const char *prefix, unsigned int len, unsigned char *data)
{
   int n;
   fprintf (stderr, "%-10s", prefix);
   for (n = 0; n < len; n++)
      fprintf (stderr, " %02X", data[n]);
   fprintf (stderr, "\n");
}
#else
#define dump(p,l,d)
#endif

// Simplify buffer loading
#define wbuf1(v) buf[++n]=(v)
#define wbuf2(v) buf[++n]=(v);buf[++n]=(v)>>8
#define wbuf3(v) buf[++n]=(v);buf[++n]=(v)>>8;buf[++n]=(v)>>16
#define wbuf4(v) buf[++n]=(v);buf[++n]=(v)>>8;buf[++n]=(v)>>16;buf[++n]=(v)>>24
#define buf2(n) buf[(n)]+(buf[(n)+1]<<8)
#define buf3(n) buf[(n)]+(buf[(n)+1]<<8)+(buf[(n)+2]<<16)
#define buf4(n) buf[(n)]+(buf[(n)+1]<<8)+(buf[(n)+2]<<16)+(buf[(n)+3]<<24)


unsigned int
df_hex (unsigned int max, unsigned char *dst, const char *src)
{                               // get hex data, return bytes
   unsigned int p = 0;
   while (p < max)
   {
      while (*src && !isxdigit (*src))
         src++;
      if (!*src)
         return p;
      int v = (*src & 15) + (isalpha (*src) ? 9 : 0);
      src++;
      if (isxdigit (*src))
      {
         v = (v << 4) + (*src & 15) + (isalpha (*src) ? 9 : 0);
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
   int n,
     p = 0;
   dump ("CMAC of", len, data);
   unsigned char temp[d->keylen];
   EVP_EncryptInit_ex (d->ctx, d->cipher, NULL, d->sk0, d->cmac);
   EVP_CIPHER_CTX_set_padding (d->ctx, 0);
   while (p + d->keylen < len)
   {                            // Initial blocks
      dump ("Enc", d->keylen, data + p);
      EVP_EncryptUpdate (d->ctx, temp, &n, data + p, d->keylen);
      p += d->keylen;
   }
   // Final block
   memcpy (temp, data + p, (len % d->keylen) ? : d->keylen);
   p = len % d->keylen;
   if (p)
   {                            // pad
      temp[p++] = 0x80;
      while (p < d->keylen)
         temp[p++] = 0;
      for (p = 0; p < d->keylen; p++)
         temp[p] ^= d->sk2[p];
   } else
      for (p = 0; p < d->keylen; p++)
         temp[p] ^= d->sk1[p];
   dump ("Enc", d->keylen, temp);
   EVP_EncryptUpdate (d->ctx, temp, &n, temp, d->keylen);
   EVP_EncryptFinal (d->ctx, temp + n, &n);
   memcpy (d->cmac, temp, d->keylen);
   dump ("CMAC", d->keylen, d->cmac);
}

unsigned int
crc (unsigned int len, unsigned char *data)
{
   //dump ("CRC", len, data);
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

const char *
df_dx (df_t * d, unsigned char cmd, unsigned int len, unsigned char *buf, unsigned int max, int elen,
       unsigned int *rlen, unsigned char mode)
{                               // Data exchange
   if (rlen)
      *rlen = 0;
   unsigned char tmp[17];
   if (!buf && !len)
   {
      buf = tmp;
      max = sizeof (tmp);
   }
   if (!d || !buf)
      return "Bad dx call";
   buf[0] = cmd;
   len++;
   if (mode & DF_MODE_TX_ENC)
   {                            // Encrypt
      if (!d->keylen)
         return "Not authenticated";
      unsigned int offset = (cmd == 0x54 ? 1 : 2);
      int n;
      if (mode & DF_MODE_TX_CRC)
      {                         // Add CRC
         add_crc (len, buf, buf + len);
         len += 4;
      }
      // Padding
      while ((len - offset) % d->keylen)
         buf[len++] = 0;
      dump ("Pre enc", len, buf);
      EVP_EncryptInit_ex (d->ctx, d->cipher, NULL, d->sk0, d->cmac);
      EVP_CIPHER_CTX_set_padding (d->ctx, 0);
      EVP_EncryptUpdate (d->ctx, buf + offset, &n, buf + offset, len - offset);
      EVP_EncryptFinal (d->ctx, buf + offset + n, &n);
      memcpy (d->cmac, buf + len - d->keylen, d->keylen);
   } else
   {
      if (d->keylen)
      {
         cmac (d, len, buf);
         if (mode & DF_MODE_TX_CMAC)
         {                      // Append CMAC
            memcpy (buf + len, d->cmac, 8);
            len += 8;
         }
      }
   }
   unsigned char *p = buf,
      *e = buf + max;
   while (1)
   {
      if (e == p)
         return "No space";
      if (p > buf)
      {                         // More data
         *p = 0xAF;
         len = 1;
      }
      int b = d->dx (d->obj, len, p, e - p);
      if (b < 0)
         return "Rx fail";
      if (!b)
      {
         d->keylen = 0;
         return "";             // Card gone is blank error
      }
      b--;                      // skip status
      if (p > buf)
      {
         *buf = *p;
         if (b)
            memmove (p, p + 1, b);
      } else
         p++;                   // status byte
      p += b;
      if ((mode & DF_IGNORE_AF) || *buf != 0xAF)
         break;
   }
   int l = p - buf - 1;
   if (!(mode & DF_IGNORE_STATUS) && *buf && *buf != 0xAF)
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
   if (mode & DF_MODE_RX_ENC)
   {                            // Decrypt
      if (l > 0)
      {                         // More than just status...
         int n;
         unsigned char cmac[16];
         memcpy (cmac, buf + 1 + l - d->keylen, d->keylen);
         EVP_DecryptInit_ex (d->ctx, d->cipher, NULL, d->sk0, d->cmac);
         EVP_CIPHER_CTX_set_padding (d->ctx, 0);
         EVP_DecryptUpdate (d->ctx, buf + 1, &n, buf + 1, l);
         EVP_DecryptFinal (d->ctx, buf + n, &n);
         memcpy (d->cmac, cmac, d->keylen);
         dump ("Dec", l + 1, buf);
         if (elen >= 0)
         {
            if (l != ((elen + 4) | 15) + 1)
               return "Rx encrypted wrong length";
            unsigned int c = buf4 (1 + elen);
            buf[1 + elen] = buf[0];     // Status at end of playload
            if (c != crc (elen + 1, buf + 1))
               return "Rx CRC fail";
         }
      }
   } else if (d->keylen)
   {                            // Check CMAC
      if (elen || l)
      {
         if (elen >= 0 && l != elen + 8)
            return "Rx unexpected length";
         if (l < 8)
            return "Rx no space for CMAC";
         l -= 8;
         // cmac is of status at END of payload
         unsigned char c1 = buf[l + 1];
         buf[l + 1] = *buf;     // append status
         cmac (d, l + 1, buf + 1);
         buf[l + 1] = c1;       // put back for comparison
         if (memcmp (d->cmac, buf + l + 1, 8))
            return "Rx bad CMAC";
      }
   } else
   {                            // Simple response
      if (elen >= 0 && l != elen)
         return "Rx unexpected length";
   }
   if (rlen)
      *rlen = l;
   return NULL;
}


const char *
df_init (df_t * d, void *obj, df_dx_func_t * dx)
{                               // Initialise
   memset (d, 0, sizeof (*d));
   d->obj = obj;
   d->dx = dx;
   if (!(d->ctx = EVP_CIPHER_CTX_new ()))
      return "Unable to make CTX";
   return NULL;
}

const char *
df_select_application (df_t * d, unsigned char aid[3])
{                               // Select an AID (NULL means AID 0)
   unsigned char buf[17] = { };
   if (aid)
      memcpy (buf + 1, aid, 3);
   const char *e = df_dx (d, 0x5A, 3, buf, sizeof (buf), 0, NULL, 0);
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
   const char *e = df_dx (d, 0x60, 0, buf, sizeof (buf), 28, NULL, 0);
   if (e)
      return e;
   if (ver)
      memcpy (ver, buf + 1, 28);
   return NULL;
}

const char *
df_get_key_settings (df_t * d, unsigned char keyno, unsigned char *setting, unsigned char *keynos)
{
   unsigned char buf[17],
     n = 0;
   wbuf1 (keyno);
   const char *e = df_dx (d, 0x45, n, buf, sizeof (buf), 2, NULL, 0);
   if (e)
      return e;
   if (setting)
      *setting = buf[1];
   if (keynos)
      *keynos = buf[2];
   return e;
}

const char *
df_get_key_version (df_t * d, unsigned char keyno, unsigned char *version)
{
   unsigned char buf[17],
     n = 0;
   wbuf1 (keyno);
   const char *e = df_dx (d, 0x64, n, buf, sizeof (buf), 1, NULL, 0);
   if (e)
      return e;
   if (version)
      *version = buf[1];
   return e;
}

const char *
df_authenticate_general (df_t * d, unsigned char keyno, unsigned char keylen, unsigned char *key, const EVP_CIPHER * cipher)
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
   unsigned char buf[64];
   int n = 0;
   wbuf1 (keyno);
   if ((e = df_dx (d, keylen == 8 ? 0x1A : 0xAA, n, buf, sizeof (buf), keylen, NULL, DF_IGNORE_AF)))
      return e;
   {                            // Create our random A value
      int f = open ("/dev/urandom", O_RDONLY);
      if (f < 0)
         err (1, "random");
      if (read (f, d->sk1, keylen) != keylen)
         err (1, "random");
      close (f);
   }
   // Decode B value
   memset (d->cmac, 0, keylen);
   if (EVP_DecryptInit_ex (d->ctx, cipher, NULL, key, d->cmac) != 1)
      return "Decrypt error";
   EVP_CIPHER_CTX_set_padding (d->ctx, 0);
   if (EVP_DecryptUpdate (d->ctx, d->sk2, &n, buf + 1, keylen) != 1)
      return "Decrypt error";
   if (EVP_DecryptFinal_ex (d->ctx, d->sk2 + n, &n) != 1)
      return "Decrypt error";
   memcpy (d->cmac, buf + 1, keylen);
   // Make response A+B'
   memcpy (buf + 1, d->sk1, keylen);
   memcpy (buf + keylen + 1, d->sk2 + 1, keylen - 1);
   buf[keylen * 2] = d->sk2[0];
   // Encrypt response
   if (EVP_EncryptInit_ex (d->ctx, cipher, NULL, key, d->cmac) != 1)
      return "Encrypt error";
   EVP_CIPHER_CTX_set_padding (d->ctx, 0);
   if (EVP_EncryptUpdate (d->ctx, buf + 1, &n, buf + 1, keylen * 2) != 1)
      return "Encrypt error";
   if (EVP_EncryptFinal_ex (d->ctx, buf + 1 + n, &n) != 1)
      return "Encrypt error";
   memcpy (d->cmac, buf + keylen + 1, keylen);
   // Send response
   if ((e = df_dx (d, 0xAF, keylen * 2, buf, sizeof (buf), keylen, NULL, 0)))
      return e;
   // Decode reply A'
   if (EVP_DecryptInit_ex (d->ctx, cipher, NULL, key, d->cmac) != 1)
      return "Decrypt error";
   EVP_CIPHER_CTX_set_padding (d->ctx, 0);
   if (EVP_DecryptUpdate (d->ctx, buf + 1, &n, buf + 1, keylen) != 1)
      return "Decrypt error";
   if (EVP_DecryptFinal_ex (d->ctx, buf + 1 + n, &n) != 1)
      return "Decrypt error";
   // Check A'
   if (memcmp (buf + 1, d->sk1 + 1, keylen - 1) || buf[keylen] != d->sk1[0])
      return "Auth failed";
   // Mark as logged in
   d->cipher = cipher;
   d->keylen = keylen;
   dump ("A", d->keylen, d->sk1);
   dump ("B", d->keylen, d->sk2);
   return NULL;
}

const char *
df_authenticate (df_t * d, unsigned char keyno, unsigned char key[16])
{                               // Authenticate with a key (AES)
   int n;
   const char *e;
   if ((e = df_authenticate_general (d, keyno, 16, key, EVP_aes_128_cbc ())))
      return e;
   // Make session key (sk1 and sk2 will be left with A and B values)
   memcpy (d->sk0 + 0, d->sk1 + 0, 4);
   memcpy (d->sk0 + 4, d->sk2 + 0, 4);
   memcpy (d->sk0 + 8, d->sk1 + 12, 4);
   memcpy (d->sk0 + 12, d->sk2 + 12, 4);
   // Make SK1
   memset (d->cmac, 0, 16);
   memset (d->sk1, 0, 16);
   if (EVP_EncryptInit_ex (d->ctx, EVP_aes_128_cbc (), NULL, d->sk0, d->cmac) != 1)
      return "Encrypt error";
   EVP_CIPHER_CTX_set_padding (d->ctx, 0);
   if (EVP_EncryptUpdate (d->ctx, d->sk1, &n, d->sk1, 16) != 1)
      return "Encrypt error";
   if (EVP_EncryptFinal (d->ctx, d->sk1 + n, &n) != 1)
      return "Encrypt error";
   // Shift SK1
   unsigned char xor = 0;
   if (d->sk1[0] & 0x80)
      xor = 0x87;
   for (n = 0; n < 16 - 1; n++)
      d->sk1[n] = (d->sk1[n] << 1) | (d->sk1[n + 1] >> 7);
   d->sk1[16 - 1] <<= 1;
   d->sk1[16 - 1] ^= xor;
   // Make SK2
   memcpy (d->sk2, d->sk1, 16);
   // Shift SK2
   xor = 0;
   if (d->sk2[0] & 0x80)
      xor = 0x87;
   for (n = 0; n < 16 - 1; n++)
      d->sk2[n] = (d->sk2[n] << 1) | (d->sk2[n + 1] >> 7);
   d->sk2[16 - 1] <<= 1;
   d->sk2[16 - 1] ^= xor;
   // Reset CMAC
   memset (d->cmac, 0, 16);
   dump ("SK0", 16, d->sk0);
   dump ("SK1", 16, d->sk1);
   dump ("SK2", 16, d->sk2);
   return NULL;                 // All ready
}

const char *
df_des_authenticate (df_t * d, unsigned char keyno, unsigned char key[8])
{
   const char *e;
   if ((e = df_authenticate_general (d, keyno, 8, key, EVP_des_cbc ())))
      return e;
   memcpy (d->sk0 + 0, d->sk1 + 0, 4);
   memcpy (d->sk0 + 4, d->sk2 + 0, 4);
   memset (d->cmac, 0, sizeof (d->cmac));
   // we don't need to make SK1/2 really do we?
   return NULL;
}

const char *
df_change_key_settings (df_t * d, unsigned char settings)
{                               // Change settings for current key
   if (!d->keylen)
      return "Not authenticated";
   unsigned char buf[32],
     n = 0;
   wbuf1 (settings);
   return df_dx (d, 0x54, n, buf, sizeof (buf), 0, NULL, DF_MODE_TX_ENC | DF_MODE_TX_CRC);
}

const char *
df_set_configuration (df_t * d, unsigned char settings)
{                               // Change settings for current key
   if (!d->keylen)
      return "Not authenticated";
   unsigned char buf[32],
     n = 0;
   wbuf1 (0);
   wbuf1 (settings);
   return df_dx (d, 0x5C, 2, buf, sizeof (buf), 0, NULL, DF_MODE_TX_ENC | DF_MODE_TX_CRC);
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
      n = 26;
   } else
      n = 22;
   if ((e = df_dx (d, buf[0], n, buf, sizeof (buf), 0, NULL, DF_MODE_TX_ENC)))  // CRC already sorted above
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
      if ((e = df_des_authenticate (d, 0, key)))
         return e;
      d->keylen = 0;            // We don't CMAC DES, so don't check response CMAC, assume it worked
      if ((e = df_dx (d, 0xFC, 0, NULL, 0, -1, NULL, 0)))
         return e;
      // Auth again as we did not track CMAC so cannot do key change without
      if ((e = df_des_authenticate (d, 0, key)))
         return e;
      if ((e = df_change_key (d, 0x80, 1, NULL, NULL)))
         return e;
   } else
   {                            // AES
      if ((e = df_authenticate (d, 0, key)))
         return e;
      if ((e = df_dx (d, 0xFC, 0, NULL, 0, 0, NULL, 0)))
         return e;
      if (memcmp (key, zero, 16) && (e = df_change_key (d, 0, 1, key, NULL)))
         return e;
   }
   return NULL;
}

const char *
df_commit (df_t * d)
{                               // Commit
   return df_dx (d, 0xC7, 0, NULL, 0, 0, NULL, 0);
}

const char *
df_abort (df_t * d)
{                               // Abort
   return df_dx (d, 0xA7, 0, NULL, 0, 0, NULL, 0);
}

const char *
df_get_application_ids (df_t * d, unsigned int *num, unsigned int space, unsigned char *aids)
{
   if (num)
      *num = 0;
   unsigned int rlen;
   unsigned char buf[1000];
   const char *e = df_dx (d, 0x6A, 0, buf, sizeof (buf), -1, &rlen, 0);
   if (e)
      return e;
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
   return df_dx (d, 0xDA, 3, NULL, 0, 0, NULL, 0);
}

const char *
df_create_application (df_t * d, unsigned char aid[3], unsigned char settings, unsigned char keys)
{
   unsigned char buf[32];
   memcpy (buf + 1, aid, 3);
   buf[4] = settings;
   buf[5] = (0x80 | keys);      // Always AES
   return df_dx (d, 0xCA, 5, buf, sizeof (buf), 0, NULL, 0);
}

const char *
df_write_data (df_t * d, unsigned char fileno, char type, unsigned char comms, unsigned int offset, unsigned int len,
               const void *data)
{
   if (type != 'D' && type != 'B' && type != 'L' && type != 'C')
      return "Bad file type";
   unsigned int max = 26;       // Send in blocks
   const char *e;
   while (len)
   {
      int l = len;
      if (l > max)
         l = max;
      unsigned char buf[max + 32],
        n = 0;
      wbuf1 (fileno);
      wbuf3 (offset);
      wbuf3 (l);
      memcpy (buf + n + 1, data, l);
      n += l;
      if ((e = df_dx (d, type == 'D' ? 0x3D : 0x3B, n, buf, max + 32, 0, NULL, comms & DF_MODE_MASK)))
         return e;
      len -= l;
      data += l;
      offset += l;
   }
   return NULL;
}

const char *
df_delete_file (df_t * d, unsigned char fileno)
{
   unsigned char buf[32];
   buf[1] = fileno;
   return df_dx (d, 0xDF, 1, buf, sizeof (buf), 0, NULL, 0);
}

const char *
df_get_uid (df_t * d, unsigned char uid[7])
{
   if (!d->keylen)
      return "Not authenticated";
   unsigned char buf[64];
   const char *e = df_dx (d, 0x51, 0, buf, sizeof (buf), 7, NULL, DF_MODE_RX_ENC);
   if (e)
      return e;
   if (uid)
      memcpy (uid, buf + 1, 7);
   return NULL;

}

const char *
df_free_memory (df_t * d, unsigned int *mem)
{
   unsigned char buf[32];
   const char *e = df_dx (d, 0x6E, 0, buf, sizeof (buf), 3, NULL, 0);
   if (e)
      return e;
   if (mem)
      *mem = buf3 (1);
   return NULL;
}

const char *
df_get_file_ids (df_t * d, unsigned long long *ids)
{
   unsigned int rlen;
   unsigned char buf[128];
   const char *e = df_dx (d, 0x6F, 0, buf, sizeof (buf), -1, &rlen, 0);
   if (e)
      return e;
   if (!ids)
      return NULL;
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
   unsigned char buf[32],
     n = 0;
   wbuf1 (fileno);
   wbuf1 (comms);
   wbuf2 (access);
   if (type == 'V')
   {                            // Value file
      wbuf4 (min);
      wbuf4 (max);
      wbuf4 (value);
      wbuf1 (lc);
      return df_dx (d, 0xCC, n, buf, sizeof (buf), 0, NULL, 0);
   }
   if (type == 'C' || type == 'L')
   {                            // Cyclic or linear
      wbuf3 (size);
      wbuf3 (recs);
      return df_dx (d, type == 'C' ? 0xC0 : 0xC1, n, buf, sizeof (buf), 0, NULL, 0);
   }
   if (type == 'D' || type == 'B')
   {                            // Data or backup
      wbuf3 (size);
      return df_dx (d, type == 'D' ? 0xCD : 0xCB, n, buf, sizeof (buf), 0, NULL, 0);
   }
   return "Unknown file type";
}

const char *
df_get_file_settings (df_t * d, unsigned char fileno, char *type, unsigned char *comms, unsigned short *access,
                      unsigned int *size, unsigned int *min, unsigned int *max, unsigned int *recs,
                      unsigned int *limited, unsigned char *lc)
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
   unsigned char buf[128],
     n = 0;
   wbuf1 (fileno);
   const char *e = df_dx (d, 0xF5, n, buf, sizeof (buf), -1, &rlen, 0);
   if (e)
      return e;
   if (rlen < 7 || rlen > 17)
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
   unsigned char buf[len + 32],
     n = 0;
   wbuf1 (fileno);
   wbuf3 (offset);
   wbuf3 (len);
   const char *e = df_dx (d, 0xBD, n, buf, sizeof (buf), len, NULL, comms & DF_MODE_MASK);
   if (e)
      return e;
   if (data)
      memcpy (data, buf + 1, len);
   return NULL;
}

const char *
df_read_records (df_t * d, unsigned char fileno, unsigned char comms, unsigned int record, unsigned int recs,
                 unsigned int rsize, unsigned char *data)
{
   unsigned char buf[recs * rsize + 32],
     n = 0;
   wbuf1 (fileno);
   wbuf3 (record);
   wbuf3 (recs);
   const char *e = df_dx (d, 0xBB, n, buf, sizeof (buf), recs * rsize, NULL, (comms & DF_MODE_MASK) << DF_MODE_SHIFT);
   if (e)
      return e;
   if (data)
      memcpy (data, buf + 1, recs * rsize);
   return NULL;
}

const char *
df_get_value (df_t * d, unsigned char fileno, unsigned char comms, unsigned int *value)
{
   unsigned char buf[32],
     n = 0;
   wbuf1 (fileno);
   const char *e = df_dx (d, 0x6C, n, buf, sizeof (buf), 4, NULL, (comms & DF_MODE_MASK) << DF_MODE_SHIFT);
   if (e)
      return e;
   if (value)
      *value = buf4 (1);
   return NULL;
}
