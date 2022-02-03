/* Library for PN532 access */
/* (c) Copyright 2022 Andrews & Arnold Ltd, Adrian Kennard */
/*
 * This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <unistd.h>
#include <stdio.h>
#include <sys/select.h>
#include <string.h>
#include <alloca.h>
#include "pn532.h"
#include <openssl/evp.h>
#include "desfireaes.h"

/* #define DEBUGLOW */
extern int      debug;

static int
pn532_get(int s, unsigned int us)
{
   fd_set          r;
   FD_ZERO(&r);
   FD_SET(s, &r);
   struct timeval  t = {0, us};
   if (select(s + 1, &r, NULL, NULL, &t) < 1)
      return -1;
   unsigned char   b = 0;
   if (read(s, &b, 1) != 1)
      return -1;
   return b;
}

static int
uart_rx(int s, unsigned char *buf, int len, int ms)
{
   int             l = 0,
                   v;
   while (l < len && (v = pn532_get(s, ms * 1000)) >= 0)
      buf[l++] = v;
   if (s < 0)
      return -1;
#ifdef	DEBUGLOW
   fprintf(stderr, "<");
   for (int i = 0; i < len; i++)
      fprintf(stderr, "%02X ", buf[i]);
   fprintf(stderr, "(%d)\n", len);
#endif
   return l;
}

static void
pn532_put(int s, unsigned char b)
{
   write(s, &b, 1);
}

static void
uart_tx(int s, unsigned char *buf, int len)
{
   for (int l = 0; l < len; l++)
      pn532_put(s, buf[l]);
#ifdef	DEBUGLOW
   fprintf(stderr, ">");
   for (int i = 0; i < len; i++)
      fprintf(stderr, "%02X ", buf[i]);
   fprintf(stderr, "(%d)\n", len);
#endif
   usleep(len * 1000000 / 115200 / 10);
}

static int
uart_preamble(int s, int ms)
{                               /* Wait for preamble */
   unsigned char   last = 0xFF;
   while (1)
   {
      unsigned char   c;
      int             l = uart_rx(s, &c, 1, ms);
      if (l < 1)
         return l;
      if (last == 0x00 && c == 0xFF)
         return 2;
      last = c;
   }
}

/* Low level access functions */
static int
pn532_tx(int s, unsigned char cmd, int len1, unsigned char *data1, int len2, unsigned char *data2, const char *name)
{                               /* Send data to PN532 */
   if (debug)
      fprintf(stderr, "[32m");
   unsigned char   buf[20],
                  *b = buf;
   *b++ = 0x55;
   *b++ = 0x55;
   *b++ = 0x55;
   *b++ = 0x00;                 /* Preamble */
   *b++ = 0x00;                 /* Start 1 */
   *b++ = 0xFF;                 /* Start 2 */
   int             l = len1 + len2 + 2;
   if (l >= 0x100)
   {
      *b++ = 0xFF;              /* Extended len */
      *b++ = 0xFF;
      *b++ = (l >> 8);          /* len */
      *b++ = (l & 0xFF);
      *b++ = -(l >> 8) - (l & 0xFF);    /* Checksum */
   } else
   {
      *b++ = l;                 /* Len */
      *b++ = -l;                /* Checksum */
   }
   *b++ = 0xD4;                 /* Direction (host to PN532) */
   *b++ = cmd;
   unsigned char   sum = 0xD4 + cmd;
   for (l = 0; l < len1; l++)
      sum += data1[l];
   for (l = 0; l < len2; l++)
      sum += data2[l];
   if (debug)
   {
      fprintf(stderr, "Tx[3m");
      for (int i = 0; i < b - buf - 6; i++)
         fprintf(stderr, " %02X", buf[i + 6]);
      fprintf(stderr, "[0;1;32m");
   }
   /* Send data */
   uart_tx(s, buf, b - buf);
   if (len1)
   {
      if (debug)
         for (int i = 0; i < len1; i++)
            fprintf(stderr, " %02X", data1[i]);
      uart_tx(s, data1, len1);
   }
   if (len2)
   {
      if (debug)
         for (int i = 0; i < len2; i++)
            fprintf(stderr, " %02X", data2[i]);
      uart_tx(s, data2, len2);
   }
   buf[0] = -sum;               /* Checksum */
   buf[1] = 0x00;               /* Postamble */
   if (debug)
   {
      fprintf(stderr, "[0;32;3m");
      for (int i = 0; i < 2; i++)
         fprintf(stderr, " %02X", buf[i]);
      fprintf(stderr, "[0;32m");
   }
   uart_tx(s, buf, 2);
   if (debug && name)
      fprintf(stderr, " %s", name);
   /* Get ACK and check it */
   l = uart_preamble(s, 50);
   if (l < 2)
   {
      if (debug)
         fprintf(stderr, " [31mPreamble timeout[0m\n");
      return -1;
   }
   l = uart_rx(s, buf, 3, 5);
   if (l < 3)
   {
      if (debug)
         fprintf(stderr, " [31mACK timeout[0m\n");
      return -1;
   }
   if (buf[2])
   {
      if (debug)
         fprintf(stderr, " [31mBad ACK[0m\n");
      return -1;
   }
   if (buf[0] == 0xFF && !buf[1])
   {
      if (debug)
         fprintf(stderr, " [31mNAK[0m\n");
      return -1;
   }
   if (buf[0] || buf[1] != 0xFF)
   {
      if (debug)
         fprintf(stderr, " [31mBad ACK[0m\n");
      return -1;
   }
   if (debug)
      fprintf(stderr, "[0m\n");
   return len1 + len2;
}

int
pn532_rx(int s, int max1, unsigned char *data1, int max2, unsigned char *data2, int ms)
{                               /* Recv data from PN532 */
   if (debug)
      fprintf(stderr, "[33m");
   int             l = uart_preamble(s, ms);
   if (l < 2)
   {
      if (debug)
         fprintf(stderr, "Rx [31mpremable timeout[0m\n");
      return -1;
   }
   unsigned char   buf[9];
   l = uart_rx(s, buf, 4, 20);
   if (debug)
   {
      fprintf(stderr, "Rx[3m");
      for (int i = 0; i < l; i++)
         fprintf(stderr, " %02X", buf[i]);
   }
   if (l < 4)
   {
      if (debug)
         fprintf(stderr, " [31mheader timeout[0m\n");
      return -1;
   }
   unsigned char   cmd;
   int             len = 0;
   if (buf[0] == 0xFF && buf[1] == 0xFF)
   {                            /* Extended */
      l = uart_rx(s, buf + 4, 3, 10);
      if (debug)
      {
         for (int i = 0; i < l; i++)
            fprintf(stderr, " %02X", buf[4 + i]);
      }
      if (l < 3)
      {
         if (debug)
            printf(" [31mShort header[0m\n");
         return -1;
      }
      if ((unsigned char)(buf[2] + buf[3] + buf[4]))
      {
         if (debug)
            printf(" [31mBad header[0m\n");
         return -1;
      }
      len = (buf[2] << 8) + buf[3];
      if (buf[5] != 0xD5)
      {
         if (debug)
            printf(" [31mNot expected response[0m\n");
         return -1;
      }
      cmd = buf[6];
   } else
   {                            /* Normal */
      if ((unsigned char)(buf[0] + buf[1]))
         return -1;
      len = buf[0];
      if (buf[2] != 0xD5)
      {
         if (debug)
            printf(" [31mNot expected response[0m\n");
         return -1;
      }
      cmd = buf[3];
   }
   if (debug)
      fprintf(stderr, "[0;1;33m");
   if (len < 2)
   {
      if (debug)
         fprintf(stderr, " [31mBad len %d[0m\n", len);
      return -1;
   }
   len -= 2;
   int             res = len;
   unsigned char   sum = 0xD5 + cmd;
   if (len > max1 + max2)
   {
      if (debug)
         fprintf(stderr, " [31mOver len %d>%d[0m\n", len, max1 + max2);
      return -1;
   }
   if (data1)
   {
      l = max1;
      if (l > len)
         l = len;
      if (l)
      {
         if (uart_rx(s, data1, l, 20) < l)
         {
            if (debug)
               fprintf(stderr, " [31mTimeout[0m\n");
            return -1;
         }
         if (debug)
            for (int i = 0; i < l; i++)
               fprintf(stderr, " %02X", data1[i]);
         len -= l;
         while (l)
            sum += data1[--l];
      }
   } else
      max1 = 0;
   if (data2)
   {
      l = max2;
      if (l > len)
         l = len;
      if (l)
      {
         if (uart_rx(s, data2, l, 20) < l)
         {
            if (debug)
               fprintf(stderr, " [31mTimeout[0m\n");
            return -1;
         }
         if (debug)
            for (int i = 0; i < l; i++)
               fprintf(stderr, " %02X", data2[i]);
         len -= l;
         while (l)
            sum += data2[--l];
      }
   } else
      max2 = 0;
   l = uart_rx(s, buf, 2, 10);
   if (l < 2)
   {
      if (debug)
         fprintf(stderr, " [31mTimeout[0m\n");
      return -1;
   }
   if (debug)
   {
      fprintf(stderr, "[0;33;3m");
      for (int i = 0; i < l; i++)
         fprintf(stderr, " %02X", buf[i]);
      fprintf(stderr, "[0;33m");
   }
   if ((unsigned char)(buf[0] + sum))
   {
      if (debug)
         fprintf(stderr, " [31mBad checksum[0m\n");
      return -1;
   }
   if (buf[1])
   {
      if (debug)
         fprintf(stderr, " [31mBad postamble[0m\n");
      return -1;
   }
   if (debug && cmd == 0x41 && res > 1)
   {
      if (max1 > 1)
         fprintf(stderr, " %s", df_err(data1[1]));
      else if (max1 + max2 > 1)
         fprintf(stderr, " %s", df_err(data2[1 - max1]));
   }
   if (debug)
      fprintf(stderr, "[0m\n");
   return res;
}

const char     *
pn532_init(int s, unsigned char outputs)
{
   /* init */
   unsigned char   buf[30] = {};
   buf[sizeof(buf) - 1] = 0x55;
   buf[sizeof(buf) - 2] = 0x55;
   buf[sizeof(buf) - 3] = 0x55;
   uart_tx(s, buf, sizeof(buf));
   /* Set up PN532 (SAM first as in vLowBat mode) */
   while (pn532_get(s, 10000) >= 0);    /* clear all rx buffer */
   /* SAMConfiguration */
   int             n = 0;
   buf[n++] = 0x01;             /* Normal */
   buf[n++] = 20;               /* *50ms timeout */
   buf[n++] = 0x00;             /* Not use IRQ */
   if (pn532_tx(s, 0x14, 0, NULL, n, buf, "SAMConfiguration") < 0 || pn532_rx(s, 0, NULL, sizeof(buf), buf, 50) < 0)
   {                            /* Again */
      uart_rx(s, buf, sizeof(buf), 100);        /* Wait long enough for command response timeout before we try again */
      /* SAMConfiguration */
      n = 0;
      buf[n++] = 0x01;          /* Normal */
      buf[n++] = 20;            /* *50ms timeout */
      buf[n++] = 0x00;          /* Not use IRQ */
      if (pn532_tx(s, 0x14, 0, NULL, n, buf, "SAMConfiguration") < 0 || pn532_rx(s, 0, NULL, sizeof(buf), buf, 50) < 0)
         return "SAMConfiguration fail";
   }
   /* GetFirmwareVersion */
   if (pn532_tx(s, 0x02, 0, NULL, 0, NULL, "GetFirmwareVersion") < 0 || pn532_rx(s, 0, NULL, sizeof(buf), buf, 50) < 0)
      return "GetFirmwareVersion fail";
   /* RFConfiguration (retries) */
   n = 0;
   buf[n++] = 5;                /* Config item 5 (MaxRetries) */
   buf[n++] = 0xFF;             /* MxRtyATR (default = 0xFF) */
   buf[n++] = 0x01;             /* MxRtyPSL (default = 0x01) */
   buf[n++] = 0x01;             /* MxRtyPassiveActivation */
   if (pn532_tx(s, 0x32, 0, NULL, n, buf, "RFConfiguration") < 0 || pn532_rx(s, 0, NULL, sizeof(buf), buf, 50) < 0)
      return "RFConfiguration fail";
   /* WriteRegister */
   n = 0;
   /* AB are 00=open drain, 10=quasi bidi, 01=input (high imp), 11=output (push/pull) */
   buf[n++] = 0xFF;             /* P3CFGA */
   buf[n++] = 0xFC;             /* P3CFGA */
   buf[n++] = (outputs & 0x3F); /* Define output bits */
   buf[n++] = 0xFF;             /* P3CFGB */
   buf[n++] = 0xFD;             /* P3CFGB */
   buf[n++] = 0xFF;             /* 0xFF */
   buf[n++] = 0xFF;             /* P3 */
   buf[n++] = 0xB0;             /* P3 */
   buf[n++] = 0xFF;             /* All high */
   buf[n++] = 0xFF;             /* P7CFGA */
   buf[n++] = 0xF4;             /* P7CFGA */
   buf[n++] = ((outputs >> 5) & 0x06);  /* Define output bits */
   buf[n++] = 0xFF;             /* P7CFGB */
   buf[n++] = 0xF5;             /* P7CFGB */
   buf[n++] = 0xFF;             /* 0xFF */
   buf[n++] = 0xFF;             /* P7 */
   buf[n++] = 0xF7;             /* P7 */
   buf[n++] = 0xFF;             /* All high */
   if (n && (pn532_tx(s, 0x08, 0, NULL, n, buf, "WriteRegister") < 0 || pn532_rx(s, 0, NULL, sizeof(buf), buf, 50) < 0))
      return "WriteRegister fail";
   /* RFConfiguration */
   n = 0;
   buf[n++] = 0x04;             /* MaxRtyCOM */
   buf[n++] = 1;                /* Retries (default 0) */
   if (pn532_tx(s, 0x32, 0, NULL, n, buf, "RFConfiguration") < 0 || pn532_rx(s, 0, NULL, sizeof(buf), buf, 50) < 0)
      return "RFConfiguration fail";
   /* RFConfiguration */
   n = 0;
   buf[n++] = 0x02;             /* Various timings (100*2^(n-1))us */
   buf[n++] = 0x00;             /* RFU */
   buf[n++] = 0x0B;             /* Default (102.4 ms) */
   buf[n++] = 0x0A;             /* Default is 0x0A (51.2 ms) */
   if (pn532_tx(s, 0x32, 0, NULL, n, buf, "RFConfiguration") < 0 || pn532_rx(s, 0, NULL, sizeof(buf), buf, 50) < 0)
      return "RFConfiguration fail";
   return NULL;
}

int
pn532_read_GPIO(int s)
{                               /* Read P3/P7 (P72/P71 in top bits, P35-30 in rest) */
   unsigned char   buf[3];
   int             l = pn532_tx(s, 0x0C, 0, NULL, 0, NULL, "Read GPIO");
   if (l >= 0)
      l = pn532_rx(s, 0, NULL, sizeof(buf), buf, 50);
   if (l < 0)
      return l;
   if (l < 3)
      return -1;
   return (buf[0] & 0x3F) | ((buf[1] & 0x06) << 5);
}

int
pn532_write_GPIO(int s, unsigned char value)
{                               /* Write P3/P7 (P72/P71 in top bits, P35-30 in rest) */
   unsigned char   buf[2];
   buf[0] = 0x80 | (value & 0x3F);
   buf[1] = 0x80 | ((value >> 5) & 0x06);
   int             l = pn532_tx(s, 0x0E, 2, buf, 0, NULL, "Write GPIO");
   if (l >= 0)
      l = pn532_rx(s, 0, NULL, sizeof(buf), buf, 50);
   return l;
}


/* Data exchange(for DESFire use) */
int
pn532_dx(void *pv, unsigned int len, unsigned char *data, unsigned int max, const char **strerr)
{                               /* Card access function - sends to card starting CMD byte, and receives reply in to same buffer,
                                 * starting status byte, returns len */
   if (!pv)
      return -1;
   int             s = *((int *)pv);
   unsigned char   tg = 1;
   int             l = pn532_tx(s, 0x40, 1, &tg, len, data, *strerr);
   if (l >= 0)
   {
      unsigned char   status;
      l = pn532_rx(s, 1, &status, max, data, 500);
      if (!l)
         l = -1;
      else if (l >= 1 && status)
         l = -1;
   }
   if (l < 0)
   {
      if (strerr)
         *strerr = "Failed";
   } else
      l--;                      /* Allow for status */
   return l;
}

int
pn532_Cards(int s, unsigned char nfcid[MAXNFCID], unsigned char ats[MAXATS])
{                               /* -ve for error, else number of cards */
   unsigned char   buf[100];
   /* InListPassiveTarget to get card count and baseID */
   buf[0] = 2;
   //2 tags(we only report 1)
      buf[1] = 0;
   //106 kbps type A(ISO / IEC14443 Type A)
      int             l = pn532_tx(s, 0x4A, 2, buf, 0, NULL, "InListPassiveTarget");
   if (l < 0)
      return l;
   l = pn532_rx(s, 0, NULL, sizeof(buf), buf, 110);
   if (l < 0)
      return l;
   if (!ats)
      ats = alloca(MAXATS);
   if (!nfcid)
      nfcid = alloca(MAXNFCID);
   memset(nfcid, 0, MAXNFCID);
   memset(ats, 0, MAXATS);
   /* Extract first card ID */
   unsigned char  *b = buf,
                  *e = buf + l; /* end */
   if (b >= e)
      return -1;
   unsigned char   cards = *b++;
   if (cards)
   {                            /* Get details of first card */
      if (b + 5 > e)
         return -1;
      unsigned char   tg = *b++;
      unsigned char   sens_res = (b[0] << 8) + b[1];
      b += 2;
      unsigned char   sel_res = *b++;
      if (b + *b + 1 > e)
         return -1;
      if (*b < MAXNFCID)
         memcpy(nfcid, b, *b + 1);      /* OK */
      else
         memset(nfcid, 0, MAXNFCID);    /* Too big */
      b += *b + 1;
      if (b < e)
      {                         /* ATS */
         if (!*b || b + *b > e)
            return -1;
         if (*b <= MAXATS)
         {
            memcpy(ats, b, *b); /* OK */
            (ats)--;            /* Make len of what follows for consistency */
         }
         b += *b;               /* ready for second target (which we are not looking at) */
      }
   }
   return cards;
}
