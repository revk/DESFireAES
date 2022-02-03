/* Command line tool for working with NFC cards locally */
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

#include <stdio.h>
#include <string.h>
#include <popt.h>
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <ctype.h>
#include <err.h>
#include <openssl/evp.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <termios.h>
#include "desfireaes.h"
#include "pn532.h"
#include <ajl.h>

int             debug = 0;      /* debug */
int             red = 33,
                amber = 32,
                green = 31;

unsigned char
gpio(int port)
{
   if (port < 0)
      port = 0 - port;
   if (port >= 30 || port <= 35)
      return (1 << (port - 30));
   if (port >= 71 || port <= 72)
      return (1 << (port - 71 + 6));
   return 0;
}

void
setled(int s, const char *led)
{                               /* Set LED */
   unsigned char   pattern = 0;
   if (led)
      for (const char *p = led; *p; p++)
         switch (toupper(*p))
         {
         case 'R':
            pattern |= gpio(red);
            break;
         case 'A':
            pattern |= gpio(amber);
            break;
         case 'G':
            pattern |= gpio(green);
            break;
         }
   if (red < 0)
      pattern ^= gpio(red);
   if (amber < 0)
      pattern ^= gpio(amber);
   if (green < 0)
      pattern ^= gpio(green);
   pn532_write_GPIO(s, pattern);
}

int             s = -1;
j_t             j = NULL;
const char     *ledfail = "R";
void
bye(void)
{
   if (j)
   {
      j_err(j_write_pretty(j, stdout));
      j_delete(&j);
   }
   fflush(stdout);
   if (s >= 0)
   {
      setled(s, ledfail);
      close(s);
   }
}

unsigned char  *
expecthex(const char *hex, int len, const char *name, const char *explain)
{
   if (!hex)
      return NULL;
   unsigned char  *bin = NULL;
   int             n = j_base16d(hex, &bin);
   if (n != len)
      errx(1, "--%s expects %d hexadecimal byte%s %s", name, len, (len == 1) ? "" : "s", explain ? : "");
   return bin;
}

static void
fill_random(unsigned char *buf, size_t size)
{
   //Create our random A value
   int             f = open("/dev/urandom", O_RDONLY);
   if (f < 0)
      err(1, "random");
   if (read(f, buf, size) != size)
      err(1, "random");
   close(f);
}

#define hex(name,len,explain) unsigned char *bin##name=expecthex(name,len,#name,explain)

int
main(int argc, const char *argv[])
{
   const char     *port = NULL;
   const char     *led = NULL;
   const char     *ledwait = "A";
   const char     *ledfound = "AG";
   const char     *leddone = "G";
   const char     *master = NULL;
   const char     *aid = NULL;
   const char     *aidkey[14] = {};
   int             remove = 0;
   int             format = 0;
   int             listaids = 0;
   int             listfiles = 0;
   int             createaid = 0;
   int             setmaster = 0;
   int             aidkeys = 2;
   int             aidsetting = 0xEB;
   int             mastersetting = 0x09;
   int             masterconfig = 0;
   int             waiting = 10;
   {
      poptContext     optCon;
      const struct poptOption optionsTable[] = {
         {"port", 'p', POPT_ARG_STRING, &port, 0, "Port", "/dev/cu.usbserial-..."},
         {"remove", 0, POPT_ARG_NONE, &remove, 0, "Wait for card to be removed"},
         {"master", 0, POPT_ARG_STRING, &master, 0, "Master key", "Key ver and AES"},
         {"aid", 0, POPT_ARG_STRING, &aid, 0, "AID", "Application ID"},
         {"aidkey0", 0, POPT_ARG_STRING, &aidkey[0], 0, "Application key 0 (can be set for keys 0...D)", "Key ver and AES"},
         {"aidkey1", 0, POPT_ARG_STRING | POPT_ARGFLAG_DOC_HIDDEN, &aidkey[1], 0, "Application key 1", "Key ver and AES"},
         {"aidkey2", 0, POPT_ARG_STRING | POPT_ARGFLAG_DOC_HIDDEN, &aidkey[2], 0, "Application key 2", "Key ver and AES"},
         {"aidkey3", 0, POPT_ARG_STRING | POPT_ARGFLAG_DOC_HIDDEN, &aidkey[3], 0, "Application key 3", "Key ver and AES"},
         {"aidkey4", 0, POPT_ARG_STRING | POPT_ARGFLAG_DOC_HIDDEN, &aidkey[4], 0, "Application key 4", "Key ver and AES"},
         {"aidkey5", 0, POPT_ARG_STRING | POPT_ARGFLAG_DOC_HIDDEN, &aidkey[5], 0, "Application key 5", "Key ver and AES"},
         {"aidkey6", 0, POPT_ARG_STRING | POPT_ARGFLAG_DOC_HIDDEN, &aidkey[6], 0, "Application key 6", "Key ver and AES"},
         {"aidkey7", 0, POPT_ARG_STRING | POPT_ARGFLAG_DOC_HIDDEN, &aidkey[7], 0, "Application key 7", "Key ver and AES"},
         {"aidkey8", 0, POPT_ARG_STRING | POPT_ARGFLAG_DOC_HIDDEN, &aidkey[8], 0, "Application key 8", "Key ver and AES"},
         {"aidkey9", 0, POPT_ARG_STRING | POPT_ARGFLAG_DOC_HIDDEN, &aidkey[9], 0, "Application key 9", "Key ver and AES"},
         {"aidkeyA", 0, POPT_ARG_STRING | POPT_ARGFLAG_DOC_HIDDEN, &aidkey[10], 0, "Application key A", "Key ver and AES"},
         {"aidkeyB", 0, POPT_ARG_STRING | POPT_ARGFLAG_DOC_HIDDEN, &aidkey[11], 0, "Application key B", "Key ver and AES"},
         {"aidkeyC", 0, POPT_ARG_STRING | POPT_ARGFLAG_DOC_HIDDEN, &aidkey[12], 0, "Application key C", "Key ver and AES"},
         {"aidkeyD", 0, POPT_ARG_STRING | POPT_ARGFLAG_DOC_HIDDEN, &aidkey[13], 0, "Application key D", "Key ver and AES"},
         {"list-files", 0, POPT_ARG_NONE, &listfiles, 0, "List files"},
         {"format", 0, POPT_ARG_NONE, &format, 0, "Format card"},
         {"list-aids", 0, POPT_ARG_NONE, &listaids, 0, "List AIDs"},
         {"create-aid", 0, POPT_ARG_NONE, &createaid, 0, "Create AID"},
         {"set-master", 0, POPT_ARG_NONE, &setmaster, 0, "Set a master key"},
         {"master-setting", 0, POPT_ARG_INT | POPT_ARGFLAG_SHOW_DEFAULT, &mastersetting, 0, "Master key setting", "N"},
         {"master-config", 0, POPT_ARG_INT | POPT_ARGFLAG_SHOW_DEFAULT, &masterconfig, 0, "Master key config", "N"},
         {"aid-keys", 0, POPT_ARG_INT | POPT_ARGFLAG_SHOW_DEFAULT, &aidkeys, 0, "AID keys", "N"},
         {"aid-setting", 0, POPT_ARG_INT | POPT_ARGFLAG_SHOW_DEFAULT, &aidsetting, 0, "AID setting", "N"},
         {"red", 0, POPT_ARG_INT | POPT_ARGFLAG_SHOW_DEFAULT, &red, 0, "Red port", "30/31/32/33/34/5/71/72"},
         {"amber", 0, POPT_ARG_INT | POPT_ARGFLAG_SHOW_DEFAULT, &amber, 0, "Amber port", "30/31/32/33/34/5/71/72"},
         {"green", 0, POPT_ARG_INT | POPT_ARGFLAG_SHOW_DEFAULT, &green, 0, "Green port", "30/31/32/33/34/5/71/72"},
         {"waiting", 0, POPT_ARG_INT | POPT_ARGFLAG_SHOW_DEFAULT, &waiting, 0, "How long to wait", "seconds"},
         {"led", 0, POPT_ARG_STRING, &led, 0, "LED", "R/A/G"},
         {"led-wait", 0, POPT_ARG_STRING | POPT_ARGFLAG_SHOW_DEFAULT, &ledwait, 0, "LED waiting for card", "R/A/G"},
         {"led-found", 0, POPT_ARG_STRING | POPT_ARGFLAG_SHOW_DEFAULT, &ledfound, 0, "LED when card found and working", "R/A/G"},
         {"led-done", 0, POPT_ARG_STRING | POPT_ARGFLAG_SHOW_DEFAULT, &leddone, 0, "LED for done OK", "R/A/G"},
         {"led-fail", 0, POPT_ARG_STRING | POPT_ARGFLAG_SHOW_DEFAULT, &ledwait, 0, "LED for failed", "R/A/G"},
         {"debug", 'v', POPT_ARG_NONE, &debug, 0, "Debug"},
         POPT_AUTOHELP {}
      };

      optCon = poptGetContext(NULL, argc, argv, optionsTable, 0);
      //poptSetOtherOptionHelp(optCon, "");

      int             c;
      if ((c = poptGetNextOpt(optCon)) < -1)
         errx(1, "%s: %s\n", poptBadOption(optCon, POPT_BADOPTION_NOALIAS), poptStrerror(c));

      if (!port && poptPeekArg(optCon))
         port = poptGetArg(optCon);

      if (poptPeekArg(optCon) || !port)
      {
         poptPrintUsage(optCon, stderr, 0);
         return -1;
      }
      poptFreeContext(optCon);
   }
   hex(master, 17, "Key version and 16 byte AES key data");
   hex(aid, 3, "Application ID");
   unsigned char  *binaidkey[14];
   for (int i = 0; i < 14; i++)
      binaidkey[i] = expecthex(aidkey[i], 17, "aidkeyN", "Key version and 16 byte AES key data");
   s = open(port, O_RDWR);
   if (s < 0)
      err(1, "Cannot open %s", port);
   {                            /* Terminal set up */
      struct termios  t;
      if (tcgetattr(s, &t))
         err(1, "Failed to get serial setting");
      cfmakeraw(&t);
      cfsetispeed(&t, 115200);
      cfsetospeed(&t, 115200);
      if (tcsetattr(s, TCSANOW, &t))
         err(1, "Failed to set serial");
   }

   const char     *e;           /* error */

   unsigned char   outputs = (gpio(red) | gpio(amber) | gpio(green));
   if ((e = pn532_init(s, outputs)))
      errx(1, "Cannot init PN532 on %s: %s", port, e);

   setled(s, led);

   /* Wait for card */
   unsigned char   nfcid[MAXNFCID] = {};
   unsigned char   ats[MAXATS] = {};
   int             cards = 0;
   setled(s, ledwait);
   time_t          giveup = time(0) + waiting;
   while (!cards && time(0) < giveup)
   {
      cards = pn532_Cards(s, nfcid, ats);
      if (cards < 0)
         errx(1, "Failed to get cards");
   }
   if (!cards)
      errx(1, "Given up");
   setled(s, ledfound);

   j = j_create();
   atexit(&bye);
   if (*nfcid)
      j_store_string(j, "id", j_base16a(*nfcid, nfcid + 1));
   if (*ats)
      j_store_string(j, "ats", j_base16a(*ats, ats + 1));

   df_t            d;
   if ((e = df_init(&d, &s, &pn532_dx)))
      errx(1, "Failed DF init: %s", e);
#define df(x,...) do{if((e=df_##x(&d,__VA_ARGS__)))errx(1,"Failed "#x": %s",e);}while(0)

   unsigned char   binzero[17] = {};
   unsigned char  *currentkey = binmaster ? : binzero;

   unsigned char   ver[28];
   if (!(e = df_get_version(&d, ver)))
      j_store_string(j, "ver", j_base16a(sizeof(ver), ver));

   df(select_application, NULL);
   unsigned char   v;
   df(get_key_version, 0, &v);
   if (aid)
      j_store_string(j, "aid", j_base16a(3, binaid));

   if (!binmaster || *binmaster != v || df_authenticate(&d, 0, binmaster + 1))
   {
      currentkey = binzero;
      df_authenticate(&d, 0, NULL);     /* try default */
   }
   if (!df_isauth(&d))
      errx(1, "Authentication failed, no further actions can be performed");

   {                            /* Get UID */
      unsigned char   uid[7];
      df(get_uid, uid);
      j_store_string(j, "uid", j_base16a(sizeof(uid), uid));
   }
   if (format)
   {
      df(format, *currentkey, currentkey + 1);
      if (binmaster && !setmaster)
      {
         df(change_key, 0x80, 0, currentkey + 1, NULL); /* clear master key */
         currentkey = binzero;
         df(authenticate, 0, NULL);     /* re-authenticate */
      }
      j_store_boolean(j, "formatted", 1);
   }
   if (setmaster && currentkey == binzero)
   {
      if (!binmaster)
         fill_random(binmaster = malloc(17), 17);       /* new master */
      df(change_key, 0x80, *binmaster, currentkey + 1, binmaster + 1);
      currentkey = binmaster;
      df(authenticate, 0, binmaster + 1);
      df(change_key_settings, mastersetting);
      df(set_configuration, masterconfig);
      j_store_string(j, "master", j_base16a(17, binmaster));

   }
   if (createaid)
   {
      if (!binaid)
         errx(1, "Set --aid");
      df(create_application, binaid, aidsetting, aidkeys);
      j_t             k = j_store_array(j, "aid-keys");
      for (int i = 0; i < aidkeys; i++)
      {
         if (!binaidkey[i])
            fill_random(binaidkey[i] = malloc(17), 17); /* new key */
         j_append_string(k, j_base16a(17, binaidkey[i]));
      }
      df(change_key, 0, *binaidkey[0], NULL, binaidkey[0] + 1);
      for (int i = 1; 1 < aidkeys; i++)
      {
         df(authenticate, i, NULL);     /* own key to change it */
         df(change_key, i, *binaidkey[i], NULL, binaidkey[i] + 1);
      }
      df(authenticate, 0, binaidkey[0] + 1);
   }
   if (listaids)
   {
      unsigned char   aids[50 * 3];
      int             num = 0;
      df(get_application_ids, &num, sizeof(aids), aids);
      j_t             a = j_store_array(j, "aids");
      for (int i = 0; i < num; i++)
         j_append_string(a, j_base16a(3, aids + 3 * i));
   }
   if (listfiles)
   {
      if (!binaid)
         errx(1, "Set --aid");
      df(select_application, binaid);
      for (int i = 0; i < 13; i++)
         if (binaidkey[i] && !df_authenticate(&d, i, binaidkey[i] + 1))
            break;
      unsigned long long ids;
      df(get_file_ids, &ids);
      j_t             a = j_store_array(j, "files");
      for (int i = 0; i < 64; i++)
         if (ids & (1ULL << i))
         {
            j_t             f = j_append_object(a);
            j_store_int(f, "id", i);
            char            type;
            unsigned char   comms;
            unsigned short  access;
            unsigned int    size;
            unsigned int    min;
            unsigned int    max;
            unsigned int    recs;
            unsigned int    limited;
            unsigned char   lc;
            df(get_file_settings, i, &type, &comms, &access, &size, &min, &max, &recs, &limited, &lc);
            j_store_stringf(f, "type", "%c", type);
            j_store_int(f, "comms", comms);
            j_store_stringf(f, "access", "%04X", access);
            if (size)
               j_store_int(f, "size", size);
            if (type == 'V')
            {
               if (min)
                  j_store_int(f, "min", min);
               if (max < 0x7FFFFFFF)
                  j_store_int(f, "max", max);
               if (limited)
                  j_store_int(f, "limited", limited);
               if (lc)
                  j_store_int(f, "lc", lc);
               unsigned int    value;
               if (!df_get_value(&d, i, comms, &value))
                  j_store_int(f, "value", value);
            }
            if (type == 'C')
            {
               if (max)
                  j_store_int(f, "max-records", max);
               j_store_int(f, "records", recs);
            }
         }
   }
   /* TODO creating file */
   /* TODO write file */
   /* TODO delete file */
   {                            /* free mem */
      unsigned int    mem;
      df(free_memory, &mem);
      j_store_int(j, "free-mem", mem);
   }
   setled(s, leddone);
   if (remove)
      while (pn532_Present(s) > 0);
   close(s);
   s = -1;
   return 0;
}
