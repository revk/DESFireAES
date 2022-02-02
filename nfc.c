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

int             debug = 0;      /* debug */

int
main(int argc, const char *argv[])
{
   const char     *port = NULL;
   {
      poptContext     optCon;
      const struct poptOption optionsTable[] = {
         {"port", 'p', POPT_ARG_STRING, &port, 0, "Port", "/dev/cu.usbserial-..."},
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
   int s = open(port, O_RDWR);
   if (s < 0)
      err(1, "Cannot open %s", port);
   {                            /* Terminal set up */
      struct termios  t;
      if (tcgetattr(s, &t))
         err(1, "Failed to get serial settings");
      cfmakeraw(&t);
      cfsetispeed(&t, 115200);
      cfsetospeed(&t, 115200);
      if (tcsetattr(s, TCSANOW, &t))
         err(1, "Failed to set serial settings");
   }

   const char *e; /* error */

   if((e=pn532_init(s)))errx(1,"Cannot init PN532 on %s: %s",port,e);

   close(s);
   return 0;
}
