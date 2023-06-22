// Simple DES test and maybe other DF test stuff

#include <stdio.h>
#include <string.h>
#include <popt.h>
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <ctype.h>
#include <err.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <desfireaes.h>

int debug = 0;

int
main (int argc, const char *argv[])
{
   poptContext optCon;          // context for parsing command-line options
   {                            // POPT
      const struct poptOption optionsTable[] = {
//      {"string", 's', POPT_ARG_STRING, &string, 0, "String", "string"},
//      {"string-default", 'S', POPT_ARG_STRING | POPT_ARGFLAG_SHOW_DEFAULT, &string, 0, "String", "string"},
         {"debug", 'v', POPT_ARG_NONE, &debug, 0, "Debug"},
         POPT_AUTOHELP {}
      };

      optCon = poptGetContext (NULL, argc, argv, optionsTable, 0);
      //poptSetOtherOptionHelp (optCon, "");

      int c;
      if ((c = poptGetNextOpt (optCon)) < -1)
         errx (1, "%s: %s\n", poptBadOption (optCon, POPT_BADOPTION_NOALIAS), poptStrerror (c));

      if (poptPeekArg (optCon))
      {
         poptPrintUsage (optCon, stderr, 0);
         return -1;
      }
   }

   const char *fail = df_check_des ();
   if (fail)
      errx (0, "Fail: %s", fail);

   poptFreeContext (optCon);
   return 0;
}
