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

#ifndef	DESFIREAES_H
#define DESFIREAES_H

// Types

// The data exchange function talks to the card
// Sends data, len bytes, starting from cmd byte.
// Receives in to data, max bytes, from status byte.
// Does not do any special handling of AF, etc.
// Returns length received
// Returns 0 for card gone
// Returns -ve for any other error (should store error in errstr)
// Note errstr will be pre-set on calling to a constant string that is the command being execute, for debug
typedef int df_dx_func_t(void *obj, unsigned int len, unsigned char *data, unsigned int max, const char **errstr);

typedef struct df_s df_t;
struct df_s {
   void *obj;                   // Opaque, passed to df_card_func
   df_dx_func_t *dx;            // Card data exchange function
#ifndef	ESP_PLATFORM
   EVP_CIPHER_CTX *ctx;
   const EVP_CIPHER *cipher;    // Current cipher DES or AES (DES used for formatting to AES)
#endif
   unsigned char blocklen;      // Current block length (0 if not logged in), 8 means DES, 16 means AES
   unsigned char keyno;         // Current auth key no
   unsigned char sk0[16];       // Session key
   unsigned char sk1[16];       // CMAC Sub key 1
   unsigned char sk2[16];       // CMAC Sub key 2
   unsigned char cmac[16];      // Current CMAC IV
   unsigned char aid[3];        // Current selected AID
};

// Some useful definitions
#define	DF_MODE_CMAC		0x01    // Check CMAC, not used as checked if authenticated but allows <<2 on comms mode
#define	DF_MODE_ENC		0x02    // Encrypted Rx, and check CRC if expected len set

#define DF_SET_MASTER_CHANGE	0x01    // App and master settings
#define DF_SET_LIST		0x02
#define DF_SET_CREATE		0x04
#define DF_SET_CHANGE		0x08
#define	DF_SET_DEFAULT		0x0F	// Default key settings for application

// Functions
// All of these functions that return a const char * return NULL for "OK" or an error message
// An empty string error message is returned for "card gone"

// Low level data exchange functions

// Convert from hex
unsigned int df_hex(unsigned int max, unsigned char *dst, const char *src);

// Initialise
const char *df_init(df_t *, void *obj, df_dx_func_t * dx);

// Low level data exchange
// Data exchange, sends a command and receives a response
// Note that data[] is used for command and response, and is max bytes long - allow at least 19 spare bytes at end for CRC and padding
// Command:
//  The command is in data, starting with command byte in data[0], and is txlen bytes long
//  Note that cmd arg is for convenience and if non 0 is simply stored in data[0]
//  If the command is long, it is split and sent using AF process
//  If not authenticated the command is sent, plain
//  If authenticated and txenc set to 0xFF, then append CMAC to command
//  If authenticated and txenc set, then it is sent encrypted
//   - A CRC is added to the end (at txlen), adding 4 bytes
//   - The command is padded as needed (up to 16 byte blocks)
//   - The command is encrypted from byte txenc (i.e. txenc bytes at the start, including the cmd byte, are not encrypted)
//   - The encryption updates the AES A IV used for CMAC checking
//  If authenticated, and txenc is 0, then the command is sent plain
//   - The command is CMAC processed to update the AES A IV for checking
// Response:
//  If response has AF status, multiple response payloads are concatenated with final status at start.
//  If not authenticated and rxenc is set, this is the number of bytes expected, else error
//   - The return value is the length of response including status byte at data[0]
//  If authenticated, and rxenc is non zero, then this is expected to be an encrypted message
//   - The length has to be a multiple of 16 bytes (after status byte)
//   - The payload is decrypted (i.e. all data after status byte)
//   - A CRC is expected at byte rxenc, this is checked as well and length checked
//   - The AES A IV is updated for CMAC checking as part of decrypting
//   - The return value is rxenc, i.e. rxenc includes status byte in count
//  If authenticated and rxenc is 0 then an 8 byte CMAC is expected
//   - The 8 bytes are removed, after checking there are 8 bytes
//   - The CMAC process is done on response (payload+status) and checked
//   - The return value is the length without the 8 byte CMAC
//  If case of any error the return value is -ve
//  If rlen is NULL, the response is expected to just be a status byte, and error if not
// Special cases
//  Receive concatenation is not done for cmd AA, 1A or 0A. The AF response is treated as good.
//  Send with txenc and cmd C4 does not add the CRC. ChangeKey has an extra CRC and padding you need to do first.
//  If we receive a clean message, checked for CRC or CMAC, etc, but with bad status then rlen is set, otherwise 0
//  - I.e. this allows you to decide if you want to ignore an error. Note an error makes us unauthenticated
// Examples
//  Cmd 54 with txenc 1, rxenc 0, and len 2, adds CRC and encrypts from byte 1, returns rlen 1 (status byte)
//  Cmd 51 with txenc 0, rxenc 8, and len 1, sends 51, receives 17 bytes, decrypts and checks CRC at byte 8, returns rlen 8 (status + 7 byte UID)
const char *df_dx(df_t * d, unsigned char cmd, unsigned int max, unsigned char *data, unsigned int txlen, unsigned char txenc, unsigned char rxenc, unsigned int *rlen, const char *name);
const char *df_err(unsigned char c);	// Error code name

// Main application functions

// Get free mem
const char *df_free_memory(df_t * d, unsigned int *mem);
// Ger version
const char *df_get_version(df_t * d, unsigned char ver[28]);
// Select an AID (NULL means AID 0)
const char *df_select_application(df_t *, const unsigned char aid[3]);
// Format card, and set var/key specified
const char *df_format(df_t *, unsigned char keyver, const unsigned char key[16]);
// Authenticate with a key
const char *df_authenticate(df_t *, unsigned char keyno, const unsigned char key[16]);
#ifndef ESP_PLATFORM
const char * df_des_authenticate (df_t * d, unsigned char keyno, const unsigned char key[16]);
const char * df_check_des (void);
#endif
// Confirm if authenticated
#define	df_isauth(d)	((d)->blocklen)
// Mark not auth
#define	df_deauth(d)	do{(d)->blocklen=0;}while(0)
// Get Key Version
const char *df_get_key_version(df_t * d, unsigned char keyno, unsigned char *version);
// Get Key settings
const char *df_get_key_settings(df_t * d, unsigned char *setting, unsigned char *keynos);
// Change to new (AES) key
const char *df_change_key(df_t * d, unsigned char keyno, unsigned char version, const unsigned char old[16], const unsigned char key[16]);
// Change settings on current key
const char *df_change_key_settings(df_t * d, unsigned char settings);
// Change card settings config
const char *df_set_configuration(df_t * d, unsigned char settings);
// Get application IDs
const char *df_get_application_ids(df_t * d, unsigned int *num, unsigned int space, unsigned char *aids);
// Create application
const char *df_create_application(df_t * d, const unsigned char aid[3], unsigned char settings, unsigned char keys);
// Delete application
const char *df_delete_application(df_t * d, const unsigned char aid[3]);
// Get real UID
const char *df_get_uid(df_t * d, unsigned char uid[7]);

// Create files
const char *df_get_file_ids(df_t * d, unsigned long long *ids); // File IDs 0-63 as bits

// Change existing file settings
const char *df_change_file_settings(df_t * d, unsigned char fileno, unsigned char comms, unsigned short oldaccess, unsigned short access);

// File types are character D=Data, B=Backup, V=Value, C=Cyclic, L=Linear
const char *df_get_file_settings(df_t * d, unsigned char fileno, char *type, unsigned char *comms, unsigned short *access, unsigned int *size, unsigned int *min, unsigned int *max, unsigned int *recs, unsigned int *limited, unsigned char *lc);
const char *df_create_file(df_t * d, unsigned char fileno, char type, unsigned char comms, unsigned short access, unsigned int size, unsigned int min, unsigned int max, unsigned int recs, unsigned int value, unsigned char lc);

// Delete a file
const char *df_delete_file(df_t * d, unsigned char fileno);

// Access files
const char *df_write_data(df_t * d, unsigned char fileno, char type, unsigned char comms, unsigned int offset, unsigned int len, const void *data);
const char *df_read_data(df_t * d, unsigned char fileno, unsigned char comms, unsigned int offset, unsigned int len, unsigned char *data);
const char *df_read_records(df_t * d, unsigned char fileno, unsigned char comms, unsigned int record, unsigned int recs, unsigned int rsize, unsigned char *data);
const char *df_get_value(df_t * d, unsigned char fileno, unsigned char comms, unsigned int *value);

// Commit
const char *df_commit(df_t *);
// Abort
const char *df_abort(df_t *);

// Credit/Debit
const char *df_credit(df_t * d, unsigned char fileno, unsigned char comms, unsigned int delta);
const char *df_limited_credit(df_t * d, unsigned char fileno, unsigned char comms, unsigned int delta);
const char *df_debit(df_t * d, unsigned char fileno, unsigned char comms, unsigned int delta);

unsigned int df_crc(unsigned int len, const unsigned char *data);

#endif
