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
/* 

// Types

// This function is used to send and receive to card
// For send, len is size of message inc cmd byte. The data starts with cmd byte. Return value is -ve for error
// For recv, len is space available. The data is filled starting with status byte. Return value is len inc status
// recv returns len 0 for card disconnect
// recv returns message with status byte FF followed by UID for card connect
typedef int df_card_func_t (void *obj, unsigned int len, unsigned char *data);

typedef struct df_s df_t;
struct df_s
{
   void *obj;                   // Opaque, passed to df_card_func
   df_card_func_t *tx,
    *rx;                        // Card data transfer functions
   EVP_CIPHER_CTX *ctx;
   unsigned char uidlen;        // Current UID len
   unsigned char uid[10];       // Current UID
   const EVP_CIPHER *cipher;    // Current cipher
   unsigned char keylen;        // Current key length (0 if not logged in)
   unsigned char keyno;         // Current auth key no
   unsigned char sk0[16];       // Session key
   unsigned char sk1[16];       // CMAC Sub key 1
   unsigned char sk2[16];       // CMAC Sub key 2
   unsigned char cmac[16];      // Current CMAC IV
   unsigned char aid[3];        // Current selected AID
};

// Definitions
// Comms mode and flags for use in tx/rx functions
#define	DF_MODE_CMAC		0x01    // Add CMAC (checking is done if authenticated anyway and not encrypted)
#define	DF_MODE_ENC		0x02    // Encrypted tx and rx
#define DF_MODE_MASK		0x03    // File modes
#define	DF_IGNORE_STATUS	0x80    // Don't check status response
#define	DF_IGNORE_AF		0x40    // Don't concatenate AF responses
#define DF_ADD_CRC		0x20    // Add CRC on Tx (if encrypting)
#define	DF_TX_ENC		0x10    // Encrypted Tx
#define	DF_RX_ENC		0x08    // Encrypted Rx

#define DF_SET_MASTER_CHANGE	0x01    // App and master settings
#define DF_SET_LIST		0x02
#define DF_SET_CREATE		0x04
#define DF_SET_CHANGE		0x08
#define	DF_SET_DEFAULT		0x0F

// Functions
// const char * response is NULL for good, else simple error string. An empty error string means card gone.

// Low level data exchange functions

// Convert from hex
unsigned int df_hex (unsigned int max, unsigned char *dst, const char *src);

// Send data, len is *after* cmd byte from data+1
const char *df_tx (df_t *, unsigned char cmd, unsigned int len, unsigned char *data, unsigned char mode);
// Receive data, rlen is length received *after* status byte from data+1. elen is expected len (-1 for don't check)
const char *df_rx (df_t * d, unsigned int max, unsigned char *data, int elen, unsigned int *rlen, unsigned char mode);
// Send and receive message
const char *df_txrx (df_t * d, unsigned char cmd, unsigned int len, unsigned char *data, unsigned int max, int elen,
                     unsigned int *rlen, unsigned char mode);

// Main application functions

// Initialise
const char *df_init (df_t *, void *obj, df_card_func_t * tx, df_card_func_t * rx);

// Wait for connect (returns NULL on connect)
const char *df_wait (df_t *);

// Get free mem
const char *df_free_memory (df_t * d, unsigned int *mem);
// Ger version
const char *df_get_version (df_t * d, unsigned char ver[28]);
// Select an AID (NULL means AID 0)
const char *df_select_application (df_t *, unsigned char aid[3]);
// Format card, and set AES master key all zeros with key version 01, key, if set, is existing master AES key
const char *df_format (df_t *, unsigned char key[16]);
// Authenticate with a key
const char *df_authenticate (df_t *, unsigned char keyno, unsigned char key[16]);
// Get Key Version
const char *df_get_key_version (df_t * d, unsigned char keyno, unsigned char *version);
// Get Key settings
const char *df_get_key_settings (df_t * d, unsigned char keyno, unsigned char *setting, unsigned char *keynos);
// Change to new (AES) key
const char *df_change_key (df_t * d, unsigned char keyno, unsigned char version, unsigned char old[16], unsigned char key[16]);
// Change settings on current key
const char *df_change_key_settings (df_t * d, unsigned char settings);
// Change card settings config
const char *df_set_configuration (df_t * d, unsigned char settings);
// Get application IDs
const char *df_get_application_ids (df_t * d, unsigned int *num, unsigned int space, unsigned char *aids);
// Create application
const char *df_create_application (df_t * d, unsigned char aid[3], unsigned char settings, unsigned char keys);
// Delete application
const char *df_delete_application (df_t * d, unsigned char aid[3]);
// Get real UID
const char *df_get_uid (df_t * d, unsigned char uid[7]);

// Create files
const char *df_get_file_ids (df_t * d, unsigned long long *ids);        // File IDs 0-63 as bits

// File types are character D=Data, B=Backup, V=Value, C=Cyclic, L=Linear
const char * df_get_file_settings (df_t * d, unsigned char fileno,char *type, unsigned char *comms,unsigned short*access,unsigned int *size,unsigned int *min,unsigned int *max,unsigned int *limited,unsigned int *recs,unsigned char *lc);
const char * df_create_file (df_t * d, unsigned char fileno,char type, unsigned char comms,unsigned short access,unsigned int size,unsigned int min,unsigned int max,unsigned int limited,unsigned int recs,unsigned char lc);

const char *df_delete_file (df_t * d, unsigned char fileno, unsigned char comms);

// Access files
const char *df_write_data (df_t * d, unsigned char fileno, unsigned char comms, unsigned int offset, unsigned int len,
                           unsigned char *data);
const char *df_read_data(df_t *d,unsigned char fileno,unsigned int offset,unsigned int len,unsigned char *data);
const char *df_read_records(df_t *d,unsigned char fileno,unsigned int record,unsigned int recs,unsigned int rsize,unsigned char *data);
const char *df_get_value(df_t *d,unsigned char fileno,unsigned int *value);

// Commit
const char *df_commit (df_t *);
// Abort
const char *df_abort (df_t *);
