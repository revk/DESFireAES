/* PN532 tools */

const char *pn532_init(int s,unsigned char outputs);
int pn532_read_GPIO(int s);
int pn532_write_GPIO(int s, unsigned char value);
int pn532_dx(void *pv, unsigned int len, unsigned char *data, unsigned int max, const char **strerr);
#define	MAXNFCID	11
#define	MAXATS		255
int pn532_Cards(int s, unsigned char nfcid[MAXNFCID], unsigned char ats[MAXATS]);
int pn532_Present(int s);
