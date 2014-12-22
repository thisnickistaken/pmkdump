#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "includes/bitfield.c"
#include "includes/parse.c"
#include "includes/dump.c"
#include "includes/debug.c"
#include <pcap.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/time.h>
#include <signal.h>
#include <poll.h>

#define WPA_AUTH_MAGIC		0x8e88

#define ePACKET			0
#define eSTART			1
#define eLOGOFF			2
#define eKEY			3
#define eASF			4

#define EAPOL_RC4_KEY		1
#define EAPOL_AES_KEY		2
#define EAPOL_WPA_KEY		254

#define EAPOL_VERSION_MASK	0x0003
#define EAPOL_DESC_V1		0x01
#define EAPOL_DESC_V2		0x02
#define EAPOL_PAIRWISE		0x08
#define EAPOL_INSTALL		0x40
#define EAPOL_ACK		0x80
#define EAPOL_MIC		0x100
#define EAPOL_SECURE		0x200
#define EAPOL_ERROR		0x400
#define EAPOL_REQ		0x800

#define EAPOL_INDEX_0		0x00           
#define EAPOL_INDEX_1		0x10
#define EAPOL_INDEX_2		0x20
#define EAPOL_INDEX_3		0x30
#define EAPOL_INDEX_MASK	0x30
#define EAPOL_INDEX_SHIFT	0x04

#define PMKDB_MAGIC		0x13370420

#define PMK_LOCKED		0x80000000

#define PMK_CLEAR_AND_READY	0x00000000

#define PTK_AA			0x00000001
#define PTK_SA			0x00000002
#define PTK_ANONCE		0x00000004
#define PTK_SNONCE		0x00000008
#define PTK_MIC			0x00000010
#define PTK_EAPOL		0x00000020

#define PD_LIST_SSID		0x00000001
#define PD_LIST_PASS		0x00000002
#define PD_UNLOCK		0x00000010
#define PD_SERVE		0x00000020
#define PD_CRACK		0x00000040
#define PD_TAKE_INPUT		0x10000000

#define PD_CON_SSID_LOCKED	0x00000001

#define PDC_GET_NEXT		0x0001
#define PDC_PMK_LIST		0x0002
#define PDC_SPEED		0x0003
#define PDC_CHANGE_SSID		0x0010
#define PDC_PASS_LIST		0x0020

#define PDCF_ACK		0x0001
#define PDCF_ERR		0x8000

#define rol(bits,word) (((word) << (bits)) | ((word) >> (32-(bits))))
#define ror(bits,word) (((word) >> (bits)) | ((word) << (32-(bits))))
#define rol16(bits,word) (((word) << (bits)) | ((word) >> (16-(bits))))
#define ror16(bits,word) (((word) >> (bits)) | ((word) << (16-(bits))))

typedef struct _WLAN_HEAD
{
	unsigned short frame_ctl;
	unsigned short duration;
	unsigned char src[6];
	unsigned char dst[6];
	unsigned char bssid[6];
	unsigned short seq;
	unsigned char data[];
} WLAN_HEAD;

typedef struct _LLC_HEAD
{
	unsigned char dsap;
	unsigned char ssap;
	unsigned char len;
	unsigned char data[];
} LLC_HEAD;
typedef struct _EAPOL_HEAD
{
	unsigned short pae_type;
	unsigned char ver;
	unsigned char type;
	unsigned short len;
	unsigned char d_type;
	unsigned char data[];	
} EAPOL_HEAD;
typedef struct _EAPOL_KEY
{
	unsigned short info;
	unsigned short key_len;
	unsigned char replay[8];
	unsigned char nonce[32];
	unsigned char iv[16];
	unsigned char rsc[8];
	unsigned char id[8];
	unsigned char mic[16];
	unsigned short dlen;
	unsigned char data[];
} EAPOL_KEY;

typedef struct _PMK_PASS
{
	unsigned char pass[64];
	off_t next;
} PMK_PASS;

typedef struct _PMK_ENTRY
{
	unsigned char pass[64];
	unsigned char pmk[32];
	off_t next;
} PMK_ENTRY;

typedef struct _PMK_TABLE
{
	unsigned char ssid[32];
	unsigned long cal_pass;
	off_t rows;
	off_t last;
	off_t next;
} PMK_TABLE;

typedef struct _PMK_DB
{
	unsigned long ssid_num;
	unsigned long pass_num;
	unsigned long status;
	unsigned long magic;
	off_t tables;
	off_t last_tbl;
	off_t pass_lst;
	off_t last_pass;
} PMK_DB;

typedef struct _MEM_PMK_DB
{
	PMK_DB db;
	int fd;
	off_t size;
} MEM_PMK_DB;

typedef struct _MEM_PMK_TABLE
{
	PMK_TABLE tbl;
	off_t loc;
} MEM_PMK_TABLE;

typedef struct _PMK_PASS_NODE
{
	unsigned char pass[64];
	struct _PMK_PASS_NODE *next;
} PMK_PASS_NODE;

typedef struct _PMK_SSID_NODE
{
	unsigned char ssid[33];
	struct _PMK_SSID_NODE *next;
} PMK_SSID_NODE;

typedef struct _PMK_ENTRY_NODE
{
	unsigned char pass[64];
	unsigned char pmk[32];
	struct _PMK_ENTRY_NODE *next;
} PMK_ENTRY_NODE;

typedef struct _PTK_DATA
{
	unsigned long status;
	unsigned long ver;
	unsigned char aa[6];
	unsigned char sa[6];
	unsigned char anonce[32];
	unsigned char snonce[32];
	unsigned char mic[16];
	unsigned char eapol[99];
} PTK_DATA;

typedef struct _CONNECTION_NODE
{
	int s;
	MEM_PMK_DB *mdb;
	unsigned long flags;
	struct sockaddr_in r,l;
	float speed;
	pthread_t pth;
	unsigned long dnum;
	PMK_ENTRY_NODE *dist;
	struct _CONNECTION_NODE *next;
} CONNECTION_NODE;
/*
typedef struct _DISTRO_NODE
{
	unsigned long num;
	PMK_ENTRY_NODE *dist;
	struct _CONNECTION_NODE *c;
	struct _DISTRO_NODE *next;
} DISTRO_NODE;
*/
typedef struct _PD_CHATTER
{
	unsigned short flags;
	unsigned short op;
	unsigned long count;
	char data[];
} PD_CHATTER;

typedef struct _PD_WORK
{
	PMK_SSID_NODE *slist;
	PMK_SSID_NODE *spos;
	MEM_PMK_TABLE *mtbl;
	PMK_PASS_NODE *rem;
} PD_WORK;

MEM_PMK_DB *CreatePMKDB(char *path);
MEM_PMK_DB *OpenPMKDB(char *path);
int UnlockPMKDB(char *path);
int ClosePMKDB(MEM_PMK_DB *mdb);
int AddSSID(MEM_PMK_DB *mdb, char *ssid);
unsigned long AddSSIDBlock(MEM_PMK_DB *mdb, char **ssid, unsigned long num);
int AddPASS(MEM_PMK_DB *mdb, char *pass);
unsigned long AddPASSBlock(MEM_PMK_DB *mdb, char **pass, unsigned long num);
int AddPMK(MEM_PMK_DB *mdb, MEM_PMK_TABLE *mtbl, char *pmk, char *pass);
MEM_PMK_TABLE *GetPMKTable(MEM_PMK_DB *mdb, char *ssid);
PMK_PASS_NODE *GetPMKPassList(MEM_PMK_DB *mdb);
PMK_SSID_NODE *GetPMKSSIDList(MEM_PMK_DB *mdb);
PMK_ENTRY_NODE *GetPMKEntries(MEM_PMK_DB *mdb, char *ssid);
int FreePMKPassList(PMK_PASS_NODE *lst);
int FreePMKSSIDList(PMK_SSID_NODE *lst);
int FreePMKEntries(PMK_ENTRY_NODE *lst);
int AddPMKPassNode(PMK_PASS_NODE **list, unsigned char *pass);
int RemovePMKPassNode(PMK_PASS_NODE **list, unsigned char *pass);
PD_WORK *InitWork(MEM_PMK_DB *mdb);
int NextWork(MEM_PMK_DB *mdb, PD_WORK *w);
PMK_ENTRY_NODE *GetWork(PD_WORK *w, unsigned long num);
int ReplaceWork(PD_WORK *w, PMK_ENTRY_NODE *ent);

int readAt(int fd, off_t offset, void *buf, unsigned long len);
int writeAt(int fd, off_t offset, void *buf, unsigned long len);

PTK_DATA *ReadPCAP(char *path);

int pbkdf2_wpa(unsigned char *pass, unsigned char *ssid, unsigned char *pmk);
int pmk_to_ptk(unsigned char *pmk, unsigned char *aa, unsigned char *sa, unsigned char *anonce, unsigned char *snonce, unsigned char *ptk);
int get_mic(unsigned long ver, unsigned char *key_mic, unsigned char *eapol, unsigned char *mic);

void *ServerInput(void *unused);
void *InitConnection(CONNECTION_NODE *c);
void *InitRemote(CONNECTION_NODE *c);
int RemoveConnection(CONNECTION_NODE **list, CONNECTION_NODE *c, pthread_mutex_t *cmtx);
int AddConnection(CONNECTION_NODE **list, CONNECTION_NODE *c, pthread_mutex_t *mtx);
int FreeConnectionList(CONNECTION_NODE **list, CONNECTION_NODE *c, pthread_mutex_t *cmtx);
/*
int RemoveDistro(DISTRO_NODE **list, DISTRO_NODE *d, pthread_mutex_t *mtx);
int AddDistro(DISTRO_NODE **list, DISTRO_NODE *d, pthread_mutex_t *mtx);
int FreeDistroList(DISTRO_NODE **list, pthread_mutex_t *mtx);
*/
PD_CHATTER *GetChatter(int s);
int SendChatter(int s, PD_CHATTER *ch);

void usage(char *name);
void crash(int signal);

unsigned long STATUS = 0x00000000;
CONNECTION_NODE *con = NULL;
PD_WORK *work = NULL;
pthread_mutex_t m_con, m_work, m_db;
pthread_t pth_input;

unsigned long work_load = 30;

#ifdef _SC_NPROCESSORS_ONLN
	unsigned long threads = sysconf(_SC_NPROCESSORS_ONLN);
#else
	unsigned long threads = 1;
#endif

int main(unsigned long argc, unsigned char **argv)
{
	int fd, s, slen = sizeof(struct sockaddr_in), keepalive = 1;
	struct sockaddr_in l,r;
	struct hostent *h = NULL;
	unsigned long port = 1337;
	struct stat st;
	char *buf = NULL, **lst = NULL;
	unsigned long x, y, z, failed;
	MEM_PMK_DB *mdb = NULL;
	MEM_PMK_TABLE *mtbl = NULL;
	PMK_PASS_NODE *plst = NULL;
	PMK_PASS_NODE *ptmp = NULL;
	PMK_SSID_NODE *slst = NULL;
	PMK_SSID_NODE *stmp = NULL;
	PMK_ENTRY_NODE *elst = NULL;
	PMK_ENTRY_NODE *etmp = NULL;
	PTK_DATA *pdat = NULL;
	char *cap = NULL, *ssid = NULL, *pass = NULL, *db = NULL, *table = NULL, *remote = NULL;
	unsigned char ptk[64], pmk[32], mic[16];
	CONNECTION_NODE *tmp_con = NULL;
	
	for(x = 1; x < 31; x++)
		signal(x, crash);
	
	if(argc == 1)
	{
		usage(argv[0]);
		exit(0);
	}
	
	for(x = 1; x < argc; x++)
	{
		switch(*argv[x])
		{
			case '-':
				switch(*(argv[x] + 1))
				{
					case 'A':
					case 'a':
						if(argc == ++x)
						{
							printf("No type specified (-a).\n");
							break;
						}
						if(aEQ(argv[x], "ssid") == 0)
						{
							if(argc == ++x)
							{
								printf("No path from which to retrieve SSID list.\n");
								break;
							}
							ssid = strdup(argv[x]);
						}
						else
						{
							if(aEQ(argv[x], "pass") == 0)
							{
								if(argc == ++x)
								{
									printf("No path from which to retrieve password list.\n");
									break;
								}
								pass = strdup(argv[x]);
							}
							else
							{
								printf("Type '%s' not understood.\n", argv[x]);
								break;
							}
						}
						break;
					case 'C':
					case 'c':
						if(argc == ++x)
						{
							printf("No path supplied for capture file (-c).\n");
							break;
						}
						cap = strdup(argv[x]);
						break;
					case 'D':
					case 'd':
						if(argc == ++x)
						{
							printf("No path supplied for PMK database.\n");
							break;
						}
						db = strdup(argv[x]);
						break;
					case 'H':
					case 'h':
						usage(argv[0]);
						exit(0);
					case 'L':
					case 'l':
						if(argc == ++x)
						{
							printf("No type specified (-l).\n");
							break;
						}
						if(aEQ(argv[x], "ssid") == 0)
						{
							set(&STATUS, PD_LIST_SSID);
						}
						else
						{
							if(aEQ(argv[x], "pass") == 0)
							{
								set(&STATUS, PD_LIST_PASS);
							}
							else
							{
								if(aEQ(argv[x], "calc") == 0)
								{
									if(argc == ++x)
									{
										printf("No table name given.\n");
										break;
									}
									table = strdup(argv[x]);
								}
								else
								{
									printf("Type '%s' not understood.\n", argv[x]);
									break;
								}
							}
						}
						break;
					case 'P':
					case 'p':
						if(argc == ++x)
						{
							printf("No port number provided (-p).\n");
							break;
						}
						if(!isNum(argv[x]))
						{
							printf("\"%s\" is not a valid port number.\n", argv[x]);
							break;
						}
						if((port = ReadNum(argv[x])) > 65535)
						{
							printf("Valid port numbers are in the range 0-65535.\n");
							break;
						}
						break;
					case 'R':
					case 'r':
						if(argc == ++x)
						{
							printf("No remote host specified (-r).\n");
							break;
						}
						remote = strdup(argv[x]);
						break;
					case 'S':
					case 's':
						set(&STATUS, PD_SERVE);
						break;
					case 'T':
					case 't':
						if(argc == ++x)
						{
							printf("Number of threads not provided (-t).\n");
							break;
						}
						if(!isNum(argv[x]))
						{
							printf("\"%s\" is not a valid number of threads.\n", argv[x]);
							break;
						}
						if((threads = ReadNum(argv[x])) == 0)
						{
							printf("So you want me to calculate using no threads?\nNot only does this sound stupid but I'll bet you it doesn't work.\n");
						}
						break;
					case 'U':
					case 'u':
						set(&STATUS, PD_UNLOCK);
						break;
					case 'V':
					case 'v':
						if(argc == ++x)
						{
							printf("Debug level not provided. Assuming level \"1\".\n");
							bdbgl(1);
						}
						else
						{
							if(!isNum(argv[x]))
							{
								printf("\"%s\" is not a valid debug level.\n", argv[x]);
								break;
							}
							bdbgl(ReadNum(argv[x]));
						}
						break;
					case 'W':
					case 'w':
						if(argc == ++x)
						{
							printf("Number of seconds for work load not specified (-w).\n");
							break;
						}
						if(!isNum(argv[x]))
						{
							printf("\"%s\" is not a valid number of secconds.\n", argv[x]);
							break;
						}
						if((work_load = ReadNum(argv[x])) == 0)
						{
							printf("So you want each connection to do 0 seconds of work?\nSome how i think you might not like these results.\n");
						}
						break;
					default:
						printf("Invalid switch in '%s'.\n", argv[x]);
						break;
				}
				break;
			default:
				printf("Unknown argument '%s'.\n", argv[x]);
				break;
		}
	}
	
	if(isset(STATUS, PD_UNLOCK))
	{
		if(!db)
		{
			printf("No PMK database specified.\n");
		}
		else
		{
			if(UnlockPMKDB(db) == -1)
				printf("Failed to unlock '%s'.\n", db);
			else
				printf("Unlocked '%s'.\n", db);
		}
	}
	
	if(db)
	{
		if(!(mdb = OpenPMKDB(db)))
		{
			printf("Failed to open PMK database, creating...\n");
			if(!(mdb = CreatePMKDB(db)))
			{
				printf("Failed to create PMK database...\n");
			}
		}
	}
		
	if(ssid)
	{
		if(!mdb)
		{
			printf("No PMK database open to add SSID's to.\n");
		}
		else
		{
			if((fd = open(ssid, O_RDONLY, 0)) == -1)
			{
				printf("Failed to open SSID list for reading.\n");
			}
			else
			{
				if(fstat(fd, &st) == -1)
				{
					printf("Failed to stat SSID list.\n");
					close(fd);
				}
				else
				{
					bdbg(2) printf("Adding SSID list...\n");
					buf = (char*)malloc(67108865);
					z ^= z;
					failed ^= failed;
					x = 67108864;
					while(st.st_size / 67108864)
					{
						bdbg(2) printf("Adding block: st.st_size = %08x%08x\n", *(unsigned long*)(&st.st_size + 4), *(unsigned long*)&st.st_size);
						if(lseek(fd, -1 * (67108864 - x), SEEK_CUR) == -1)
						{
							bdbg(1) printf("Failed seeking...\n");
							return -1;
						}
						x = 67108864;
						read(fd, buf, x);
						while(buf[--x] != '\n');
						buf[++x] = 0;
						st.st_size -= x;
						y = SplitByLine(buf, &lst);
						z += AddSSIDBlock(mdb, lst, y);
						/*z ^= z;
						for(x ^= x; x < y; x++)
						{
							if(AddSSID(mdb, lst[x]) == -1)
							{
								bdbg(2) printf("Failed adding SSID %u.\n", x);
								z++;
							}
						}*/
						failed += y - z;
						freeList(&lst, y);
					}
					x = st.st_size;
					bdbg(2) printf("Adding final block: st.st_size = 00000000%08x\n", x);
					if(lseek(fd, -1 * (67108864 - x), SEEK_CUR) == -1)
					{
						bdbg(1) printf("Failed seeking...\n");
						return -1;
					}
					read(fd, buf, x);
					buf[x] = 0;
					y = SplitByLine(buf, &lst);
					z += AddSSIDBlock(mdb, lst, y);
					failed += y - z;
					freeList(&lst, y);
					close(fd);
					free(buf);
					buf = NULL;
					printf("%u SSID's added to PMK database.\n%u SSID's failed to add.\n", z, failed);
				}
			}
		}
	}
	
	if(pass)
	{
		if(!mdb)
		{
			printf("No PMK database open to add passwords's to.\n");
		}
		else
		{
			if((fd = open(pass, O_RDONLY, 0)) == -1)
			{
				printf("Failed to open password list for reading.\n");
			}
			else
			{
				if(fstat(fd, &st) == -1)
				{
					printf("Failed to stat password list.\n");
					close(fd);
				}
				else
				{
					bdbg(2) printf("Adding PASS list...\n");
					buf = (char*)malloc(67108865);
					z ^= z;
					failed ^= failed;
					x = 67108864;
					while(st.st_size / 67108864)
					{
						bdbg(2) printf("Adding block: st.st_size = %08x%08x\n", *(unsigned long*)(&st.st_size + 4), *(unsigned long*)&st.st_size);
						if(lseek(fd, -1 * (67108864 - x), SEEK_CUR) == -1)
						{
							bdbg(1) printf("Failed seeking...\n");
							return -1;
						}
						x = 67108864;
						read(fd, buf, x);
						while(buf[--x] != '\n');
						buf[++x] = 0;
						st.st_size -= x;
						y = SplitByLine(buf, &lst);
						z += AddPASSBlock(mdb, lst, y);
						/*z ^= z;
						for(x ^= x; x < y; x++)
						{
							if(AddPASS(mdb, lst[x]) == -1)
							{
								bdbg(2) printf("Failed adding password %u.\n", x);
								z++;
							}
						}*/
						failed += y - z;
						freeList(&lst, y);
					}
					x = st.st_size;
					bdbg(2) printf("Adding final block: st.st_size = 00000000%08x\n", x);
					if(lseek(fd, -1 * (67108864 - x), SEEK_CUR) == -1)
					{
						bdbg(1) printf("Failed seeking...\n");
						return -1;
					}
					read(fd, buf, x);
					buf[x] = 0;
					y = SplitByLine(buf, &lst);
					z += AddPASSBlock(mdb, lst, y);
					failed += y - z;
					freeList(&lst, y);
					close(fd);
					free(buf);
					buf = NULL;
					printf("%u passwords added to PMK database.\n%u passwords failed to add.\n", z, failed);
				}
			}
		}
	}
	
	if(isset(STATUS, PD_LIST_SSID))
	{
		if(!mdb)
		{
			printf("No PMK database is open.\n");
		}
		else
		{
			if(!(slst = GetPMKSSIDList(mdb)))
			{
				printf("Failed to retrieve SSID list.\n");
			}
			else
			{
				printf("SSID's in PMK database:\n");
				
				for(stmp = slst; stmp != NULL; stmp= stmp->next)
					puts(stmp->ssid);
				
				printf("\nEnd of SSID list.\n\n");
				FreePMKSSIDList(slst);
				slst = NULL;
			}
		}
	}
	
	if(isset(STATUS, PD_LIST_PASS))
	{
		if(!mdb)
		{
			printf("No PMK database is open.\n");
		}
		else
		{
			if(!(plst = GetPMKPassList(mdb)))
			{
				printf("Failed to retrieve password list.\n");
			}
			else
			{
				printf("Passwords in PMK database:\n");
				
				for(ptmp = plst; ptmp != NULL; ptmp = ptmp->next)
					puts(ptmp->pass);
				
				printf("\nEnd of password list.\n\n");
				FreePMKPassList(plst);
				plst = NULL;
			}
		}
	}
	
	if(table)
	{
		if(!mdb)
		{
			printf("No open PMK database to get table from.\n");
		}
		else
		{
			if(!(elst = GetPMKEntries(mdb, table)))
			{
				printf("Failed to retrieve table entries from PMK database.\n");
			}
			else
			{
				printf("Calculated passwords in '%s':\n", table);
				
				for(etmp = elst; etmp != NULL; etmp = etmp->next)
				{
					printf("pmk:[");
					b_dump(etmp->pmk, 'x', 32, 32);
					printf("]\tpass: \"%s\"\n", etmp->pass);
				}
				
				printf("\nEnd of table.\n\n");
				FreePMKEntries(elst);
				elst = NULL;
			}
		}
	}
	
	if(cap)
	{
		if(!(pdat = ReadPCAP(cap)))
		{
			printf("Failed to read '%s'.\n", cap);
		}
		else
		{
			printf("PTK Data:\nAA: ");
			b_dump(pdat->aa, 'X', 6, 6);
			printf("\nSA: ");
			b_dump(pdat->sa, 'X', 6, 6);
			printf("\nANONCE: ");
			b_dump(pdat->anonce, 'X', 32, 32);
			printf("\nSNONCE: ");
			b_dump(pdat->snonce, 'X', 32, 32);
			printf("\nMIC: ");
			b_dump(pdat->mic, 'X', 16, 16);
			printf("\nEAPOL:\n");
			b_dump(pdat->eapol, 'X', 2, 99);
			printf("\n");
			if(isset(pdat->status, PTK_AA | PTK_SA | PTK_ANONCE | PTK_SNONCE | PTK_MIC | PTK_EAPOL))
			{
				printf("Seems like we have what we need.\n");
			}
			else
			{
				printf("Not enough data gathered.\nIncomplete handshake capture?\n");
				free(pdat);
				pdat = NULL;
			}
		}
	}
	
	if(pdat)
	{
		int pmk_to_ptk(unsigned char *pmk, unsigned char *aa, unsigned char *sa, unsigned char *anonce, unsigned char *snonce, unsigned char *ptk);

		pbkdf2_wpa("test", "test", pmk);
		pmk_to_ptk(pmk, pdat->aa, pdat->sa, pdat->anonce, pdat->snonce, ptk);
		get_mic(pdat->ver, ptk, pdat->eapol, mic);
		printf("PMK:\n");
		b_dump(pmk, 'X', 32, 32);
		printf("\nPTK:\n");
		b_dump(ptk, 'X', 64, 64);
		printf("\nMIC:\n");
		b_dump(mic, 'X', 16, 16);
		printf("\nYay!\n");
	}
	
	if(remote)
	{
		printf("Entering remote mode.\n");
		pthread_mutex_init(&m_con, NULL);
		
		set(&STATUS, PD_CRACK);
		
		for(x ^= x; x < threads; x++)
		{
			tmp_con = (CONNECTION_NODE*)malloc(sizeof(CONNECTION_NODE));
			tmp_con->mdb = NULL;
			tmp_con->flags = 0;
			tmp_con->dnum = 0;
			tmp_con->dist = NULL;
			tmp_con->next = NULL;
			tmp_con->speed = 0.0f;
			tmp_con->l.sin_family = AF_INET;
			tmp_con->l.sin_port = 0;
			tmp_con->l.sin_addr.s_addr = INADDR_ANY;
			r.sin_family = AF_INET;
			r.sin_port = htons(port);
			if(!(h = gethostbyname(remote)))
			{
				printf("Failed to resolve \"%s\".\n", remote);
				return 1;
			}
			r.sin_addr.s_addr = *(unsigned long*)h->h_addr_list[0];
			if((tmp_con->s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
			{
				printf("Failed to create socket for thread %u.\n", x);
				free(tmp_con);
			}
			else
			{
				if(bind(tmp_con->s, (struct sockaddr*)&tmp_con->l, sizeof(struct sockaddr_in)) == -1)
				{
					printf("Failed to bind to socket for thread %u.\n", x);
					close(tmp_con->s);
					free(tmp_con);
				}
				else
				{
					if(connect(tmp_con->s, (struct sockaddr*)&r, sizeof(struct sockaddr_in)) == -1)
					{
						printf("Failed to connect socket intended for thread %u.\n", x);
						close(tmp_con->s);
						free(tmp_con);
					}
					else
					{
						if(AddConnection(&con, tmp_con, &m_con) == -1)
						{
							printf("Failed to add connection to list.\n");
							close(tmp_con->s);
							free(tmp_con);
						}
						else
						{
							if(pthread_create(&tmp_con->pth, NULL, InitRemote, tmp_con))
							{
								printf("Failed to create thread %u.\n", x);
								if(RemoveConnection(&con, tmp_con, &m_con) == -1)
									printf("Failed to remove connection from list.\n");
							}
						}
					}
				}
			}
			tmp_con = NULL;
		}
	}
	
	while(isset(STATUS, PD_CRACK))
		sleep(1000);
	
	if(isset(STATUS, PD_SERVE))
	{
		bdbg(1) printf("Entering server mode.\n");
		pthread_mutex_init(&m_con, NULL);
		pthread_mutex_init(&m_work, NULL);
		pthread_mutex_init(&m_db, NULL);
		bdbg(1) printf("Initializing work distribution structures...\n");
		if(!(work = InitWork(mdb)))
		{
			printf("No work in PMK database or InitWork() failed.\n");
			return -1;
		}
		bdbg(1) printf("Complete.\n");
		l.sin_family = AF_INET;
		l.sin_port = htons(port);
		l.sin_addr.s_addr = INADDR_ANY;
		
		if(!mdb)
		{
			printf("No open PMK database to serve.\n");
		}
		else
		{
			if((s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
			{
				printf("Failed to create socket.\n");
			}
			else
			{
				if(bind(s, (struct sockaddr*)&l, sizeof(struct sockaddr_in)) == -1)
				{
					printf("Failed to bind socket to port %u.\n", port);
				}
				else
				{
					if(listen(s, 5) == -1)
					{
						printf("Failed to listen on port %u.\n", port);
					}
					else
					{
						set(&STATUS, PD_TAKE_INPUT);
						if(pthread_create(&pth_input, NULL, ServerInput, NULL))
						{
							printf("Error creating input thread.\n");
						}
						else
						{
							bdbg(1) printf("Entered server mode.\n");
							while(isset(STATUS, PD_SERVE))
							{
								tmp_con = (CONNECTION_NODE*)malloc(sizeof(CONNECTION_NODE));
								tmp_con->mdb = mdb;
								tmp_con->flags = 0;
								tmp_con->dist = NULL;
								tmp_con->next = NULL;
								tmp_con->speed = 0.0f;
								if((tmp_con->s = accept(s, &tmp_con->r, &slen)) == -1)
								{
									printf("Error accepting connection.\n");
									break;
								}
								if(AddConnection(&con, tmp_con, &m_con) == -1)
								{
									printf("Failed to add connection to list.\n");
									break;
								}
								if(pthread_create(&tmp_con->pth, NULL, InitConnection, tmp_con))
								{
									printf("Error creating thread.\n");
									break;
								}
							}
							clear(&STATUS, PD_TAKE_INPUT);
							while(con)
							{
								printf("!!!!!\nWaiting on connections to terminate\nSleeping %d secconds...\n!!!!!\n", work_load);
								sleep(work_load);
							}
						}
					}
				}
				printf("Closing socket.\n");
				close(s);
			}
		}
	}
	
	if(mdb)
	{
		if(ClosePMKDB(mdb) == -1)
			printf("Failed to close PMK database.\n");
	}
	
	return 0;
}

MEM_PMK_DB *CreatePMKDB(char *path)
{
	MEM_PMK_DB *mdb;
	
	if(!path)
		return NULL;
	
	if(!(mdb = (MEM_PMK_DB*)malloc(sizeof(MEM_PMK_DB))))
		return NULL;
	
	if((mdb->fd = open(path, O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IWUSR )) == -1)
	{
		free(mdb);
		return NULL;
	}
	
	mdb->db.ssid_num = 0;
	mdb->db.pass_num = 0;
	mdb->db.status = PMK_LOCKED;
	mdb->db.magic = PMKDB_MAGIC;
	mdb->db.tables = 0;
	mdb->db.last_tbl = 0;
	mdb->db.pass_lst = 0;
	mdb->db.last_pass = 0;
	mdb->size = sizeof(PMK_DB);
	
	if(write(mdb->fd, &mdb->db, sizeof(PMK_DB)) == -1)
	{
		close(mdb->fd);
		free(mdb);
		return NULL;
	}
	
	return mdb;
}

MEM_PMK_DB *OpenPMKDB(char *path)
{
	MEM_PMK_DB *mdb;
	struct stat st;
	
	if(!path)
		return NULL;
	
	if(!(mdb = (MEM_PMK_DB*)malloc(sizeof(MEM_PMK_DB))))
		return NULL;
	
	if((mdb->fd = open(path, O_RDWR, S_IRUSR | S_IWUSR)) == -1)
	{
		free(mdb);
		return NULL;
	}
	
	if(read(mdb->fd, &mdb->db, sizeof(PMK_DB)) == -1)
	{
		close(mdb->fd);
		free(mdb);
		return NULL;
	}
	
	if(fstat(mdb->fd, &st) == -1)
	{
		close(mdb->fd);
		free(mdb);
		return NULL;
	}
	mdb->size = st.st_size;
	
	if(mdb->db.magic != PMKDB_MAGIC || isset(mdb->db.status, PMK_LOCKED))
	{
		close(mdb->fd);
		free(mdb);
		return NULL;
	}
	
	set(&mdb->db.status, PMK_LOCKED);
	if(writeAt(mdb->fd, 0, &mdb->db, sizeof(PMK_DB)) == -1)
	{
		close(mdb->fd);
		free(mdb);
		return NULL;
	}
	
	return mdb;
}

int UnlockPMKDB(char *path)
{
	struct stat st;
	MEM_PMK_DB mdb;
	
	if(!path)
		return -1;
	
	if((mdb.fd = open(path, O_RDWR, 0)) == -1)
		return -1;
	
	if(read(mdb.fd, &mdb.db, sizeof(PMK_DB)) == -1)
	{
		close(mdb.fd);
		return -1;
	}
	
	if(mdb.db.magic == PMKDB_MAGIC && isset(mdb.db.status, PMK_LOCKED))
	{
		clear(&mdb.db.status, PMK_LOCKED);
		if(writeAt(mdb.fd, 0, &mdb.db, sizeof(PMK_DB)) == -1)
		{
			close(mdb.fd);
			return -1;
		}
	}
	else
	{
		close(mdb.fd);
		return -1;
	}
	
	close(mdb.fd);
	
	return 0;
}

int AddSSID(MEM_PMK_DB *mdb, char *ssid)
{
	PMK_TABLE tbl;
	off_t next;
	unsigned long ssid_len;
	unsigned long x;
	int err;
	
	if(!ssid || !mdb)
		return -1;
	ssid_len = strlen(ssid);
	if(ssid_len > 32 || ssid_len == 0)
		return -1;
	
	memset(&tbl, 0, sizeof(PMK_TABLE));
	
	memcpy(&tbl.ssid, ssid, ssid_len);
	
	if(writeAt(mdb->fd, mdb->size, &tbl, sizeof(PMK_TABLE)) == -1)
		return -1;
	
	mdb->db.ssid_num++;
	if(!mdb->db.tables)
		mdb->db.tables = mdb->size;
	else
	{
		next = mdb->db.tables;
		while((err = readAt(mdb->fd, next, &tbl, sizeof(PMK_TABLE))) != -1)
		{
			for(x ^= x; x < ssid_len && ssid[x] == tbl.ssid[x]; x++);
			if(x == ssid_len)
				return -1;
			
			if(!tbl.next)
			{
				tbl.next = mdb->size;
				if(writeAt(mdb->fd, next, &tbl, sizeof(PMK_TABLE)) == -1)
					return -1;
				break;
			}
			next = tbl.next;
		}
		if(err == -1)
			return -1;
	}
	mdb->size += sizeof(PMK_TABLE);
	if(writeAt(mdb->fd, 0, &mdb->db, sizeof(PMK_DB)) == -1)
		return -1;
	
	return 0;
}

unsigned long AddSSIDBlock(MEM_PMK_DB *mdb, char **ssid, unsigned long num)
{
	PMK_TABLE *tbl = NULL, tbl2;
	unsigned char *buf = NULL;
	unsigned long x, len, good = 0;
	off_t next;
	int err;

	if(!mdb || !ssid || !num)
		return 0;
	
	for(x ^= x; x < num; x++)
		if(strlen(ssid[x]) > 32)
			*ssid[x] = 0;
	if(!mdb->db.tables)
	{
		mdb->db.tables = mdb->size;
	}
	else
	{
		next = mdb->db.last_tbl;
		while((err = readAt(mdb->fd, next, &tbl2, sizeof(PMK_TABLE))) != - 1)
		{
			/*for(x ^= x; x < num; x++)
				if(memcmp(ssid[x], tbl2.ssid, strlen(ssid[x])) == 0)
					*ssid[x] = 0;*/
			if(!tbl2.next)
			{
				tbl2.next = mdb->size;
				if(writeAt(mdb->fd, next, &tbl2, sizeof(PMK_TABLE)) == -1)
					return 0;
				break;
			}
			next = tbl2.next;
		}
		if(err == -1)
			return 0;
	}
	for(x ^= x; x < num; x++)
		if(*ssid[x])
			good++;
	buf = (unsigned char *)malloc(sizeof(PMK_TABLE) * good);
	memset(buf, 0, sizeof(PMK_TABLE) * good);
	tbl = buf;
	next = mdb->size + sizeof(PMK_TABLE);
	for(x ^= x; x < num; x++)
		if(*ssid[x])
		{
			memcpy(tbl->ssid, ssid[x], strlen(ssid[x]));
			tbl->next = next;
			next += sizeof(PMK_TABLE);
			tbl++;
		}
	tbl--;
	tbl->next ^= tbl->next;
	if(writeAt(mdb->fd, mdb->size, buf, good * sizeof(PMK_TABLE)) == -1)
		return 0;
	mdb->size += good * sizeof(PMK_TABLE);
	tbl--;
	mdb->db.last_tbl = tbl->next;
	mdb->db.ssid_num += good;
	free(buf);
	if(writeAt(mdb->fd, 0, &mdb->db, sizeof(PMK_DB)) == -1)
		return 0;
	return good;
}

int AddPASS(MEM_PMK_DB *mdb, char *pass)
{
	PMK_PASS p;
	off_t next;
	unsigned long pass_len;
	unsigned long x;
	int err;
	
	if(!pass || !mdb)
		return -1;
	pass_len = strlen(pass);
	if(pass_len > 63 || pass_len < 8)
		return -1;
	
	memset(&p, 0, sizeof(PMK_PASS));
	memcpy(&p.pass, pass, pass_len);
	if(writeAt(mdb->fd, mdb->size, &p, sizeof(PMK_PASS)) == -1)
		return -1;
	
	mdb->db.pass_num++;
	if(!mdb->db.pass_lst)
		mdb->db.pass_lst = mdb->size;
	else
	{
		next = mdb->db.pass_lst;
		while((err = readAt(mdb->fd, next, &p, sizeof(PMK_PASS))) != -1)
		{
			for(x ^= x; x < pass_len && pass[x] == p.pass[x]; x++);
			if(x == pass_len)
				return -1;
			
			if(!p.next)
			{
				p.next = mdb->size;
				if(writeAt(mdb->fd, next, &p, sizeof(PMK_PASS)) == -1)
					return -1;
				break;
			}
			next = p.next;
		}
		if(err == -1)
			return -1;
	}
	mdb->size += sizeof(PMK_PASS);
	if(writeAt(mdb->fd, 0, &mdb->db, sizeof(PMK_DB)) == -1)
		return -1;
	
	return 0;
}

unsigned long AddPASSBlock(MEM_PMK_DB *mdb, char **pass, unsigned long num)
{
	PMK_PASS *p = NULL, p2;
	off_t next;
	unsigned long x, len, good = 0;
	unsigned char *buf = NULL;
	int err;
	
	if(!mdb || !pass || !num)
		return 0;
	
	for(x ^= x; x < num; x++)
	{
		len = strlen(pass[x]);
		if(len < 8 || len > 63)
			*pass[x] = 0;
	}
	
	if(!mdb->db.pass_lst)
		mdb->db.pass_lst = mdb->size;
	else
	{
		next = mdb->db.last_pass;
		while((err = readAt(mdb->fd, next, &p2, sizeof(PMK_PASS))) != -1)
		{
			/*for(x ^= x; x < num; x++)
				if(memcmp(pass[x], p2.pass, strlen(pass[x])) == 0)
					*pass[x] = 0;*/
			if(!p2.next)
			{
				p2.next = mdb->size;
				if(writeAt(mdb->fd, next, &p2, sizeof(PMK_PASS)) == -1)
					return 0;
				break;
			}
			next = p2.next;
		}
		if(err == -1)
			return 0;
	}
	for(x ^= x; x < num; x++)
		if(*pass[x])
			good++;
	buf = (unsigned char *)malloc(sizeof(PMK_PASS) * good);
	memset(buf, 0, sizeof(PMK_PASS) * good);
	p = buf;
	next = mdb->size + sizeof(PMK_PASS);
	for(x ^= x; x < num; x++)
		if(*pass[x])
		{
			memcpy(p->pass, pass[x], strlen(pass[x]));
			p->next = next;
			next += sizeof(PMK_PASS);
			p++;
		}
	p--;
	p->next ^= p->next;
	if(writeAt(mdb->fd, mdb->size, buf, good * sizeof(PMK_PASS)) == -1)
		return 0;
	mdb->size += good * sizeof(PMK_PASS);
	p--;
	mdb->db.last_pass = p->next;
	mdb->db.pass_num += good;
	free(buf);
	if(writeAt(mdb->fd, 0, &mdb->db, sizeof(PMK_DB)) == -1)
		return 0;
	return good;
}

int AddPMK(MEM_PMK_DB *mdb, MEM_PMK_TABLE *mtbl, char *pmk, char *pass)
{
	PMK_ENTRY ent;
	unsigned long pass_len;
	off_t next;
	int err;
	
	if(!mdb || !mtbl || !pmk || !pass)
		return -1;
	
	pass_len = strlen(pass);
	if(pass_len > 63 || pass_len < 8)
		return -1;
	
	memset(&ent, 0, sizeof(PMK_ENTRY));
	memcpy(&ent.pmk, pmk, 32);
	memcpy(&ent.pass, pass, pass_len);
	
	if(writeAt(mdb->fd, mdb->size, &ent, sizeof(PMK_ENTRY)) == -1)
		return -1;
	
	mtbl->tbl.cal_pass++;
	
	if(!mtbl->tbl.rows)
		mtbl->tbl.rows = mdb->size;
	else
	{
		next = mtbl->tbl.rows;
		while((err = readAt(mdb->fd, next, &ent, sizeof(PMK_ENTRY))) != -1)
		{
			if(strcmp(ent.pass, pass) == 0)
				return -1;
			if(!ent.next)
			{
				ent.next = mdb->size;
				if(writeAt(mdb->fd, next, &ent, sizeof(PMK_ENTRY)) == -1)
					return -1;
				break;
			}
			next = ent.next;
		}
		if(err == -1)
			return -1;
	}
		
	mdb->size += sizeof(PMK_ENTRY);
	if(writeAt(mdb->fd, 0, &mdb->db, sizeof(PMK_DB)) == -1)
		return -1;
	if(writeAt(mdb->fd, mtbl->loc, &mtbl->tbl, sizeof(PMK_TABLE)) == -1)
		return -1;
	
	return 0;
}

unsigned long AddPMKBlock(MEM_PMK_DB *mdb, MEM_PMK_TABLE *mtbl, char *pmk, char *pass, unsigned long num)
{
	PMK_ENTRY *e = NULL, e2;
	unsigned char *buf = NULL;
	unsigned long x, len, good = 0;
	int err;
	off_t next;
	
	if(!mdb || !mtbl || !pmk || !pass || !num)
		return 0;
	
	for(x ^= x; x < num; x++)
	{
		len = strlen(pass + 64 * x);
		if(len > 63 || len < 8)
			*(pass + 64 * x) = 0;
	}
	
	if(!mtbl->tbl.rows)
	{
		mtbl->tbl.rows = mdb->size;
	}
	else
	{
		next = mtbl->tbl.last;
		while((err = readAt(mdb->fd, next, &e2, sizeof(PMK_ENTRY))) != -1)
		{
			/*for(x ^= x; x < num; x++)
				if(memcmp(pass + 64 * x, e2.pass, strlen(pass + 64 * x)) == 0)
					*(pass + 64 * x) = 0;*/
			if(!e2.next)
			{
				e2.next = mdb->size;
				if(writeAt(mdb->fd, next, &e2, sizeof(PMK_ENTRY)) == -1)
					return 0;
				break;
			}
			next = e2.next;
		}
		if(err == -1)
			return 0;
	}
	for(x ^= x; x < num; x ++)
		if(*(pass + 64 * x))
			good++;
	buf = (unsigned char*)malloc(sizeof(PMK_ENTRY) * good);
	memset(buf, 0, sizeof(PMK_ENTRY) * good);
	e = buf;
	next = mdb->size + sizeof(PMK_ENTRY);
	for(x ^= x; x < num; x++)
	{
		if(*(pass + 64 * x))
		{
			memcpy(e->pass, pass + 64 * x, strlen(pass + 64 * x));
			memcpy(e->pmk, pmk + 32 * x, 32);
			e->next = next;
			next += sizeof(PMK_ENTRY);
			e++;
		}
	}
	e--;
	e->next ^= e->next;
	if(writeAt(mdb->fd, mdb->size, buf, good * sizeof(PMK_ENTRY)) == -1)
		return 0;
	mdb->size += good * sizeof(PMK_ENTRY);
	e--;
	mtbl->tbl.last = e->next;
	mtbl->tbl.cal_pass += good;
	free(buf);
	if(writeAt(mdb->fd, mtbl->loc, &mtbl->tbl, sizeof(PMK_TABLE)) == -1)
		return 0;
	return good;
}

MEM_PMK_TABLE *GetPMKTable(MEM_PMK_DB *mdb, char *ssid)
{
	MEM_PMK_TABLE *mtbl;
	unsigned long ssid_len;
	unsigned long x;
	off_t next;
	int err;
	
	if(!mdb || !ssid)
		return NULL;
	
	if(!mdb->db.tables)
		return NULL;
	
	ssid_len = strlen(ssid);
	if(ssid_len > 32 || ssid_len == 0)
		return NULL;
	
	mtbl = (MEM_PMK_TABLE*)malloc(sizeof(MEM_PMK_TABLE));
	
	next = mdb->db.tables;
	while((err = readAt(mdb->fd, next, &mtbl->tbl, sizeof(PMK_TABLE))) != -1)
	{
		bdbg(3)
		{
			printf("GetPMKTable() got table at offset 0x%08X%08X\n\tSSID:\t\t\t\"%s\"\n\tCalculated Passphrases:\t%d\n\tRow List Offset:\t0x%08X%08X\n\tNext Table Offset:\t0x%08X%08x\n", *(unsigned long*)(&mtbl->loc + 4), *(unsigned long*)&mtbl->loc, mtbl->tbl.ssid, mtbl->tbl.cal_pass, *(unsigned long*)(&mtbl->tbl.rows + 4), *(unsigned long*)&mtbl->tbl.rows, *(unsigned long*)(&mtbl->tbl.next + 4), *(unsigned long*)&mtbl->tbl.next);
		}
		bdbg(4)
		{
			b_dump(mtbl, 'X', 2, sizeof(MEM_PMK_TABLE));
			printf("\n");
		}
		for(x ^= x; x < ssid_len && ssid[x] == mtbl->tbl.ssid[x]; x++)
		{
			bdbg(3) printf("'%c'='%c'\n", ssid[x], mtbl->tbl.ssid[x]);
		}
		if(x == ssid_len && ssid[x] == mtbl->tbl.ssid[x])
		{
			bdbg(3) printf("%d = %d\t'%c'='%c'\n", x, ssid_len, ssid[x], mtbl->tbl.ssid[x]);
			mtbl->loc = next;
			return mtbl;
		}
		if((next = mtbl->tbl.next) == NULL)
			break;
	}
	if(err == -1)
	{
		free(mtbl);
		return NULL;
	}
	
	free(mtbl);
	
	return NULL;
}		

PMK_PASS_NODE *GetPMKPassList(MEM_PMK_DB *mdb)
{
	PMK_PASS_NODE *lst, *n;
	PMK_PASS p;
	int err;
	
	if(!mdb)
		return NULL;
		
	if(!mdb->db.pass_lst)
		return NULL;
	
	lst = (PMK_PASS_NODE*)malloc(sizeof(PMK_PASS_NODE));
	n = lst;
	p.next = mdb->db.pass_lst;
	
	while((err = readAt(mdb->fd, p.next, &p, sizeof(PMK_PASS))) != -1)
	{
		memcpy(n->pass, p.pass, 64);
		if(!p.next)
		{
			n->next = NULL;
			break;
		}
		else
		{
			n->next = (PMK_PASS_NODE*)malloc(sizeof(PMK_PASS_NODE));
			n = n->next;
		}
	}
	if(err == -1)
	{
		free(lst);
		return NULL;
	}
	
	return lst;
}

PMK_SSID_NODE *GetPMKSSIDList(MEM_PMK_DB *mdb)
{
	PMK_SSID_NODE *lst, *n;
	PMK_TABLE tbl;
	int err;
	
	if(!mdb)
		return NULL;
	
	if(!mdb->db.tables)
		return NULL;
	
	lst = (PMK_SSID_NODE*)malloc(sizeof(PMK_SSID_NODE));
	n = lst;
	tbl.next = mdb->db.tables;
	while((err = readAt(mdb->fd, tbl.next, &tbl, sizeof(PMK_TABLE))) != -1)
	{
		memcpy(n->ssid, tbl.ssid, 32);
		n->ssid[32] = 0;
		if(!tbl.next)
		{
			n->next = NULL;
			break;
		}
		else
		{
			n->next = (PMK_SSID_NODE*)malloc(sizeof(PMK_SSID_NODE));
			n = n->next;
		}
	}
	if(err == -1)
	{
		free(lst);
		return NULL;
	}
	
	return lst;
}

PMK_ENTRY_NODE *GetPMKEntries(MEM_PMK_DB *mdb, char *ssid)
{
	PMK_ENTRY_NODE *lst, *n;
	MEM_PMK_TABLE *mtbl;
	PMK_ENTRY ent;
	int err;
	unsigned long ssid_len;
	
	if(!mdb || !ssid)
		return NULL;
	
	if(!(mtbl = GetPMKTable(mdb, ssid)))
		return NULL;
	
	bdbg(3)
	{
		printf("GetPMKEntries() got table \"%s\" at offset 0x%08X%08X\n\tSSID:\t\t\t\"%s\"\n\tCalculated Passphrases:\t%d\n\tRow List Offset:\t0x%08X%08X\n\tNext Table Offset:\t0x%08X%08x\n", ssid, *(unsigned long*)(&mtbl->loc + 4), *(unsigned long*)&mtbl->loc, mtbl->tbl.ssid, mtbl->tbl.cal_pass, *(unsigned long*)(&mtbl->tbl.rows + 4), *(unsigned long*)&mtbl->tbl.rows, *(unsigned long*)(&mtbl->tbl.next + 4), *(unsigned long*)&mtbl->tbl.next);
	}
	bdbg(4)
	{
		b_dump(mtbl, 'X', 2, sizeof(MEM_PMK_TABLE));
		printf("\n");
	}
	
	if(!mtbl->tbl.rows)
	{
		memset(mtbl, 0, sizeof(MEM_PMK_TABLE));
		return mtbl;
	}
	
	lst = (PMK_ENTRY_NODE*)malloc(sizeof(PMK_ENTRY_NODE));
	n = lst;
	ent.next = mtbl->tbl.rows;
	
	while((err = readAt(mdb->fd, ent.next, &ent, sizeof(PMK_ENTRY))) != -1)
	{
		memcpy(n->pass, ent.pass, 64);
		memcpy(n->pmk, ent.pmk, 32);
		if(!ent.next)
		{
			n->next = NULL;
			break;
		}
		else
		{
			n->next = (PMK_ENTRY_NODE*)malloc(sizeof(PMK_ENTRY_NODE));
			n = n->next;
		}
	}
	if(err == -1)
	{
		free(lst);
		return NULL;
	}
	
	return lst;
}

int FreePMKPassList(PMK_PASS_NODE *lst)
{
	PMK_PASS_NODE *x;
	
	if(!lst)
		return -1;
	
	for(x = lst; lst != NULL; x = lst)
	{
		lst = lst->next;
		free(x);
	}
	
	return 0;
}

int FreePMKSSIDList(PMK_SSID_NODE *lst)
{
	PMK_SSID_NODE *x;
	
	if(!lst)
		return -1;
	
	for(x = lst; lst != NULL; x = lst)
	{
		lst = lst->next;
		free(x);
	}
	
	return 0;
}

int FreePMKEntries(PMK_ENTRY_NODE *lst)
{
	PMK_ENTRY_NODE *x;
	
	if(!lst)
		return -1;
	
	for(x = lst; lst != NULL; x = lst)
	{
		lst = lst->next;
		free(x);
	}
	
	return 0;
}

int ClosePMKDB(MEM_PMK_DB *mdb)
{
	if(!mdb)
		return -1;
	
	clear(&mdb->db.status, PMK_LOCKED);
	if(writeAt(mdb->fd, 0, &mdb->db, sizeof(PMK_DB)) == -1)
		return -1;
	 
	close(mdb->fd);
	free(mdb);
	
	return 0;
}

int AddPMKPassNode(PMK_PASS_NODE **list, unsigned char *pass)
{
	PMK_PASS_NODE *n, *next;
	
	if(!list || !pass)
		return -1;
	
	if(!(*list))
	{
		*list = (PMK_PASS_NODE*)malloc(sizeof(PMK_PASS_NODE));
		(*list)->next = NULL;
		memcpy((*list)->pass, pass, 64);
	}
	else
	{
		for(n = *list; n->next; n = n->next);
		
		n->next = (PMK_PASS_NODE*)malloc(sizeof(PMK_PASS_NODE));
		n->next->next = NULL;
		memcpy(n->next->pass, pass, 64);
	}
	
	return 0;
}

int RemovePMKPassNode(PMK_PASS_NODE **list, unsigned char *pass)
{
	PMK_PASS_NODE *n, *next = NULL;
	
	if(!list || !pass)
		return -1;
	if(!(*list))
		return -1;
	
	if(memcmp((*list)->pass, pass, 64) == 0)
	{
		next = *list;
		*list = (*list)->next;
		free(next);
	}
	else
	{
		for(n = *list; n->next; n = n->next)
		{
			if(memcmp(n->next->pass, pass, 64) == 0)
			{
				next = n->next;
				n->next = n->next->next;
				free(next);
				break;
			}
		}
	}
	if(!next)
		return -1;
	
	return 0;
}

int RemovePMKEntryNode(PMK_ENTRY_NODE **list, unsigned char *pass)
{
	PMK_ENTRY_NODE *n, *next = NULL;
	
	if(!list || !pass)
		return -1;
	if(!(*list))
		return -1;
	
	if(memcmp((*list)->pass, pass, 64) == 0)
	{
		next = *list;
		*list = (*list)->next;
		free(next);
	}
	else
	{
		for(n = *list; n->next; n = n->next)
		{
			if(memcmp(n->next->pass, pass, 64) == 0)
			{
				next = n->next;
				n->next = n->next->next;
				free(next);
				break;
			}
		}
	}
	if(!next)
		return -1;
	
	return 0;
}

int AttachPMKEntryNode(PMK_ENTRY_NODE **list, PMK_ENTRY_NODE *ent)
{
	PMK_ENTRY_NODE *n, *next;
	
	if(!list || !ent)
		return -1;
	
	if(!(*list))
	{
		*list = ent;
		(*list)->next = NULL;
	}
	else
	{
		for(n = *list; n->next; n = n->next);
		
		n->next = ent;
		n->next->next = NULL;
	}
	
	return 0;
}

PD_WORK *InitWork(MEM_PMK_DB *mdb)
{
	PD_WORK *w = NULL;
	PMK_ENTRY_NODE *elist = NULL, *ent = NULL;
	unsigned long x;
	PMK_PASS_NODE *n;
	
	if(!mdb)
	{
		bdbg(2) printf("InitWork() fail 1\n");
		return NULL;
	}
	
	w = (PD_WORK*)malloc(sizeof(PD_WORK));
	
	printf("x!\n");
	if((w->slist = GetPMKSSIDList(mdb)) == NULL)
	{
		bdbg(2) printf("InitWork() fail 2\n");
		free(w);
		return NULL;
	}
	printf("y!\n");
	for(w->spos = w->slist; w->spos; w->spos = w->spos->next)
	{
		printf("@");
		if((w->mtbl = GetPMKTable(mdb, w->spos->ssid)) == NULL)
		{
			bdbg(2) printf("InitWork() fail 3\n");
			FreePMKSSIDList(w->slist);
			free(w);
			return NULL;
		}
		if(w->mtbl->tbl.cal_pass == mdb->db.pass_num)
		{
			free(w->mtbl);
			continue;
		}
		printf("cal_pass=%d passnum=%d\n",w->mtbl->tbl.cal_pass, mdb->db.pass_num);
		if((w->rem = GetPMKPassList(mdb)) == NULL)
		{
			bdbg(2) printf("InitWork() fail 4\n");
			FreePMKSSIDList(w->slist);
			free(w->mtbl);
			free(w);
			return NULL;
		}
		n = w->rem;
		for(x ^= x; n; x++)
		{
			printf("+");
			n = n->next;
		}
		elist = GetPMKEntries(mdb, w->spos->ssid);
		printf("w->rem=%08x elist=%08x\n",w->rem,elist);
		for(ent = elist; ent; ent = ent->next)
		{
			printf("-");
			RemovePMKPassNode(&w->rem, ent->pass);
		}
		FreePMKEntries(elist);
		
		n = w->rem;
		for(x ^= x; n; x++)
		{
			printf("+");
			n = n->next;
		}
		bdbg(2) printf("InitWork() return %d\n", x); 
		return w;
	}
	
	bdbg(2) printf("InitWork() fail 5\n");
	
	return NULL;
}

int NextWork(MEM_PMK_DB *mdb, PD_WORK *w)
{
	PMK_ENTRY_NODE *elist = NULL, *ent = NULL;
	
	if(!mdb || !w)
		return -1;
	
	free(w->mtbl);
	for(w->spos = w->spos->next; w->spos; w->spos = w->spos->next)
	{
		if((w->mtbl = GetPMKTable(mdb, w->spos->ssid)) == NULL)
			return -1;
		if(w->mtbl->tbl.cal_pass == mdb->db.pass_num)
		{
			free(w->mtbl);
			continue;
		}
		if((w->rem = GetPMKPassList(mdb)) == NULL)
			return -1;
		elist = GetPMKEntries(mdb, w->spos->ssid);
		for(ent = elist; ent; ent = ent->next);
			RemovePMKPassNode(&w->rem, ent->pass);
		FreePMKEntries(elist);
		return 0;
	}
	
	return 1;
}

PMK_ENTRY_NODE *GetWork(PD_WORK *w, unsigned long num)
{
	PMK_ENTRY_NODE *elist = NULL, *ent = NULL;
	PMK_PASS_NODE *n = NULL;
	unsigned char del[64];
	unsigned long x;
	
	if(!w || !num)
	{
		bdbg(2) printf("GetWork() fail 1\n");
		return NULL;
	}
	if(!w->rem)
	{
		bdbg(2) printf("GetWork() need next work\n");
		elist = (PMK_ENTRY_NODE*)malloc(sizeof(PMK_ENTRY_NODE));
		memset(elist, 0, sizeof(PMK_ENTRY_NODE));
		return elist;
	}
	
	n = w->rem;
	for(x ^= x; x < num && n; x++)
	{
		if(!elist)
		{
			elist = (PMK_ENTRY_NODE*)malloc(sizeof(PMK_ENTRY_NODE));
			ent = elist;
		}
		else
		{
			ent->next = (PMK_ENTRY_NODE*)malloc(sizeof(PMK_ENTRY_NODE));
			ent = ent->next;
		}
		memcpy(ent->pass, n->pass, 64);
		memset(ent->pmk, 0, 32);
		ent->next = NULL;
		memcpy(del, n->pass, 64);
		n = n->next;
		RemovePMKPassNode(&w->rem, del);
	}
	
	return elist;
}

int ReplaceWork(PD_WORK *w, PMK_ENTRY_NODE *ent)
{
	if(!w || !ent)
		return -1;
	
	while(ent)
	{
		AddPMKPassNode(&w->rem, ent->pass);
		ent = ent->next;
	}
	
	return 0;
}

int readAt(int fd, off_t offset, void *buf, unsigned long len)
{
	if(!buf || !len)
		return -1;
	
	if(lseek(fd, offset, SEEK_SET) == -1)
		return -1;
	
	if(read(fd, buf, len) == -1)
		return -1;
	
	return 0;
}

int writeAt(int fd, off_t offset, void *buf, unsigned long len)
{
	if(!buf || !len)
		return -1;
	
	if(lseek(fd, offset, SEEK_SET) == -1)
		return -1;
	
	if(write(fd, buf, len) == -1)
		return -1;
	
	return 0;
}

PTK_DATA *ReadPCAP(char *path)
{
	PTK_DATA *pdat;
	pcap_t *pcap;
	struct pcap_pkthdr head;
	WLAN_HEAD *wlan;
	LLC_HEAD *llc;
	EAPOL_HEAD *eapolh;
	EAPOL_KEY *eapol;
	char *buf;
	char errbuf[PCAP_ERRBUF_SIZE];
	unsigned long x, frames = 0;
	
	unsigned short key_info;
	unsigned short key_ver;
	unsigned short key_index;
	unsigned short key_len;
	
	unsigned char replay[8];
	
	if(!path)
		return NULL;
	
	if(!(pcap = pcap_open_offline(path, errbuf)))
	{
		bdbg(2) printf("Failed to pcap_open_offline(\"%s\").\n", path);
		return NULL;
	}
	
	pdat = (PTK_DATA*)malloc(sizeof(PTK_DATA));
	memset(pdat, 0, sizeof(PTK_DATA));
	memset(replay, 0, 8);
	
	x ^= x;
	bdbg(1) printf("Reading Data");
	while((buf = pcap_next(pcap, &head)))
	{
		x++;
		bdbg(4) printf(".");
		wlan = (WLAN_HEAD*)buf;
		if(head.len > 12)
		{
			llc = (LLC_HEAD*)wlan->data;
			if(head.len > 12 + llc->len)
			{
				eapolh = (EAPOL_HEAD*)(llc->data + llc->len);
				eapol = (EAPOL_KEY*)eapolh->data;
			}
			else
				eapol = NULL;
		}
		else
		{
			llc = NULL;
			eapol = NULL;
		}
		if(!llc || !eapol)
			continue;
		
		if(eapolh->pae_type == WPA_AUTH_MAGIC)
		{
			bdbg(4) printf("! %4x", eapol->info);
			key_info = rol16(8, eapol->info);
			key_len = rol16(8, eapol->key_len);
			key_ver = key_info & EAPOL_VERSION_MASK;
			key_index = key_info &EAPOL_INDEX_MASK;
			key_index = key_index >> 4;
			bdbg(4) printf("! %4x", key_ver);
			if(eapolh->ver != 1 || eapolh->type != 3)
				continue;
			bdbg(4) printf("!");
			if(key_ver != EAPOL_RC4_KEY && key_ver != EAPOL_AES_KEY)
				continue;
			bdbg(4) printf("!");
			if(key_ver == EAPOL_RC4_KEY)
			{
				bdbg(4) printf(">");
				if(eapolh->type != 254 && (key_info & EAPOL_PAIRWISE) == 0)
					continue;
			}
			else
			{
				if(key_ver == EAPOL_AES_KEY)
				{
					bdbg(4) printf("<");
					if(eapolh->type != 2 && (key_info & EAPOL_PAIRWISE) == 0)
						continue;
				}
			}
			bdbg(4) printf("!");
			
			if(isset(key_info, EAPOL_MIC) && !isset(key_info, EAPOL_ACK) && !isset(key_info, EAPOL_INSTALL) && eapol->dlen > 0)
			{
				bdbg(3) printf("\nHandshake Packet #2");
				memcpy(pdat->snonce, eapol->nonce, 32);
				set(&pdat->status, PTK_SNONCE);
			}
			else
			{
				if(isset(key_info, EAPOL_MIC) && isset(key_info, EAPOL_INSTALL) && isset(key_info, EAPOL_ACK))
				{
					bdbg(3) printf("\nHandshake Packet #3");
					memcpy(pdat->sa, wlan->dst, 6);
					set(&pdat->status, PTK_SA);
					memcpy(pdat->aa, wlan->src, 6);
					set(&pdat->status, PTK_AA);
					memcpy(pdat->anonce, eapol->nonce, 32);
					set(&pdat->status, PTK_ANONCE);
					memcpy(replay, eapol->replay, 8);
				}
				else
				{
					bdbg(4) printf("else2\n");
					if(isset(key_info, EAPOL_MIC) && !isset(key_info, EAPOL_ACK) && !isset(key_info, EAPOL_INSTALL) && memcmp(replay, eapol->replay, 8) == 0)
					{
						bdbg(3) printf("\nHandshake Packet #4");
						memcpy(pdat->mic, eapol->mic, 16);
						set(&pdat->status, PTK_MIC);
						memcpy(pdat->eapol, &eapolh->ver, 99);
						memset(pdat->eapol + 81, 0, 16);
						set(&pdat->status, PTK_EAPOL);
						pdat->ver = key_ver;
						break;
					}
					else
					{
						bdbg(3) printf("\nHandshake Packet #1 Maybe?");
					}
				}
			}
			frames++;
			
			bdbg(3) printf("\nPacket: %8u\nLength:\t%u\nCapLen:\t%u\n802.11 Info:\nFrame Control:\t(0x%04X)\nDuration:\t%u\nSource MAC:\t%02x:%02x:%02x:%02x:%02x:%02x\nDest MAC:\t%02x:%02x:%02x:%02x:%02x:%02x\nBSSID:\t\t%02x:%02x:%02x:%02x:%02x:%02x\nSequence:\t%u\nLLC Info:\nDSAP:\t%02X\nSSAP:\t%02X\nLength:\t%02x\nEAPOL Info:\nPAE Type:\t%04x\nVersion:\t%u\nType:\t%02X\nKey Info:\t%02X\nKey Length:\t%u\n\nReading data", x, head.len, head.caplen, wlan->frame_ctl, wlan->duration, wlan->src[0], wlan->src[1], wlan->src[2], wlan->src[3], wlan->src[4], wlan->src[5], wlan->dst[0], wlan->dst[1], wlan->dst[2], wlan->dst[3], wlan->dst[4], wlan->dst[5], wlan->bssid[0], wlan->bssid[1], wlan->bssid[2], wlan->bssid[3], wlan->bssid[4], wlan->bssid[5], wlan->seq, llc->dsap, llc->ssap, llc->len, eapolh->pae_type, eapolh->ver, eapolh->type, eapol->info, key_len);
		}
	}
	bdbg(3) printf("\n%x frames of interest.\n", frames);
	
	return pdat;
}

int pmk_to_ptk(unsigned char *pmk, unsigned char *aa, unsigned char *sa, unsigned char *anonce, unsigned char *snonce, unsigned char *ptk)
{
	SHA_CTX c;
	unsigned char data[76], counter = 0, ipad[64], opad[64], md[20];
	unsigned long x, y = 0, plen;
	unsigned char *addr[] = {"Pairwise key expansion", "\0", data, &counter};
	
	memset(data, 0, 76);
	
	if(memcmp(aa, sa, 6) < 0)
	{
		memcpy(data, aa, 6);
		memcpy(data + 6, sa, 6);
	}
	else
	{
		memcpy(data, sa, 6);
		memcpy(data + 6, aa, 6);
	}
	
	if(memcmp(anonce, snonce, 32) < 0)
	{
		memcpy(data + 12, anonce, 32);
		memcpy(data + 44, snonce, 32);
	}
	else
	{
		memcpy(data + 12, snonce, 32);
		memcpy(data + 44, anonce, 32);
	}	
	
	while(y < 64)
	{
		plen = 64 - y;
		memset(ipad, 0x36, 64);
		memset(opad, 0x5c, 64);
	
		for(x ^= x; x < 32; x++)
		{
			ipad[x] ^= pmk[x];
			opad[x] ^= pmk[x];
		}
		
		SHA1_Init(&c);
		SHA1_Update(&c, ipad, 64);
		SHA1_Update(&c, addr[0], strlen(addr[0]));	
		SHA1_Update(&c, addr[1], 1);
		SHA1_Update(&c, addr[2], 76);
		SHA1_Update(&c, addr[3], 1);
		SHA1_Final(md, &c);
		
		SHA1_Init(&c);
		SHA1_Update(&c, opad, 64);
		SHA1_Update(&c, md, 20);
		SHA1_Final(md, &c);
		
		if(plen > 20)
			memcpy(ptk + y, md, 20);
		else
			memcpy(ptk + y, md, plen);
		
		counter++;
		y += 20;
	}
	
	return 0;
}

int pbkdf2_wpa(unsigned char *pass, unsigned char *ssid, unsigned char *pmk)
{
	SHA_CTX c, hipad, hopad;
	unsigned char *trick;
	unsigned char ipad[64], opad[64], tmp[20], md[20], cbuf[4];
	unsigned long x, y, ssid_len;
	
	*(unsigned long*)cbuf = 0;
	cbuf[3] = 1;
	
	memset(ipad, 0x36, 64);
	memset(opad, 0x5c, 64);
		
	for(x ^= x; pass[x] != 0; x++)
	{
		ipad[x] ^= pass[x];
		opad[x] ^= pass[x];
	}
	
	ssid_len = strlen(ssid);
		
	SHA1_Init(&c);
	SHA1_Update(&c, ipad, 64);
	memcpy(&hipad, &c, sizeof(SHA_CTX));
	SHA1_Update(&c, ssid, ssid_len);	
	SHA1_Update(&c, cbuf, 4);
	SHA1_Final(md, &c);
	
	SHA1_Init(&c);
	SHA1_Update(&c, opad, 64);
	memcpy(&hopad, &c, sizeof(SHA_CTX));
	SHA1_Update(&c, md, 20);
	SHA1_Final(md, &c);
		
	memcpy(tmp, md, 20);
		
	for(x = 1; x < 4096; x++)
	{
		memcpy(&c, &hipad, sizeof(SHA_CTX));
		SHA1_Update(&c, tmp, 20);
		SHA1_Final(tmp, &c);
			
		memcpy(&c, &hopad, sizeof(SHA_CTX));
		SHA1_Update(&c, tmp, 20);
		SHA1_Final(tmp, &c);
			
		for(y ^= y; y < 20; y ++)
			md[y] ^= tmp[y];
	}
		
	memcpy(pmk, md, 20);
	cbuf[3]++;
		
	memcpy(&c, &hipad, sizeof(SHA_CTX));
	SHA1_Update(&c, ssid, ssid_len);	
	SHA1_Update(&c, cbuf, 4);
	SHA1_Final(md, &c);
		
	memcpy(&c, &hopad, sizeof(SHA_CTX));
	SHA1_Update(&c, md, 20);
	SHA1_Final(md, &c);
		
	memcpy(tmp, md, 20);
		
	for(x = 1; x < 4096; x++)
	{
		memcpy(&c, &hipad, sizeof(SHA_CTX));
		SHA1_Update(&c, tmp, 20);
		SHA1_Final(tmp, &c);
			
		memcpy(&c, &hopad, sizeof(SHA_CTX));
		SHA1_Update(&c, tmp, 20);
		SHA1_Final(tmp, &c);
			
		for(y ^= y; y < 20; y ++)
			md[y] ^= tmp[y];
	}
	for(x ^= x; x < 12; x++)
		pmk[20 + x] = md[x];

	return 0;
}

int get_mic(unsigned long ver, unsigned char *key_mic, unsigned char *eapol, unsigned char *mic)
{
	unsigned long x;
	unsigned char md[20], ipad[64], opad[64];
	SHA_CTX sha;
	MD5_CTX md5;
	
	memset(ipad, 0x36, 64);
	memset(opad, 0x5c, 64);
	
	for(x ^= x; x < 16; x++)
	{
		ipad[x] ^= key_mic[x];
		opad[x] ^= key_mic[x];
	}
	
	switch(ver)
	{
		case EAPOL_RC4_KEY:
			MD5_Init(&md5);
			MD5_Update(&md5, ipad, 64);
			MD5_Update(&md5, eapol, 99);
			MD5_Final(md, &md5);
			
			MD5_Init(&md5);
			MD5_Update(&md5, opad, 64);
			MD5_Update(&md5, md, 16);
			MD5_Final(md, &md5);
			memcpy(mic, md, 16);
			break;
		case EAPOL_AES_KEY:
			SHA1_Init(&sha);
			SHA1_Update(&sha, ipad, 64);
			SHA1_Update(&sha, eapol, 99);	
			SHA1_Final(md, &sha);
		
			SHA1_Init(&sha);
			SHA1_Update(&sha, opad, 64);
			SHA1_Update(&sha, md, 20);
			SHA1_Final(md, &sha);
			memcpy(mic, md, 16);
			break;
		default:
			return -1;
	}
	
	return 0;
}

void *ServerInput(void *unused)
{
	char ch;
	CONNECTION_NODE *c;
	float speed;
	
	while(isset(STATUS, PD_TAKE_INPUT | PD_SERVE))
	{
		ch = (char)fgetc(stdin);
		switch(ch)
		{
			case 'p':
				speed = 0.0f;
				pthread_mutex_lock(&m_con);
				for(c = con; c != NULL; c = c->next)
					speed += c->speed;
				pthread_mutex_unlock(&m_con);
				printf("*****\nProjected Speed:\t%f\n*****\n", speed);
				break;
			case 'q':
				clear(&STATUS, PD_SERVE);
				printf("*****\nExiting server mode...\n*****\n");
				break;
		}
	}
	
	return NULL;
}

void *InitConnection(CONNECTION_NODE *c)
{
	char *buf = NULL;
	PD_CHATTER *ch = NULL, *ch2 = NULL;
	PMK_ENTRY_NODE *n = NULL;
	int err = 0;
	unsigned long x;
	unsigned char del[64];
	
	bdbg(1) printf("thread%08x: Entry.\n", c->pth);
		
	while(ch = GetChatter(c->s))
	{
		switch(ch->op)
		{
			case PDC_GET_NEXT:
				bdbg(1) printf("thread%08x: Requesting next command.\n", c->pth);
				while(!c->dist)
				{
					if(c->speed == 0.0f)
						c->dnum = 1000;
					else
						c->dnum = (unsigned long)((float)work_load * c->speed);
					bdbg(1) printf("thread%08x: Trying to get %d passwords.\n", c->pth, c->dnum);
					pthread_mutex_lock(&m_work);
					c->dist = GetWork(work, c->dnum);
					pthread_mutex_unlock(&m_work);	
					n = c->dist;
					for(c->dnum ^= c->dnum; n; c->dnum++)
						n = n->next;
					bdbg(1) printf("thread%08x: Got %d.\n", c->pth, c->dnum);
					if(c->dist->pass[0] == 0 && c->dist->next == NULL)
					{
						bdbg(1) printf("thread%08x: Sleeping...\n", c->pth);
						free(c->dist);
						c->dist = NULL;
						sleep(work_load);
					}
				}
				if(!isset(c->flags, PD_CON_SSID_LOCKED))
				{
					bdbg(1) printf("thread%08x: Sending SSID \"%s\"...\n", c->pth, work->mtbl->tbl.ssid);
					ch2 = (PD_CHATTER*)malloc(40);
					ch2->flags ^= ch2->flags;
					ch2->op = PDC_CHANGE_SSID;
					ch2->count = 1;
					memcpy(ch2->data, work->mtbl->tbl.ssid, 32);
					bdbg(4)
					{
						b_dump((unsigned char*)ch2, 'X', 2, 40);
						b_dump(ch2->data, 'C', 32, 32);
					}
					SendChatter(c->s, ch2);
					free(ch2);
					ch2 = GetChatter(c->s);
					if(!(ch2->op == PDC_GET_NEXT && isset(ch2->flags, PDCF_ACK)))
					{
						bdbg(1) printf("thread%08x: Got invalid response...\n", c->pth);
						err = -1;
						break;
					}
					free(ch2);
					ch2 = NULL;
					set(&c->flags, PD_CON_SSID_LOCKED);
				}
				bdbg(1) printf("thread%08x: Making packet for %d passwords of %d size.\n", c->pth, c->dnum, 8 + 64 * c->dnum);
				ch2 = (PD_CHATTER*)malloc(8 + 64 * c->dnum);
				ch2->flags ^= ch2->flags;
				ch2->op = PDC_PASS_LIST;
				ch2->count = c->dnum;
				n = c->dist;
				for(x ^= x; n; x++)
				{
					bdbg(3) printf("thread%08x: [%d] copying '%s' to packet.\n", c->pth, x, n->pass);
					memcpy(ch2->data + 64 * x, n->pass, 64);
					n = n->next;
				}
				bdbg(1) printf("thread%08x: Sending %d passwords.\n", c->pth, c->dnum);
				bdbg(4)
				{
					b_dump((unsigned char*)ch2, 'X', 2, 8 + 64 * c->dnum);
					b_dump(ch2->data, 'C', 64, 64 * c->dnum);
				}
				SendChatter(c->s, ch2);
				free(ch2);
				ch2 = NULL;
				break;
			case PDC_PMK_LIST:
				bdbg(1) printf("thread%08x: Deposited PMK list.\n", c->pth);
				bdbg(4)
				{
					b_dump(ch, 'X', 2, 8 + 32 * ch->count);
					printf("\n");
				}
				n = c->dist;
				pthread_mutex_lock(&m_db);
				pthread_mutex_lock(&m_work);
				buf = (unsigned char*)malloc(ch->count * 64);
				for(x ^= x; n; x++)
				{
					memcpy(buf + 64 * x, n->pass, 64);
					/*AddPMK(c->mdb, work->mtbl, ch->data + 32 * x, n->pass);*/
					memcpy(del, n->pass, 64);
					n = n->next;
					RemovePMKEntryNode(&c->dist, del);
				}
				AddPMKBlock(c->mdb, work->mtbl, ch->data, buf, ch->count);
				pthread_mutex_unlock(&m_work);
				pthread_mutex_unlock(&m_db);
				break;
			case PDC_SPEED:
				bdbg(1) printf("thread%08x: Reported speed at %f.\n", c->pth, *(float*)&ch->count);
				bdbg(4)
				{
					b_dump(ch, 'X', 2, 8);
					printf("\n");
				}
				c->speed = *(float*)&ch->count;
				break;
			default:
				bdbg(1) printf("thread%08x: Unexpected op.\n", c->pth);
				err = -1;
				break;
		}
		if(err == -1)
		{
			bdbg(1) printf("thread%08x: ERROR\n", c->pth);
			break;
		}
	}
	
	bdbg(1) printf("thread%08x: Exit.\n", c->pth);
	if(RemoveConnection(&con, c, &m_con) == -1)
	{
		bdbg(1) printf("thread%08x: Failed to remove connection from list.\n", c->pth);
	}
	
	return NULL;
}

void *InitRemote(CONNECTION_NODE *c)
{
	PD_CHATTER *ch = NULL, *ch2 = NULL;
	int err = 0;
	unsigned long x;
	unsigned char ssid[32];
	float elapsed;
	struct timeval start, end;
		
	bdbg(1) printf("thread%08x: Entry.\n", c->pth);
	
	memset(ssid, 0, 32);
	
	while(1)
	{
		if(!ch)
		{
			bdbg(1) printf("thread%08x: Making request packet.\n", c->pth);
			ch = (PD_CHATTER*)malloc(8);
			ch->flags ^= ch->flags;
			ch->op = PDC_GET_NEXT;
			ch->count ^= ch->count;
		}
		bdbg(1) printf("thread%08x: Sending packet.\n", c->pth);
		if(SendChatter(c->s, ch) == -1)
		{
			bdbg(1) printf("thread%08x: Failed to send PDC_GET_NEXT.\n", c->pth);
			break;
		}
		bdbg(1) printf("thread%08x: Waiting for next packet...\n", c->pth);
		if(!(ch2 = GetChatter(c->s)))
		{
			bdbg(1) printf("thread%08x: Failed to recieve command.\n", c->pth);
			break;
		}
		switch(ch2->op)
		{
			case PDC_CHANGE_SSID:
				bdbg(1) printf("thread%08x: Change SSID to \"%s\" and set ACK flag.\n", c->pth, ch2->data);
				memcpy(ssid, ch2->data, 32);
				set(&ch->flags, PDCF_ACK);
				break;
			case PDC_PASS_LIST:
				bdbg(1) printf("thread%08x: Got %d passwords.\n", c->pth, ch2->count);
				free(ch);
				if(ssid[0] == 0)
				{
					bdbg(1) printf("thread%08x: No SSID to compute for.\n", c->pth);
					err = -1;
					break;
				}
				ch = (PD_CHATTER*)malloc(8 + ch2->count * 32);
				ch->flags ^= ch->flags;
				ch->op = PDC_PMK_LIST;
				ch->count = ch2->count;
				bdbg(1) printf("thread%08x: Generating PMKs.\n", c->pth);
				gettimeofday(&start, 0);
				for(x ^= x; x < ch2->count; x++)
				{
					pbkdf2_wpa(ch2->data + x * 64, ssid, ch->data + x * 32);
				}
				gettimeofday(&end, 0);
				if (end.tv_usec < start.tv_usec)
				{
					end.tv_sec--;
					end.tv_usec += 1000000;
				}
				end.tv_sec -= start.tv_sec;
				end.tv_usec -= start.tv_usec;
				elapsed = end.tv_sec + end.tv_usec / 1000000.0;
				c->speed = ch2->count / elapsed;
				bdbg(1) printf("thread%08x: Sending PMKs.\n", c->pth);
				if(SendChatter(c->s, ch) == -1)
				{
					bdbg(1) printf("thread%08x: Failed to send PMK list.\n", c->pth);
					err = -1;
					break;
				}
				free(ch);
				ch = (PD_CHATTER*)malloc(8);
				ch->flags ^= ch->flags;
				ch->op = PDC_SPEED;
				ch->count = *(unsigned long*)&c->speed;
				bdbg(1) printf("thread%08x: Sending speed.\n", c->pth);
				if(SendChatter(c->s, ch) == -1)
				{
					bdbg(1) printf("thread%08x: Failed to send calculation speed.\n", c->pth);
					err = -1;
					break;
				}
				free(ch); 
				ch = NULL;
				break;
			default:
				bdbg(1) printf("thread%08x: Invalid op.\n", c->pth);
				err = -1;
				break;
		}
		if(err == -1)
			break;
		free(ch2);
		ch2 = NULL;
	}
	
	bdbg(1) printf("thread%08x: Exit.\n", c->pth);
	if(RemoveConnection(&con, c, &m_con) == -1)
	{
		bdbg(1) printf("thread%08x: Failed to remove connection from list.\n", c->pth);
	}
	
	return NULL;
}

int RemoveConnection(CONNECTION_NODE **list, CONNECTION_NODE *c, pthread_mutex_t *cmtx)
{
	CONNECTION_NODE *n, *next;
	
	if(!list || !c || !cmtx)
		return -1;
	if(!(*list))
		return -1;
	
	pthread_mutex_lock(cmtx);
	if(*list == c)
	{
		if((*list)->dist)
		{
			FreePMKEntries((*list)->dist);
		}
		if((*list)->s != -1)
			close((*list)->s);
		next = (*list)->next;
		free(*list);
		*list = next;
		pthread_mutex_unlock(cmtx);
		return 0;
	}
	else
	{
		for(n = *list; n; n = n->next)
		{
			if(n->next == c)
			{
				if(n->next->dist)
				{
					FreePMKEntries(n->next->dist);
				}
				if(n->next->s != -1)
					close(n->next->s);
				next = n->next->next;
				free(n->next);
				n->next = next;
				pthread_mutex_unlock(cmtx);
				return 0;
			}
		}
	}
	
	pthread_mutex_unlock(cmtx);
	return -1;
}

int AddConnection(CONNECTION_NODE **list, CONNECTION_NODE *c, pthread_mutex_t *mtx)
{
	CONNECTION_NODE *n;
	
	if(!list || !c)
		return -1;
	
	pthread_mutex_lock(mtx);
	if(!(*list))
	{
		*list = c;
	}
	else
	{
		for(n = *list; n->next; n = n->next);
		n->next = c;
	}
	
	pthread_mutex_unlock(mtx);
	return 0;
}

int FreeConnectionList(CONNECTION_NODE **list, CONNECTION_NODE *c, pthread_mutex_t *cmtx)
{
	CONNECTION_NODE *n, *next;
	
	if(!list)
		return -1;
	
	while(*list)
	{
		if(RemoveConnection(list, *list, cmtx) == -1)
			return -1;
	}
	
	return 0;
}
/*
int RemoveDistro(DISTRO_NODE **list, DISTRO_NODE *d, pthread_mutex_t *mtx)
{
	DISTRO_NODE *n, *next;
	
	if(!list || !d)
		return -1;
	if(!(*list))
		return -1;
	
	pthread_mutex_lock(mtx);
	if(*list == d)
	{
		next = (*list)->next;
		free(*list);
		*list = next;
		pthread_mutex_unlock(mtx);
		return 0;
	}
	else
	{
		for(n = *list; n; n = n->next)
		{
			if(n->next == d)
			{
				next = n->next->next;
				free(n->next);
				n->next = next;
				pthread_mutex_unlock(mtx);
				return 0;
			}
		}
	}
	
	pthread_mutex_unlock(mtx);
	return -1;
}

int AddDistro(DISTRO_NODE **list, DISTRO_NODE *d, pthread_mutex_t *mtx)
{
	DISTRO_NODE *n;
	
	if(!list || !d)
		return -1;
	
	pthread_mutex_lock(mtx);
	if(!(*list))
	{
		*list = d;
	}
	else
	{
		for(n = *list; n->next; n = n->next);
		n->next = d;
	}
	
	pthread_mutex_unlock(mtx);
	return 0;
}

int FreeDistroList(DISTRO_NODE **list, pthread_mutex_t *mtx)
{
	DISTRO_NODE *n, *next;
	PMK_ENTRY_NODE *d, *dnext;
	
	if(!list)
		return -1;
	
	pthread_mutex_lock(mtx);
	for(next = n = *list; next; n = next)
	{
		if(n->dist)
			for(dnext = d = n->dist; dnext; d = dnext)
			{
				dnext = d->next;
				free(d);
			}
		next = n->next;
		free(n);
	}
	*list = NULL;
	
	pthread_mutex_unlock(mtx);
	return 0;
}
*/
PD_CHATTER *GetChatter(int s)
{
	PD_CHATTER *ch = NULL;
	unsigned char *buf = NULL;
	unsigned long len, recd = 0;
	int err;
	struct timeval tv;
	
	gettimeofday(&tv, 0);
	
	bdbg(2) printf("GetChatter() %d.%06d\n", tv.tv_sec, tv.tv_usec);

	
	if(s == -1)
		return NULL;
	bdbg(3) printf("-\n");
	if((err = recv(s, &len, 4, 0)) != 4)
	{
		switch(err)
		{
			case -1:
				bdbg(2) printf("Socket errored!\n");
				break;
			case 0:
				bdbg(2) printf("Socket closed!\n");
				break;
			default:
				bdbg(2) printf("Wrong number of bytes!\n");
				break;
		}
		if(err < 1)
			return NULL;
	}
	bdbg(3) printf("-\n");
	if(len == 0)
		return NULL;
	buf = (char*)malloc(len);
	bdbg(3) printf("-\n");
	while(recd < len)
	{
		bdbg(3) printf("--\n");
		err = recv(s, buf + recd, len - recd, 0);
		switch(err)
		{
			case -1:
				bdbg(2) printf("Socket errored!\n");
				break;
			case 0:
				bdbg(2) printf("Socket closed!\n");
				break;
			default:
				recd += err;
				break;
		}
		if(err < 1)
		{
			free(buf);
			return NULL;
		}
	}
	bdbg(3) printf("-\n");
	ch = (PD_CHATTER*)buf;
	
	switch(ch->op)
	{
		case PDC_SPEED:
		case PDC_GET_NEXT:
			if(len != 8)
				err = -1;
			break;
		case PDC_PMK_LIST:
			if(len != 8 + ch->count * 32)
				err = -1;
			break;
		case PDC_CHANGE_SSID:
			if(len != 40 || ch->count != 1)
				err = -1;
			break;
		case PDC_PASS_LIST:
			if(len != 8 + ch->count * 64)
				err = -1;
			break;
		default:
			err = -1;
			break;
	}
	bdbg(3) printf("-\n");
	if(err == -1)
	{
		bdbg(2) printf("Data not understood.\n");
		return NULL;
	}
	bdbg(3) printf("-\n");
	return ch;
}

int SendChatter(int s, PD_CHATTER *ch)
{
	unsigned long len;
	struct timeval tv;
	
	gettimeofday(&tv, 0);
	
	
	bdbg(2) printf("SendChatter() %d.%06d\n", tv.tv_sec, tv.tv_usec);
	
	if(!ch)
		return -1;
	
	switch(ch->op)
	{
		case PDC_SPEED:
		case PDC_GET_NEXT:
			len = 8;
			break;
		case PDC_PMK_LIST:
			len = 8 + ch->count * 32;
			break;
		case PDC_CHANGE_SSID:
			len = 40;
			break;
		case PDC_PASS_LIST:
			len = 8 + ch->count * 64;
			break;
		default:
			return -1;
	}
	bdbg(2) printf("SendChatter() sending length...\n");
	if(send(s, &len, 4, 0) == -1)
		return -1;
	bdbg(2) printf("SendChatter() sending payload...\n");
	if(send(s, ch, len, 0) == -1)
		return -1;
	bdbg(2) printf("SendChatter() done\n");
	return 0;
}

void usage(char *name)
{
	if(!name)
		return;
	
	printf("Usage: %s [options]\n"
		"\n"
		"Options:\n"
		"	-a pass|ssid <filename>		--	Add password or SSID list from specified file\n"
		"	-c <filename>			--	PCAP capture file\n"
		"	-d <filename>			--	PMK Database\n"
		"	-h				--	Display this screen\n"
		"	-l pass|ssid|calc [<table>]	--	Lists passwords SSIDs or calculated PMKs from database\n"
		"	-p <port>			--	Specify port number\n"
		"	-r <host>			--	Specify remote host (Client Mode)\n"
		"	-s				--	Server Mode\n"
		"	-t <threads>			--	Number of threads to use for calculating PMKs\n"
		"	-u				--	Unlock locked database after crash\n"
		"	-v <level>			--	Set debug level\n"
		"	-w <seconds>			--	Number of seconds of work to hand each client\n", name);
	
	return;
}

void crash(int signal)
{
	struct timeval tv;
	
	gettimeofday(&tv, 0);
	
	bdbg(2) printf("crash: ");
	switch(signal)
	{
		case SIGINT:
			bdbg(2) printf("Interupted. %d.%06d\n", tv.tv_sec, tv.tv_usec);
			exit(1);
			break;
		case SIGILL:
			bdbg(2) printf("Illegal instruction. ");
			break;
		case SIGFPE:
			bdbg(2) printf("Floating point error. ");
			break;
		case SIGSEGV:
			bdbg(2) printf("Segmentation fault!!!! %d.%06d\n", tv.tv_sec, tv.tv_usec);
			exit(1);
			break;
		case SIGPIPE:
			bdbg(2) printf("Broken pipe. ");
			break;
		case SIGSTKFLT:
			bdbg(2) printf("Stack fault. ");
			break;
		case SIGURG:
			bdbg(2) printf("Urgent condition on socket. ");
			break;
		default:
			bdbg(2)(printf("Unknown."));
			break;
	}
	bdbg(2) printf("%d.%06d\n", tv.tv_sec, tv.tv_usec);
}
