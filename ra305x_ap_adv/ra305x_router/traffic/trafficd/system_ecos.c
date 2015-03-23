/*
 * yubo@xiaomi.com
 * 2014-09-12
 */


#ifdef __ECOS

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include <sys/types.h>
#include <network.h>
#include <stdio.h>
#include <netinet/if_ether.h>
#include <sys/mbuf.h>
#include <cyg/kernel/kapi.h>
#include <cyg/io/flash.h>
#include <cyg/infra/diag.h>
#include <ifaddrs.h>
#include <cyg/io/eth/eth_drv_stats.h>
#include <cyg/io/eth/eth_drv.h>
#include <cyg/io/eth/netdev.h>

#include <config.h>
#include <http_proc.h>
#include <http_conf.h>
#include <cfg_net.h>
#include <sys_status.h>
#include <net/route.h>
#include <net/if.h>
#include <stdlib.h>
#include <cfg_id.h>

#if MODULE_SYSLOG
#include <eventlog.h>
#endif

#include <cfg_def.h>
#include <cfg_net.h>
#include <time.h>
#include <cgi_api.h>

//#include <rt_os_net.h>
#endif

#include <sys/socket.h>
#include "traffic/system.h"
#include "traffic/trafficd.h"

#include "traffic/ubus.h"

int padding = RSA_PKCS1_PADDING;
static const char rnd_seed[] = "string to make the random number generator think it has entropy";
char repeater_key[16] = {0};
char repeater_iv[16] = {0};
char router_key[16] = {0};
char router_iv[16] = {0};

#define MAX_ALLOC_LEN 512
char rr_ssid[MAX_ALLOC_LEN] = {0};
char rr_pwd[MAX_ALLOC_LEN] = {0};
int flag_ssid_pwd = 0;


#define ARP_DEFAULT_SIZE 16

struct _arp_entry{
	__be32 ip;
	char hw[HWAMAXLEN];
};

struct arp_table {
	int idx;
	int size;
	struct _arp_entry arps[];
};

struct trafficd_system_data {
	struct uloop_timeout timeout_mat;
	struct uloop_timeout timeout_init;
} *sd;

struct arp_table *arp;


#ifdef __ECOS
typedef struct _IPMacMappingEntry
{
    UINT    ipAddr; /* In network order */
    UCHAR   macAddr[MAC_ADDR_LEN];
    ULONG   lastTime;
    struct _IPMacMappingEntry *pNext;
}IPMacMappingEntry, *PIPMacMappingEntry;
#endif

extern int rt28xx_ap_ioctl(
    struct eth_drv_sc   *pEndDev,
    int         cmd,
    caddr_t     pData);

static void update_mat_table(void);


enum {
	INIT_TOKEN,
	INIT_SSID,
	INIT_SSID_PWD,
	__INIT_MAX,
};

static const struct blobmsg_policy init_policy[__INIT_MAX] = {
	[INIT_TOKEN] = { .name = "token",    .type = BLOBMSG_TYPE_STRING },
	[INIT_SSID] = { .name = "ssid",     .type = BLOBMSG_TYPE_STRING },
	[INIT_SSID_PWD] = { .name = "ssid_pwd", .type = BLOBMSG_TYPE_STRING },
};

static RSA * createRSA(unsigned char * key, int pub_key)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO"  );
        return 0;
    }
    if(pub_key)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
    if(rsa == NULL)
    {
        printf( "Failed to create RSA"  );
    }

    return rsa;
}

static int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}

static int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,0);
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}

static int private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,0);
    int result = RSA_private_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}

static int public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,1);
    int  result = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}

static void printLastError(char *msg)
{
    char * err = malloc(130);
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
    free(err);
}

static int base64Encode(char* output, const unsigned char* data, size_t length)
{
    BIO* base64 = BIO_new(BIO_f_base64());
    if (base64 == NULL) {
        return -1;
    }
    BIO_set_flags(base64, BIO_FLAGS_BASE64_NO_NL);
    BIO* memory = BIO_new(BIO_s_mem());
    if (memory == NULL) {
        BIO_free_all(base64);
        return -1;
    }
    BIO* bio = BIO_push(base64, memory);
    BIO_write(bio, data, length);
    if (BIO_flush(bio) == -1) {
        return -1;
    }
    const char* p;
    size_t n = BIO_get_mem_data(memory, &p);
    int i;
    for (i = 0; i < n; ++i) {
        if (*(p+i) == '+') {
            *(output+i) = '-';
        } else if (*(p+i) == '/') {
            *(output+i) = '_';
        } else if (*(p+i) == '=') {
            break;
        } else {
            *(output+i) = *(p+i);
        }
    }

    BIO_free_all(bio);
    return n;
}

#if 1
static int
base64Decode(char* output, const unsigned char* data, size_t length) {
    BIO* base64 = BIO_new(BIO_f_base64());
    if (base64 == NULL) {
        return -1;
    }
    BIO_set_flags(base64, BIO_FLAGS_BASE64_NO_NL);
    BIO* memory = BIO_new_mem_buf(data, length);
    if (memory == NULL) {
        BIO_free_all(base64);
        return -1;
    }
    BIO* bio = BIO_push(base64, memory);
    int n = BIO_read(bio, output, length);
    if (n < 0) {
        BIO_free_all(bio);
        return -1;
    }
    BIO_free_all(bio);
    return n;
}
#endif

/**
* *  * Create random UUID
* *   *
* *    * @param buf - buffer to be filled with the uuid string
* *     */
static char *random_uuid( char *buf )
{
    const char *c = "89ab";
    char *p = buf;
    int n;

    srand(time(0));

    for( n = 0; n < 16; ++n   )
    {
        int b = rand()%255;
        switch( n   )
        {
            case 6:
            sprintf(p, "4%x", b%15 );
            break;
            case 8:
            sprintf(p, "%c%x", c[rand()%strlen(c)], b%15 );
            break;
            default:
            sprintf(p, "%02x", b);
            break;
        }

        p += 2;
        switch( n  )
        {
            case 3:
            case 5:
            case 7:
            case 9:
            *p++ = '-';
            break;
        }
    }
    *p = 0;
    return buf;
}

static char byteMap[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'  };
static int byteMapLen = sizeof(byteMap);

/* Utility function to convert nibbles (4 bit values) into a hex character representation */
static char
nibbleToChar(uint8_t nibble)
{
    if(nibble < byteMapLen) return byteMap[nibble];
    return '*';
}

/* Convert a buffer of binary values into a hex string representation */
char* bytesToHexString(uint8_t *bytes, size_t buflen)
{
    char *retval;
    int i;

    retval = malloc(buflen*2 + 1);
    for(i=0; i<buflen; i++) {
        retval[i*2] = nibbleToChar(bytes[i] >> 4);
        retval[i*2+1] = nibbleToChar(bytes[i] & 0x0f);
    }
    retval[i*2] = '\0';
    return retval;
}

extern void set_hide_mode(unsigned char mod);

static void receive_call_result_data(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr *tb[__INIT_MAX];
	char *token, *ssid, *ssid_pwd;
	int len, ret;

	if (!msg)
		return;

	ret = 0;

	blobmsg_parse(init_policy, __INIT_MAX, tb,
			blob_data(msg), blob_len(msg));

	if(tb[INIT_TOKEN] && tb[INIT_SSID] && tb[INIT_SSID_PWD]){
		token    = blobmsg_data(tb[INIT_TOKEN]);
		ssid     = blobmsg_data(tb[INIT_SSID]);
		ssid_pwd = blobmsg_data(tb[INIT_SSID_PWD]);
		// todo
		dlog("recv token[%s], ssid[%s] ssid_pwd[%s]\n",
			token, ssid, ssid_pwd);
		// printf("recv token[%s], ssid[%s] ssid_pwd[%s]\n", token, ssid, ssid_pwd);

        char *base64 = malloc(MAX_ALLOC_LEN);
        char *router_key_iv = malloc(MAX_ALLOC_LEN);
        char *r_ssid = malloc(MAX_ALLOC_LEN);
        char *r_pwd = malloc(MAX_ALLOC_LEN);

        char base64_ssid[MAX_ALLOC_LEN] = {0};
        char base64_pwd[MAX_ALLOC_LEN] = {0};

        // get router key, iv
        memset(base64, 0, MAX_ALLOC_LEN);
        int base64_length = base64Decode(base64, token, strlen(token));
        // printf("json base64 len: %d\n", base64_length);

        AES128_CBC_decrypt_buffer(router_key_iv, base64, base64_length, repeater_key, repeater_iv);
        memcpy(router_key, router_key_iv, 16);
        memcpy(router_iv, router_key_iv+16, 16);

        // ssid
        memset(base64_ssid, 0, MAX_ALLOC_LEN);
        memset(r_ssid, 0, MAX_ALLOC_LEN);
        memset(rr_ssid, 0, MAX_ALLOC_LEN);
        base64_length = base64Decode(base64_ssid, ssid, strlen(ssid));
        AES128_CBC_decrypt_buffer(r_ssid, base64_ssid, base64_length, router_key, router_iv);
        memcpy(rr_ssid, r_ssid, strlen(r_ssid));
        // printf("rr_ssid:%s\n", rr_ssid);

        // ssid pwd
        memset(base64_pwd, 0, MAX_ALLOC_LEN);
        memset(r_pwd, 0, MAX_ALLOC_LEN);
        memset(rr_pwd, 0, MAX_ALLOC_LEN);
        base64_length = base64Decode(base64_pwd, ssid_pwd, strlen(ssid_pwd));
        AES128_CBC_decrypt_buffer(r_pwd, base64_pwd, base64_length, router_key, router_iv);
        memcpy(rr_pwd, r_pwd, strlen(r_pwd));
        // printf("rr_pwd:%s\n", rr_pwd);

        flag_ssid_pwd = 1;
	/* Succeed to get password and ssid, so clear hide_mode flag */
	set_hide_mode(0);

        if (router_key_iv)
            free(router_key_iv);
        if (base64)
            free(base64);
        if (r_ssid)
            free(r_ssid);
        if (r_pwd)
            free(r_pwd);
	}else{
		dlog("recv DATA INVALID\n");
		ret = 1;
	}

	if (ret){
        printf("ecos pair verify failed!\n");
		dlog("ret:%d wait %d try again\n", ret,
				TRAFFICD_INIT_LOOP_TIME / 1000);
		uloop_timeout_set(&sd->timeout_init, TRAFFICD_INIT_LOOP_TIME);
	}else{
	printf("ssid:%s\n", rr_ssid);
        printf("ecos pair verify ok!\n");
#ifdef __ECOS
        #if 0
		CFG_set(CFG_TRAFFIC_INIT, 0);
		sys->init_mode = 0;
		uloop_timeout_set(&sd->timeout_mat, TRAFFICD_WIFIAP_LOOP_TIME);
        #endif
#endif
	}
}

static void init_loop_cb(struct uloop_timeout *timeout)
{
	uint32_t id;
	// replace *d
    char key_iv[32] = {0};

    char repeater_pubkey[] = "-----BEGIN PUBLIC KEY-----\n"\
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyUF9+Td53E0lEqP8eRyM\n"\
            "DoREPIety4BJscApuPwcGxiVA+75mYw8AFKlTaWlLL7w/qyuxnOiNm6TTFCxJGI1\n"\
            "C9GnABm8myC5hnDSC6qE+E1Al6wZgyI4rkC+Qr7GFI9B8r9bM+RdKyMxD9JuXUcx\n"\
            "+rx/TPnJttUfAkCloYStd5LiCel6c/bfWiR5hyxLjXC5Cz5cdpzXwvyvgEBvZHxX\n"\
            "A5jqPVfWcJ3P3s88ogPxx52iM4dzLtzWB6BOmZA/3SbvZle2Efy7mVAl/9gkwvgf\n"\
            "Dm/TSnMbnUBim3H5CIlECsvs2RuvI5og0S3oEO4B8TQQjujSqbA6h+EcZc9Djmh2\n"\
            "vQIDAQAB\n"\
            "-----END PUBLIC KEY-----\n";

    unsigned char  *encrypted=malloc(MAX_ALLOC_LEN);
    unsigned char  *base64=malloc(MAX_ALLOC_LEN);
    RAND_seed(rnd_seed, sizeof rnd_seed);       /* or RSA_PKCS1_PADDING/OAEP may fail */

    random_uuid(repeater_key);
    random_uuid(repeater_iv);

    memcpy(key_iv, repeater_key, 16);
    memcpy(key_iv+16, repeater_iv, 16);

    int encrypted_length= public_encrypt(key_iv,
                                         32,
                                         repeater_pubkey,
                                         encrypted);
    if(encrypted_length == -1)
    {
        printLastError("Public Encrypt failed ");
        exit(0);
    }
    printf("Encrypted length =%d\n",encrypted_length);
    printf("Try to init_loop_cb...\n");

    int base64_length = base64Encode(base64, encrypted, encrypted_length);
    // printf("base64 len: %d\n", base64_length);
    // printf("base64: %s\n", base64);

	if(ubus_lookup_id(sys->tbus_ctx, "netapi", &id)){
		dlog("can't lookup netapi\n");
		goto fail;
	}

	blob_buf_init(&traffic_b, 0);
	blobmsg_add_field(&traffic_b, BLOBMSG_TYPE_UNSPEC,
			"data", base64, base64_length);
	ubus_invoke(sys->tbus_ctx, id, "init", traffic_b.head,
			receive_call_result_data, NULL, TRAFFICD_INIT_TIMEOUT);

    free(encrypted);
    free(base64);
	return;

fail:
    free(encrypted);
    free(base64);
	uloop_timeout_set(&sd->timeout_init, TRAFFICD_INIT_LOOP_TIME);
}

static void reset_arp_table(void)
{
	arp->idx = 0;
}

static int resize_arp_table(){
	struct arp_table *_arp;
	int size;
	size = arp->size * 2;
	_arp = realloc(arp, sizeof(struct arp_table) +
			size * sizeof(struct _arp_entry));
	if(!_arp){
		elog("realloc fail\n");
		return 1;
	}
	arp = _arp;
	arp->size = size;
	return 0;
}
static int push_arp(char *hw, __be32 ip)
{
	dlog("hw:%s, ip:%x", hw, ip);
	if(arp->idx == arp->size){
		if(resize_arp_table())
			return 1;
	}
	//push
	arp->arps[arp->idx].ip = ip;
	strncpy(arp->arps[arp->idx].hw, hw, HWAMAXLEN);
	arp->idx += 1;
	return 0;
}

static int update_arp(char *hw, __be32 ip)
{
	int i;
	int found = 0;
	dlog("hw:%s, ip:%x", hw, ip);
	for(i = 0; i < arp->idx; i++){
		if(strcmp(arp->arps[i].hw, hw) == 0){
			found = 1;
			if(arp->arps[i].ip)
				continue;
			arp->arps[i].ip = ip;
			return 0;
		}
	}
	if(found){
		if(arp->idx == arp->size){
			if(resize_arp_table())
				return 1;
		}
		arp->arps[arp->idx].ip = ip;
		strncpy(arp->arps[arp->idx].hw, hw, HWAMAXLEN);
		arp->idx += 1;
	}
	return 1;
}

static void refresh_arp_table(void)
{
#ifdef __ECOS
	int idx = 0;
	struct iwreq iwr;
	RT_802_11_MAC_TABLE MacTab;
	struct eth_drv_sc       *sc;
	cyg_netdevtab_entry_t   *t;
	int found = 0;
	char hw[HWAMAXLEN];

	memset(&iwr, 0, sizeof(iwr));
	memset(&MacTab, 0, sizeof(RT_802_11_MAC_TABLE));
	iwr.u.data.pointer = (caddr_t) &MacTab;
    for (t = &__NETDEVTAB__[0]; t != &__NETDEVTAB_END__; t++) {
        sc = (struct eth_drv_sc *)t->device_instance;
        if (strcmp(sc->dev_name, TRAFFICD_IF_AP) == 0) {
            found = 1;
            break;
        }
    }

    if (found == 1) {
        if(rt28xx_ap_ioctl(sc, RTPRIV_IOCTL_GET_MAC_TABLE,
					(caddr_t)&iwr) < 0) {
            elog("RTPRIV_IOCTL_GET_MAC_TABLE sock fail!!\n");
			arp->size = 0;
            return;
        }
    } else {
		arp->size = 0;
        return;
    }

	reset_arp_table();
	for (idx = 0; idx < MacTab.Num; idx++){
		if(MacTab.Entry[idx].TxRate.field.MODE >= 2){
			snprintf((char *)hw, HWAMAXLEN, "%02X:%02X:%02X:%02X:%02X:%02X",
				MacTab.Entry[idx].Addr[0], MacTab.Entry[idx].Addr[1],
				MacTab.Entry[idx].Addr[2], MacTab.Entry[idx].Addr[3],
				MacTab.Entry[idx].Addr[4], MacTab.Entry[idx].Addr[5]);
			push_arp(hw, 0);
		}
	}
#endif
}

static void mat_loop_cb(struct uloop_timeout *timeout)
{
	void *c, *t;
	char buf[16];
	int i;

	if(sys->tbus_ctx->sock.fd >= 0){
		refresh_arp_table();
		update_mat_table();

		blob_buf_init(&traffic_b, 0);
		blobmsg_add_string(&traffic_b, "hw", sys->ap_hw);
		c = blobmsg_open_array(&traffic_b, "mat");

		for (i = 0; i < arp->idx; i++) {
			t = blobmsg_open_table(&traffic_b, "arp");
			blobmsg_add_string(&traffic_b, "sta", arp->arps[i].hw);
			if(arp->arps[i].ip){
				sprintf(buf, "%u.%u.%u.%u", NIPQUAD(arp->arps[i].ip));
				blobmsg_add_string(&traffic_b, "ip", buf);
			}
			blobmsg_close_table(&traffic_b, t);
		}

		blobmsg_close_array(&traffic_b, c);
		ubus_send_event(sys->tbus_ctx, sys->cfg.tbus_listen_event, traffic_b.head);
		D(SYSTEM, "send msg and wait %d(s)\n", TRAFFICD_WIFIAP_LOOP_TIME / 1000);
	}else{
		D(SYSTEM, "ctx->sock.fd[%d]\n", sys->tbus_ctx->sock.fd);
	}
	uloop_timeout_set(timeout, TRAFFICD_WIFIAP_LOOP_TIME);
}

#ifdef __ECOS

static void mat_callback(IPMacMappingEntry *pHead){
	char hw[HWAMAXLEN];

/*
	D(SYSTEM, "\t:IP=0x%x,Mac=%02x:%02x:%02x:%02x:%02x:%02x, lastTime=0x%lx, next=%p\n",
		pHead->ipAddr, pHead->macAddr[0],pHead->macAddr[1],pHead->macAddr[2],
		pHead->macAddr[3],pHead->macAddr[4],pHead->macAddr[5], pHead->lastTime,
		pHead->pNext);
*/
	snprintf((char *)hw, HWAMAXLEN, "%02X:%02X:%02X:%02X:%02X:%02X",
		pHead->macAddr[0],pHead->macAddr[1],pHead->macAddr[2],
		pHead->macAddr[3],pHead->macAddr[4],pHead->macAddr[5]);

	D(SYSTEM, "ip:%u.%u.%u.%u mac:%s\n", NIPQUAD(pHead->ipAddr),hw);
	update_arp(hw, pHead->ipAddr);
}




static void update_mat_table(void)
{
	struct eth_drv_sc *sc = NULL;
	cyg_netdevtab_entry_t *t;

	for (t = &__NETDEVTAB__[0]; t != &__NETDEVTAB_END__; t++){
		sc = (struct eth_drv_sc *)t->device_instance;
		if (strcmp(sc->dev_name, TRAFFICD_IF_AP) == 0){
			break;
		}
	}

	if(sc){
		struct iwreq iwr;
		int status;
		memset(&iwr, 0, sizeof(iwr));
		iwr.u.data.pointer = (caddr_t) mat_callback;
		iwr.u.data.flags = RTPRIV_IOCTL_MAT_CALLBACK;
		iwr.u.data.flags |= OID_GET_SET_TOGGLE;
		iwr.u.data.length = sizeof(caddr_t);
		status = rt28xx_ap_ioctl(sc, RTPRIV_IOCTL_MAT_CALLBACK, (caddr_t)&iwr);
		dlog("set mat_callback [%d]\n", status);
	}


#if 0
	char line[200], ip[100], hw[100];
	int num;
	struct hw_node *hw_node;
	struct ip_node *ip_node;
	FILE *fp;


	/* Open the PROCps kernel table. */
	if ((fp = fopen(PROC_MAT_TABLE_FILE, "r")) == NULL) {
		D(SYSTEM, "fopen %s error\n", PROC_MAT_TABLE_FILE);
		return;
	}

	for (; fgets(line, sizeof(line), fp);) {
		num = sscanf(line, "%100s %100s\n",
				ip, hw);
		if (num < 2)
			break;
		upper_nstring(hw, HWAMAXLEN);

		hw_node = trafficd_hw_get(hw, true);
		ip_node = trafficd_ip_get(ip, true);
		if(hw_node && ip_node &&
				ip_node->hw != hw_node){
			ip_node->hw = hw_node;
			list_del(&ip_node->list);
			list_add(&ip_node->list, &hw_node->ip_list);
		}
	}
	fclose(fp);
#endif
}


#ifdef DEMO
void system_get_apcli0_ip(void){
    _show_all_interfaces();

    //ifconfig apcli0
    show_network_interface(&printf, argv[0]);
    // show route
    show_network_tables(&printf);
}


void system_get_mattab(void){

}

#endif


void system_show_assoclist(void)
{
	int idx = 0;
	struct iwreq iwr;
	RT_802_11_MAC_TABLE MacTab;
	struct eth_drv_sc       *sc;
	cyg_netdevtab_entry_t   *t;
	int found = 0;

	memset(&iwr, 0, sizeof(iwr));
	memset(&MacTab, 0, sizeof(RT_802_11_MAC_TABLE));
	iwr.u.data.pointer = (caddr_t) &MacTab;
    for (t = &__NETDEVTAB__[0]; t != &__NETDEVTAB_END__; t++) {
        sc = (struct eth_drv_sc *)t->device_instance;
        if (strcmp(sc->dev_name, TRAFFICD_IF_AP) == 0) {
            found = 1;
            break;
        }
    }

    if (found == 1) {
        if(rt28xx_ap_ioctl(sc, RTPRIV_IOCTL_GET_MAC_TABLE, (caddr_t)&iwr) < 0) {
            dlog("RTPRIV_IOCTL_GET_MAC_TABLE sock fail!!\n");
            return;
        }
    } else {
        return;
    }

	for (idx = 0; idx < MacTab.Num; idx++){
		if(MacTab.Entry[idx].TxRate.field.MODE >= 2){
			D(SYSTEM, "%02X:%02X:%02X:%02X:%02X:%02X",
				MacTab.Entry[idx].Addr[0], MacTab.Entry[idx].Addr[1],
				MacTab.Entry[idx].Addr[2], MacTab.Entry[idx].Addr[3],
				MacTab.Entry[idx].Addr[4], MacTab.Entry[idx].Addr[5]);
		}
	}
}

#if 0
char const *pWirelessSysEventText[IW_SYS_EVENT_TYPE_NUM] = {
    "had associated successfully",                          /* IW_ASSOC_EVENT_FLAG */
    "had disassociated",                                    /* IW_DISASSOC_EVENT_FLAG */
    "had deauthenticated",                                  /* IW_DEAUTH_EVENT_FLAG */
    "had been aged-out and disassociated",                  /* IW_AGEOUT_EVENT_FLAG */
    "occurred CounterMeasures attack",                      /* IW_COUNTER_MEASURES_EVENT_FLAG */
    "occurred replay counter different in Key Handshaking", /* IW_REPLAY_COUNTER_DIFF_EVENT_FLAG */
    "occurred RSNIE different in Key Handshaking",          /* IW_RSNIE_DIFF_EVENT_FLAG */
    "occurred MIC different in Key Handshaking",            /* IW_MIC_DIFF_EVENT_FLAG */
    "occurred ICV error in RX",                             /* IW_ICV_ERROR_EVENT_FLAG */
    "occurred MIC error in RX",                             /* IW_MIC_ERROR_EVENT_FLAG */
    "Group Key Handshaking timeout",                        /* IW_GROUP_HS_TIMEOUT_EVENT_FLAG */
    "Pairwise Key Handshaking timeout",                     /* IW_PAIRWISE_HS_TIMEOUT_EVENT_FLAG */
    "RSN IE sanity check failure",                          /* IW_RSNIE_SANITY_FAIL_EVENT_FLAG */
    "set key done in WPA/WPAPSK",                           /* IW_SET_KEY_DONE_WPA1_EVENT_FLAG */
    "set key done in WPA2/WPA2PSK",                         /* IW_SET_KEY_DONE_WPA2_EVENT_FLAG */
    "connects with our wireless client",                    /* IW_STA_LINKUP_EVENT_FLAG */
    "disconnects with our wireless client",                 /* IW_STA_LINKDOWN_EVENT_FLAG */
    "scan completed",                                       /* IW_SCAN_COMPLETED_EVENT_FLAG */
    "scan terminate!! Busy!! Enqueue fail!!",               /* IW_SCAN_ENQUEUE_FAIL_EVENT_FLAG */
    "channel switch to ",                                   /* IW_CHANNEL_CHANGE_EVENT_FLAG */
    "wireless mode is not support",                         /* IW_STA_MODE_EVENT_FLAG */
    "blacklisted in MAC filter list",                       /* IW_MAC_FILTER_LIST_EVENT_FLAG */
    "Authentication rejected because of challenge failure", /* IW_AUTH_REJECT_CHALLENGE_FAILURE */
    "Scanning",                                             /* IW_SCANNING_EVENT_FLAG */
    "Start a new IBSS",                                     /* IW_START_IBSS_FLAG */
    "Join the IBSS",                                        /* IW_JOIN_IBSS_FLAG */
    "Shared WEP fail",                                      /* IW_SHARED_WEP_FAIL*/
    };
#endif

static int iw_callback(char *data, uint32_t len)
{
	/*
	len:59, data:(RT2860) STA(8c:be:be:73:4c:35) had associated successfully
	len:60, data:(RT2860) STA(8c:be:be:73:4c:35) set key done in WPA2/WPA2PSK
	*/
	if (data == NULL){
		perror("iw_callback(data == NULL)");
		return -1;
	}
	D(SYSTEM, "len:%d, data:%s\n", len, data);

	return 0;
}

int system_init()
{
	struct eth_drv_sc *sc = NULL;
	cyg_netdevtab_entry_t *t;

	if(!sys->cfg.is_router && sys->tbus_ctx){
		sd = calloc(1, sizeof(* sd));
		if (!sd){
			elog("calloc failed\n");
			return -1;
		}

		arp = calloc(1, sizeof(struct arp_table) +
				ARP_DEFAULT_SIZE * sizeof(struct _arp_entry));
		if(!arp){
			elog("calloc failed\n");
			return -1;
		}
		arp->size = ARP_DEFAULT_SIZE;

		dlog("set timeout_init\n");
		sd->timeout_init.cb = init_loop_cb;
		dlog("set timeout_mat\n");
		sd->timeout_mat.cb = mat_loop_cb;
		if(sys->init_mode){
			uloop_timeout_set(&sd->timeout_init, TRAFFICD_INIT_LOOP_TIME);
		}else{
			uloop_timeout_set(&sd->timeout_mat, TRAFFICD_WIFIAP_LOOP_TIME);
		}
	}

	for (t = &__NETDEVTAB__[0]; t != &__NETDEVTAB_END__; t++){
		sc = (struct eth_drv_sc *)t->device_instance;
		if (strcmp(sc->dev_name, TRAFFICD_IF_AP) == 0){
			break;
		}
	}

	if(sc){
		struct iwreq iwr;
		int status;
		memset(&iwr, 0, sizeof(iwr));
		iwr.u.data.pointer = (caddr_t) iw_callback;
		iwr.u.data.flags = RTPRIV_IOCTL_IW_CALLBACK;
		iwr.u.data.flags |= OID_GET_SET_TOGGLE;
		iwr.u.data.length = sizeof(caddr_t);
		status = rt28xx_ap_ioctl(sc, RTPRIV_IOCTL_IW_CALLBACK, (caddr_t)&iwr);
		dlog("!!Set callback for 2.4G device[%d]\n", status);
	}

	return 0;
}

int system_done(void){
	return 0;
}

void system_dump(void){
	char *buffer = NULL;

	//get wan gw
	buffer =  NSTR(primary_wan_ip_set[0].gw_ip);
	D(SYSTEM, "get apcli0 gw [%s]\n", buffer);

	//get wan ip
	buffer =  NSTR(primary_wan_ip_set[0].ip);
	D(SYSTEM, "get apcli0 ip [%s]\n", buffer);

	//get wan mac
	buffer = ESTR(SYS_wan_mac);
	D(SYSTEM, "get apcli0 mac [%s]\n", buffer);

	update_mat_table();

	system_show_assoclist();

}
#else

int system_init()
{

	if(!sys->cfg.is_router && sys->tbus_ctx){
		sd = calloc(1, sizeof(* sd));
		if (!sd)
			return -1;

		dlog("set timeout_init\n");
		sd->timeout_init.cb = init_loop_cb;
		dlog("set timeout_mat\n");
		sd->timeout_mat.cb = mat_loop_cb;
		if(sys->init_mode){
			uloop_timeout_set(&sd->timeout_init, TRAFFICD_INIT_LOOP_TIME);
		}else{
			uloop_timeout_set(&sd->timeout_mat, TRAFFICD_WIFIAP_LOOP_TIME);
		}
	}
	return 0;
}

static void update_mat_table(void)
{
}

int system_done(void){
	return 0;
}

void system_show_assoclist(void){

}

void system_dump(){

}

#endif
