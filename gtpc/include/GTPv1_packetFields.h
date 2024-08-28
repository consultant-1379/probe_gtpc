
//the bitfield for the MNC as per GTPv1
#ifndef GTPv1_packetFields
#define GTPv1_packetFields


//#pragma pack(1) //vital to get bit fields to line up correctly
#include <pcap.h>
#include "gtpv1_utils.h"
#include <netinet/in.h>
#include <string.h>
#include <strings.h>
#include <string>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <unordered_map>
using std::string;
using std::cout;
using std::ostream;
using std::endl;
using std::hash;

//using std::precision;

// esirich: DEFTFTS-1825
// include the lengths of the character buffers
#include "gtp_ie.h"



extern std::ofstream f_out;


class GTPPorts{
public:
enum PortNumbers{GTP_CONTROL_PORT = 2123};
};

class IPVersion{
public:
	enum{IPV4 =  4};
};

class GTPMessageTypes{
public:
	enum {ECHO_REQUEST= 1,
		ECHO_RESPONSE = 2,
		VERSION_NOT_SUPPORTED = 3,
		SEND_ROUTING_FOR_QPRS_REQUEST =32,
		SEND_ROUTING_FOR_QPRS_RESPONSE = 33,
		CREATE_PDP_CONTEXT_REQUEST=0X10,
		CREATE_PDP_CONTEXT_RESPONSE =0X11,
		UPDATE_PDP_CONTEXT_REQUEST = 0X12,
		UPDATE_PDP_CONTEXT_RESPONSE= 0x13,
		DELETE_PDP_CONTEXT_REQUEST = 0x14,
		DELETE_PDP_CONTEXT_RESPONSE= 0x15
	};
};

struct FTEID {

	unsigned int addr;
	unsigned int teid;
	double time; // creation time

	FTEID() {
		addr = 0;
		teid = 0;
		time = -1;
	}

};


struct PDPSession {
	double startTime;

	double touch;  // last activity on this session of any kind

	double time_pdn_response;
	double time_update_request;
	double time_update_response;

	double active_update_start;

   char imsi[IMSI_MAX_CHARS];
   char imei[IMEI_MAX_CHARS];   

	struct FTEID sgsn;
	struct FTEID ggsn_c, ggsn_d;
	struct FTEID dle; // downlink endpoint (rnc or sgsn)

	string apn;
    char msisdn[MSISDN_MAX_CHARS];
	unsigned int ue_addr;
	int nsapi;

	string pdp_type; //primary or secondary
	string rat; //GSM, ...

	int dtflag;

    char mnc[MNC_MAX_CHARS];
    char mcc[MCC_MAX_CHARS];
    int lac, rac;
    int cid, sac;

	int pdn_cause;
	unsigned char update_cause;

	int arp, delay_class, reliability_class, precedence;
	string traffic_class;
	int thp;

	int max_ul, max_dl;
	int gbr_ul, gbr_dl;

	int sdu;
	static int instanceCounter;
	static int deleteCounter;

	void init() {
		time_pdn_response=0;
		time_update_request=0;
		time_update_response=0;
		active_update_start=0;
		bzero(imsi, IMSI_MAX_CHARS);
		strcpy(imsi, IMSI_INIT_STRING);
		pdn_cause=-1;
		update_cause=0;
		bzero(msisdn, MSISDN_MAX_CHARS);
		strcpy(msisdn, MSISDN_INIT_STRING);
		pdp_type = "unknown";
		rat = "";
		traffic_class = "";
		nsapi = -1;
		bzero(imei, IMEI_MAX_CHARS);
		strcpy(imei, IMEI_INIT_STRING);
		ue_addr = 0;
		sdu=-1;
		max_ul = max_dl = gbr_ul = gbr_dl = -1;
		thp = arp = delay_class = reliability_class = precedence = -1;
		bzero(mcc, MCC_MAX_CHARS);
		strcpy(mcc, MCC_INIT_STRING);
		bzero(mnc, MNC_MAX_CHARS);
		strcpy(mnc, MNC_INIT_STRING);
		lac=rac=cid=sac=-1;
		dtflag=0;
	}

	PDPSession(char *imsi_init) {
		init();
		strncpy(imsi, imsi_init, IMSI_MAX_CHARS);
		instanceCounter++;
	}

	~PDPSession(){
		instanceCounter--;
		deleteCounter++;
	}

	static int getInstanceCounter(){
		return instanceCounter;
	}
	static int getDeleteCounter(){
		return deleteCounter;
	}

	void print() {

		unsigned char* psgsnaddr=(unsigned char*)&(sgsn.addr);
		unsigned char* pggsncaddr=(unsigned char*)&(ggsn_c.addr);
		unsigned char* pggsndaddr=(unsigned char*)&(ggsn_d.addr);
		unsigned char* pdleaddr=(unsigned char*)&(dle.addr);
		unsigned char* pueaddr=(unsigned char*)&(ue_addr);

		printf("\nPDPSESSSION_PRINT********************************************************\n");
		printf("XXX start %f imsi %llu msisdn %llu sgsn %i.%i.%i.%i %0x ggsn_c %i.%i.%i.%i %0x ggsn_d %i.%i.%i.%i %0x dle %i.%i.%i.%i %0x apn %s ue_addr %i.%i.%i.%i nsapi %i\n",
				startTime, imsi, msisdn,
				psgsnaddr[3], psgsnaddr[2], psgsnaddr[1], psgsnaddr[0], sgsn.teid,
				pggsncaddr[3], pggsncaddr[2], pggsncaddr[1], pggsncaddr[0], ggsn_c.teid,
				pggsndaddr[3], pggsndaddr[2], pggsndaddr[1], pggsndaddr[0], ggsn_d.teid,
				pdleaddr[3], pdleaddr[2], pdleaddr[1], pdleaddr[0], dle.teid,
				apn.c_str(),
				pueaddr[3], pueaddr[2], pueaddr[1], pueaddr[0],
				nsapi);
		printf("\n*************************************************************************\n");

	}
	void printUpdate();
	void printPDPSession();

};

struct hash_long_long {
	size_t operator()(const long long in)  const {
		long long ret = (in >> 32L) ^ hash<int>()(in & 0xFFFFFFFF);
		return (size_t) ret;
	}
};

struct MNCBCDDigits{
	unsigned char:4;
	unsigned char Hundreds:4;
	unsigned char Tens:4;
	unsigned char Units:4;
};


//the bitfield for the MCC as per GTPv1
struct MCCBCDDigits{
	unsigned char Hundreds:4;
	unsigned char Tens:4;
	unsigned char Units:4;
};

struct GTP_Control_Full_Header{
	unsigned char N_PDUNumberFlag:1;
	unsigned char SequenceNumberFlag:1;
	unsigned char ExtensionHeaderFlag:1;
	unsigned char Reserved:1;
	unsigned char ProtocolType:1;
	unsigned char Version:3;

	unsigned char MessageType:8;

	unsigned short TotalLength:16;

	unsigned int TunnelEndpointIdentifier :32;

	unsigned short SequenceNumber:16;
	unsigned char N_PDUNumber:8;
	unsigned char NextExtensionHeaderType:8;

};

struct GTP_Control_Basic_Header{
	unsigned char N_PDUNumberFlag:1;
	unsigned char SequenceNumberFlag:1;
	unsigned char ExtensionHeaderFlag:1;
	unsigned char Reserved:1;
	unsigned char ProtocolType:1;
	unsigned char Version:3;

	unsigned char MessageType:8;

	unsigned short TotalLength:16;

	unsigned int TunnelEndpointIdentifier :32;

};


union GTP_Control_Header{
	GTP_Control_Basic_Header basicHeader;
	GTP_Control_Full_Header fullHeader;
};

struct LinuxCookedHeader{
	u_short incoming:16;
	u_short ARPHPD_:16;
	u_short loopback:16;
	u_short llaAddressType:16;
	u_short llaAddress[4];

};

struct my_ip {
	u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* type of service */
	u_int16_t	ip_len;		/* total length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_int8_t	ip_ttl;		/* time to live */
	u_int8_t	ip_p;		/* protocol */
	u_int16_t	ip_sum;		/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};


void decodeMNC(unsigned char *p, char *mnc);
void decodeMCC(unsigned char *p, char *mcc);
unsigned long long parseIMSI_IMEI_Field(unsigned char *p, int pos);
unsigned int extractIpAddress(unsigned char* p);
unsigned short extractPortFromPacket(unsigned char* p);



#endif

