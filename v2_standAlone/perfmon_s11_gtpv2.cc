//#include "stdio.h"

#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> /* if this gives you an error try pcap/pcap.h */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <string>
#include <ext/hash_map>
#include <time.h>
#include <vector>

#include "gtp_ie_gtpv2.h"

using namespace std;
using namespace __gnu_cxx;

FILE *file_pdn=NULL;
FILE *file_eps=NULL;
FILE *file_tun=NULL;
int records_written=0;

int session_id_c=0;

int num_create_session_response_notfound=0;
int num_modify_request_notfound=0;
int num_modify_response_notfound=0;
int num_notification_notfound=0;
int num_notification_ack_notfound=0;

int num_create_session_response=0;
int num_modify_request=0;
int num_modify_response=0;
int num_notification=0;
int num_notification_ack=0;


void printaddr(int a) {
	unsigned char* i=(unsigned char*)&(a);

	printf("%i.%i.%i.%i", i[3],i[2],i[1],i[0]);
}

struct dataeq {   
	size_t operator()(const FTEID& x) const
	{
		return __gnu_cxx::hash< u_int32_t >()((u_int32_t)x.addr ^ (u_int32_t)x.teid);
	};

	bool operator() (const FTEID f1, const FTEID f2) const {
		return (f1.addr==f2.addr)&&(f1.teid==f2.teid);
	};
};

struct PDNSession {
	double start;

	double touch;  // last activity on this session of any kind

	int session_id;

	double time_pdn_response;
	double time_update_request;
	double time_update_response;

	double paging_start;

	double active_update_start;

	unsigned long long imsi;

	struct FTEID mme;
	struct FTEID sgw_c, sgw_d;
	struct FTEID enb;

	char apn[100];
	unsigned long long msisdn;
	unsigned int ue_addr;
	int default_bearer_id;

	unsigned char pdn_cause;
	unsigned char update_cause;

	int default_bearer_established;

	int sreq_flag;
	int paging_flag;

	PDNSession() {

		session_id = session_id_c;
		session_id_c ++;

		paging_start=0;
		touch=0;

		time_pdn_response=0;
		time_update_request=0;
		time_update_response=0;
		active_update_start=0;
		imsi=0;
		pdn_cause=0;
		update_cause=0;
		msisdn=0;
		ue_addr=0;
		default_bearer_id=255;

		default_bearer_established=0;

		sreq_flag = paging_flag = 0;
	}




	void print() {

		unsigned char* pmmeaddr=(unsigned char*)&(mme.addr);
		unsigned char* psgwcaddr=(unsigned char*)&(sgw_c.addr);
		unsigned char* psgwdaddr=(unsigned char*)&(sgw_d.addr);
		unsigned char* penbaddr=(unsigned char*)&(enb.addr);
		unsigned char* pueaddr=(unsigned char*)&(ue_addr);

		printf("\nPDNSESSSION (ID=%i) ********************************************************\n", session_id);
		printf("XXX start %f imsi %llu msisdn %llu mme %i.%i.%i.%i %0x sgw_c %i.%i.%i.%i %0x sgw_d %i.%i.%i.%i %0x enb %i.%i.%i.%i %0x apn %s ue_addr %i.%i.%i.%i default_bearer_id %i\n",
				start, imsi, msisdn,
				pmmeaddr[3], pmmeaddr[2], pmmeaddr[1], pmmeaddr[0], mme.teid,
				psgwcaddr[3], psgwcaddr[2], psgwcaddr[1], psgwcaddr[0], sgw_c.teid,
				psgwdaddr[3], psgwdaddr[2], psgwdaddr[1], psgwdaddr[0], sgw_d.teid,
				penbaddr[3], penbaddr[2], penbaddr[1], penbaddr[0], enb.teid,
				apn,
				pueaddr[3], pueaddr[2], pueaddr[1], pueaddr[0],
				default_bearer_id);
		printf("\n*************************************************************************\n");

	};

	void printPDNSession() {

		unsigned char* pueaddr=(unsigned char*)&(ue_addr);

		records_written++;

		/*
      printf("PDNSession start %f end - time_pdn_response %f time_update_request %f time_update_response %f pdn_cause %i update cause %i imsi %llu apn %s default_eps_bearer_id %i ue_addr_ipv4 %i.%i.%i.%i ue_addr_ipv6 -\n", start, time_pdn_response,
		     time_update_request,
		     time_update_response,
		     pdn_cause,
		     update_cause,imsi, apn, nsapi, pueaddr[3], pueaddr[2], pueaddr[1], pueaddr[0]);
		 */

		// null is the end time and the ipv6 addr
		/*
      fprintf(file_pdn, "%f\t%f\t%f\t%f\t%i\t%i\t\\N\t%llu\t%s\t%i\t%i.%i.%i.%i\t\\N\n", 
      	             start, 
		     time_pdn_response,
		     time_update_request,
		     time_update_response,
		     pdn_cause,
		     update_cause,
		     imsi, 
		     apn, 
		     nsapi, 
		     pueaddr[3], pueaddr[2], pueaddr[1], pueaddr[0]);
		 */



		//      sprintf(buff, "insert into pdn_session.current values ( \
		//                     %f, %f, %f, %f, \
		//		     %i, %i, \
		//		     null, \
		//		     %llu, \
		//		     '%s', \
		//		     %i,\
		//		     '%i.%i.%i.%i'::inet,\
		//		     null \
		//	     )",
		//      	             start,
		//		     time_pdn_response,
		//		     time_update_request,
		//		     time_update_response,
		//		     pdn_cause,
		//		     update_cause,
		//		     imsi,
		//		     apn,
		//		     default_bearer_id,
		//		     pueaddr[3], pueaddr[2], pueaddr[1], pueaddr[0]);

		// printf("\n*************************************************************************\n");
		// printf(buff);

	}

	void printTunnelSession() {

		unsigned char* pmmeaddr=(unsigned char*)&(mme.addr);
		unsigned char* psgwcaddr=(unsigned char*)&(sgw_c.addr);
		unsigned char* psgwdaddr=(unsigned char*)&(sgw_d.addr);
		unsigned char* penbaddr=(unsigned char*)&(enb.addr);
		unsigned char* pueaddr=(unsigned char*)&(ue_addr);

		records_written++;


		//      sprintf(buff, "insert into tunnel_session.current values ( \
		//               %f, null, %llu, %i, '%s', \
		//	       '%i.%i.%i.%i'::inet,     \
		//	       '%i.%i.%i.%i'::inet, %u, \
		//	       '%i.%i.%i.%i'::inet, %u, \
		//	       '%i.%i.%i.%i'::inet, %u, \
		//	       '%i.%i.%i.%i'::inet, %u,  \
		//	       %i, %i \
		//      	             		    )",
		//      	       active_update_start, imsi, default_bearer_id, apn,
		//  	       pueaddr[3], pueaddr[2], pueaddr[1], pueaddr[0],
		//	       pmmeaddr[3], pmmeaddr[2], pmmeaddr[1], pmmeaddr[0], mme.teid,
		//	       psgwcaddr[3], psgwcaddr[2], psgwcaddr[1], psgwcaddr[0], sgw_c.teid,
		//	       psgwdaddr[3], psgwdaddr[2], psgwdaddr[1], psgwdaddr[0], sgw_d.teid,
		//	       penbaddr[3], penbaddr[2], penbaddr[1], penbaddr[0], enb.teid,
		//	       sreq_flag, paging_flag
		//	       );

		// printf("\n*************************************************************************\n");
		// printf(buff);



	}

	void CloseTunnelSession(DecodedMsg *pmsg) {

		//
		//      sprintf(buff,"update tunnel_session.all set duration = %f where imsi = %llu and start = %f",
		//      	             pmsg->timestamp - active_update_start,
		//		     imsi,
		//		     active_update_start);

		// printf("\n*************************************************************************\n");
		// printf(buff);


	}


	void printEPSBearerSession() {
		// printf("EPSBearerSession start %f end - imsi %llu linked_bearer_id %i qos -\n", start, imsi, nsapi);

		records_written++;

		/*
      fprintf(file_eps, "%f\t\\N\t%llu\t%i\t\\N\n", 
      	    start, 
	    imsi, 
	    nsapi); // qos is the last null
		 */

		//      PGresult *res;
		//      char buff[1000];
		//      sprintf(buff, "insert into epsbearer_session.current values (%f, NULL, %llu, %i)", start, imsi, default_bearer_id);
		//
		//      // printf("\n*************************************************************************\n");
		//      // printf(buff);
		//      res = InsertSQL(conn, buff, "epsbearer_session", start);

	}

};

hash_map<struct FTEID, struct PDNSession*, dataeq, dataeq> hmap_mme, hmap_sgw;
hash_map<struct FTEID, struct PDNSession*, dataeq, dataeq>::iterator it;


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


void EraseSession(PDNSession *s) {

	it = hmap_mme.find(s->mme);
	if(it != hmap_mme.end()) hmap_mme.erase(it);

	it = hmap_sgw.find(s->sgw_c);
	if(it != hmap_sgw.end()) hmap_sgw.erase(it);

	delete(s);

}

void CreateSessionRequest(unsigned char *p, int datalen, DecodedMsg *pmsg) {

	// printf("*****************************************************\n");
	// printf("XXX CreateSessionRequest\n");
	// printf("teid 0x%x\n", pmsg->teid);

	// if(pmsg->teid==0) printf("Primary\n");
	// else printf("Secondary\n");

	int pos=0;
	while(pos<datalen) {

		pos = DecodeIE(p, pos, datalen, pmsg);
		// printf("pos %i datalen %i\n");

	}

	FTEID mme;
	mme = pmsg->fteid[0];

	// GTPv2
	// teid is not set
	// IMSI, MSISDN
	// fteid[1] = MME GTP-C
	// fteid[2] = PGW?
	// ue_addr = PDN address (may be empty!)
	// apn
	// default EPS bearer QoS (not decoded)
	// ambr (not decoded)

	// create new hash entry

	it = hmap_mme.find(mme);
	if(it != hmap_mme.end()) {

		PDNSession *pdnSession = it->second;

		if(pmsg->timestamp - pdnSession->start < 10) {
			// printf("XXX Retransmitted CreateSessionRequest\n");

			pdnSession->touch = pmsg->timestamp;
			return;
		}

		// printf("XXX SessionConflict\n");

		EraseSession(it->second);
	}

	PDNSession *pdnSession = new PDNSession();

	hmap_mme[mme] = pdnSession;

	pdnSession->start = pmsg->timestamp;

	pdnSession->touch = pmsg->timestamp;


	pdnSession->imsi = pmsg->imsi;
	pdnSession->msisdn = pmsg->msisdn;

	strcpy(pdnSession->apn, pmsg->apn);

	pdnSession->mme = mme;

	pdnSession->default_bearer_id = pmsg->eps_bearer_id;

	// pdnSession->print();
	// printf("*****************************************************\n");


}

void CreateSessionResponse(unsigned char *p, int datalen, DecodedMsg *pmsg) {

	// printf("XXX CreateSessionResponse\n");
	// printf("teid 0x%x\n", pmsg->teid);

	int pos=0;
	while(pos<datalen) {

		// printf("pos %i datalen %i\n", pos, datalen);

		pos = DecodeIE(p, pos, datalen, pmsg);
	}

	// GTPv2:
	// teid = MME control teid


	FTEID mme;
	mme.addr = pmsg->dst_addr;
	mme.teid = pmsg->teid;

	num_create_session_response++;

	it = hmap_mme.find(mme);
	if(it == hmap_mme.end()) {
		// printf("XXX SESSION NOT FOUND+++++++++++++++++++++++++++++++++++\n");

		num_create_session_response_notfound++;

		// mme.print();
		return;
	}

	PDNSession *pdnSession = it->second;

	// printf("PDNSession_ID=%i\n", pdnSession->session_id);

	pdnSession->pdn_cause = pmsg->cause;

	pdnSession->touch = pmsg->timestamp;


	if(pmsg->cause != 16) {
		// printf("Request NOT accepted\n");

		// pdnSession->print();

		EraseSession(pdnSession);

		return;
	}


	pdnSession->sgw_c = pmsg->fteid[0];

	// store in second hash map the same pointer
	hmap_sgw[pdnSession->sgw_c] = pdnSession;

	int id = pdnSession->default_bearer_id;

	if(pmsg->bearer[0][id].present==1) {
		pdnSession->sgw_d = pmsg->bearer[0][id].fteid[0];

		// printf("sgw_d fteid: ");
		// pdnSession->sgw_d.print();
	}


	pdnSession->ue_addr = pmsg->ue_addr;

	pdnSession->time_pdn_response = pmsg->timestamp;

	if(pmsg->cause_present) pdnSession->pdn_cause = pmsg->cause;

	// pdnSession->print();
}

void ModifyBearerRequest(unsigned char *p, int datalen, DecodedMsg *pmsg) {

	// printf("XXX ModifyBearerRequest\n");
	// printf("teid 0x%x\n", pmsg->teid);

	int pos=0;
	while(pos<datalen) {

		pos = DecodeIE(p, pos, datalen, pmsg);
		// printf("pos %i datalen %i\n");

	}

	// FTEID mme = pmsg->fteid[0]; THIS PROBABLY DOES NOT EXIST IN ALL CASES

	FTEID sgw;
	sgw.addr = pmsg->dst_addr;
	sgw.teid = pmsg->teid;

	num_modify_request++;


	it = hmap_sgw.find(sgw);
	if(it == hmap_sgw.end()) {
		// printf("XXX SESSION NOT FOUND+++++++++++++++++++++++++++++++++++\n");

		num_modify_request_notfound++;

		// sgw.print();
		return;
	}

	PDNSession *pdnSession = it->second;

	// printf("PDNSession_ID=%i\n", pdnSession->session_id);

	pdnSession->touch = pmsg->timestamp;

	double delay = pmsg->timestamp - pdnSession->paging_start;

	// check if this is in response to dl  notification and dl_not_ack?
	if(pdnSession->paging_flag == 1 && delay < 300) {
		// printf("PAGING success delay %f\n",pmsg->timestamp - pdnSession->paging_start );

		pdnSession->paging_flag=1; // user to indicate that tunnel is due to pagign

		unsigned char* addr=(unsigned char*)&(pdnSession->mme.addr);

		// Successful paging goes into the paging table with cause code = 16 (success)
		//      sprintf(buff, "insert into paging.current values ( \
		//                     %f, %f, 16, \
		//		     %llu, \
		//		     '%i.%i.%i.%i'::inet,\
		//		     %u \
		//	     )",
		//      	             pdnSession->paging_start,
		//		     delay,
		//		     pdnSession->imsi,
		//		     addr[3], addr[2], addr[1], addr[0],
		//		     sgw.teid);

		// printf(buff);


		// pdnSession->paging_flag=0;

	}
	pdnSession->paging_start=0;


	if(pmsg->delay_value_present) {
		pdnSession -> sreq_flag = 1;
		// printf("This tunnel is a result of SREQ\n");
	} else pdnSession -> sreq_flag = 0;


	if(pdnSession->active_update_start>0) {
		// printf("CHANGE TUNNEL, CLOSE EARLIER");

		// pdnSession->print();

		pdnSession->CloseTunnelSession(pmsg);

	}


	int id = pdnSession->default_bearer_id;

	// printf("\nModifyBearer default_bearer=%i\n", id);
	if(id==-1) {
		printf("Bearer id should be set! SessionID=%i\n", pdnSession->session_id);
		exit(0);
	}

	if(pmsg->bearer[0][id].present==1) {
		pdnSession->enb = pmsg->bearer[0][id].fteid[0];

		// printf("enb fteid: ");
		// pdnSession->enb.print();
	}

	if(pdnSession->time_update_request==0) pdnSession->time_update_request = pmsg->timestamp;

	pdnSession->active_update_start = pmsg->timestamp;

	// pdnSession->print();

	// printf("XXX ModifyBearerRequest END\n");

}

void ModifyBearerResponse(unsigned char *p, int datalen, DecodedMsg *pmsg) {

	// printf("XXX ModifyBearerResponse\n");
	// printf("teid 0x%x\n", pmsg->teid);

	int pos=0;
	while(pos<datalen) {

		pos = DecodeIE(p, pos, datalen, pmsg);
		// printf("pos %i datalen %i\n");

	}

	num_modify_response++;


	FTEID mme;
	mme.addr = pmsg->dst_addr;
	mme.teid = pmsg->teid;

	it = hmap_mme.find(mme);
	if(it == hmap_mme.end()) {
		// printf("XXX SESSION NOT FOUND+++++++++++++++++++++++++++++++++++\n");

		num_modify_response_notfound++;

		// mme.print();
		return;
	}

	PDNSession *pdnSession = it->second;

	// printf("PDNSession_ID=%i\n", pdnSession->session_id);

	pdnSession->touch = pmsg->timestamp;


	pdnSession->time_update_response = pmsg->timestamp;
	if(pmsg->cause_present) pdnSession->update_cause = pmsg->cause;

	if(pdnSession->default_bearer_established==0) {
		pdnSession->printPDNSession();
		pdnSession->printEPSBearerSession();
	}
	pdnSession->printTunnelSession();

	pdnSession->default_bearer_established=1;

	pdnSession->paging_flag=0;

}



void DeleteSessionRequest(unsigned char *p, int datalen, DecodedMsg *pmsg) {

	//printf("*****************************************************\n");
	//printf("XXX DeleteSessionRequest\n");
	//printf("teid 0x%x\n", pmsg->teid);

	int pos=0;
	while(pos<datalen) {
		pos = DecodeIE(p, pos, datalen, pmsg);
	}

	FTEID sgw;
	sgw.addr = pmsg->dst_addr;
	sgw.teid = pmsg->teid;

	it = hmap_sgw.find(sgw);

	if(it == hmap_sgw.end()) {
		// printf("XXX SESSION NOT FOUND+++++++++++++++++++++++++++++++++++\n");
		// sgw.print();
		return;
	}

	PDNSession *s = (*it).second;

	s->touch = pmsg->timestamp;




	//   sprintf(buff,"update pdn_session.all set duration = %f where imsi = %llu and start = %f",
	//      	             pmsg->timestamp - s->start,
	//		     s->imsi,
	//		     s->start);
	//
	//   // printf("\n*************************************************************************\n");
	//   // printf(buff);
	//
	//
	//   sprintf(buff,"update epsbearer_session.all set duration = %f where imsi = %llu and start = %f",
	//      	             pmsg->timestamp - s->start,
	//		     s->imsi,
	//		     s->start);

	// printf(buff);


	// printf("PDN Session %i closed duration %f\n", s->mme.teid, pmsg->timestamp - s->start);

	if(s->active_update_start>0) {
		s->CloseTunnelSession(pmsg);
	}


	EraseSession(s);

	// printf("*****************************************************\n");
}

void DownlinkDataNotification(unsigned char *p, int datalen, DecodedMsg *pmsg) {

	// printf("*****************************************************\n");
	// printf("OOO DownlinkDataNotification\n");
	// printf("teid 0x%x\n", pmsg->teid);

	int pos=0;
	while(pos<datalen) {

		pos = DecodeIE(p, pos, datalen, pmsg);
		// printf("pos %i datalen %i\n");

	}

	// printf("src: ");
	// printaddr(pmsg->src_addr);
	// printf(" dst: ");
	// printaddr(pmsg->dst_addr);
	// printf(" teid: %0x\n", pmsg->teid);

	FTEID mme;
	mme.addr = pmsg->dst_addr;
	mme.teid = pmsg->teid;

	num_notification++;


	it = hmap_mme.find(mme);
	if(it == hmap_mme.end()) {
		// printf("XXX SESSION NOT FOUND+++++++++++++++++++++++++++++++++++\n");

		num_notification_notfound++;

		// mme.print();
		return;
	}

	PDNSession *pdnSession = it->second;

	pdnSession->touch = pmsg->timestamp;

	// printf("PDNSession_ID=%i\n", pdnSession->session_id);

	if(pmsg->timestamp - pdnSession->paging_start<300
			&& pdnSession->paging_start!=0) {
		// printf("Repeated paging previous: %f\n", pdnSession->paging_start);
	}

	if(pdnSession->paging_start==0 || pmsg->timestamp - pdnSession->paging_start
			> 300) pdnSession->paging_start = pmsg->timestamp;

	// printf("Paging start %f\n", pdnSession->paging_start);

	// printf("*****************************************************\n");

}   

void DownlinkDataNotificationAck(unsigned char *p, int datalen, DecodedMsg *pmsg) {

	// printf("*****************************************************\n");
	// printf("OOO DownlinkDataNotificationAck\n");
	// printf("teid 0x%x\n", pmsg->teid);

	int pos=0;
	while(pos<datalen) {

		pos = DecodeIE(p, pos, datalen, pmsg);
		// printf("pos %i datalen %i\n");

	}

	//printf("src: ");
	//printaddr(pmsg->src_addr);
	//printf(" dst: ");
	//printaddr(pmsg->dst_addr);
	//printf(" teid: %0x\n", pmsg->teid);

	FTEID sgw;
	sgw.addr = pmsg->dst_addr;
	sgw.teid = pmsg->teid;

	num_notification_ack++;

	it = hmap_sgw.find(sgw);
	if(it == hmap_sgw.end()) {
		// printf("XXX SESSION NOT FOUND+++++++++++++++++++++++++++++++++++\n");
		num_notification_ack_notfound++;
		// sgw.print();
		return;
	}

	PDNSession *pdnSession = it->second;

	pdnSession->touch = pmsg->timestamp;

	// printf("PDNSession_ID=%i\n", pdnSession->session_id);

	unsigned char* addr=(unsigned char*)&(sgw.addr);

	double delay = pmsg->timestamp - pdnSession->paging_start;

	// printf("DL Notification delay %f\n", delay);

	char sdelay[100];
	if(delay>300) {
		sprintf(sdelay,"null");
		pdnSession->paging_start=0; // RESET PAGIONG START, WE DO NOT BELIEVE IT IS THE SAME PROC
		pdnSession->paging_flag = 0;
	} else {
		pdnSession->paging_flag = 1;
		sprintf(sdelay,"%f", delay);
	}
	//
	//   sprintf(buff, "insert into downlink_data_notification.current values ( \
	//                     %f, %s, %i, \
	//		     %llu, \
	//		     '%i.%i.%i.%i'::inet,\
	//		     %u \
	//	     )",
	//      	             pdnSession->paging_start,
	//		     sdelay, pmsg->cause,
	//		     pdnSession->imsi,
	//		     addr[3], addr[2], addr[1], addr[0],
	//		     sgw.teid);

	// printf(buff);


	// printf("*****************************************************\n");

}      

void DownlinkDataNotificationFailure(unsigned char *p, int datalen, DecodedMsg *pmsg) {

	// printf("*****************************************************\n");
	// printf("OOO DownlinkDataNotificationFailure\n");
	// printf("teid 0x%x\n", pmsg->teid);

	int pos=0;
	while(pos<datalen) {

		pos = DecodeIE(p, pos, datalen, pmsg);
		// printf("pos %i datalen %i\n");

	}


	// if(pmsg->cause == 87) printf("Cause: UE not responding\n");

	//printf("src: ");
	//printaddr(pmsg->src_addr);
	//printf(" dst: ");
	//printaddr(pmsg->dst_addr);
	//printf(" teid: %0x\n", pmsg->teid);

	FTEID sgw;
	sgw.addr = pmsg->dst_addr;
	sgw.teid = pmsg->teid;

	it = hmap_sgw.find(sgw);
	if(it == hmap_sgw.end()) {
		// printf("XXX SESSION NOT FOUND+++++++++++++++++++++++++++++++++++\n");
		// sgw.print();
		return;
	}

	PDNSession *pdnSession = it->second;


	pdnSession->touch = pmsg->timestamp;


	// printf("PDNSession_ID=%i\n", pdnSession->session_id);

	double delay = pmsg->timestamp - pdnSession->paging_start;
	// printf("Paging delay (failed) %f\n", delay);

	unsigned char* addr=(unsigned char*)&(pdnSession->mme.addr);

	// Failed paging goes into the paging table with cause code
	//   sprintf(buff, "insert into paging.current values ( \
	//                     %f, %f, %i, \
	//		     %llu, \
	//		     '%i.%i.%i.%i'::inet,\
	//		     %u \
	//	     )",
	//      	             pdnSession->paging_start,
	//		     delay, pmsg->cause,
	//		     pdnSession->imsi,
	//		     addr[3], addr[2], addr[1], addr[0],
	//		     sgw.teid);

	// printf(buff);




	pdnSession->paging_start=0;

	// printf("*****************************************************\n");
}      

void ContextRequest(unsigned char *p, int datalen, DecodedMsg *pmsg) {

	printf("*****************************************************\n");
	printf("OOO ContextRequest\n");
	printf("teid 0x%x\n", pmsg->teid);

	int pos=0;
	while(pos<datalen) {

		pos = DecodeIE(p, pos, datalen, pmsg);
		// printf("pos %i datalen %i\n");

	}

}      

void ContextResponse(unsigned char *p, int datalen, DecodedMsg *pmsg) {

	printf("*****************************************************\n");
	printf("OOO ContextResponse\n");

	printf("teid 0x%x\n", pmsg->teid);

	int pos=0;
	while(pos<datalen) {

		pos = DecodeIE(p, pos, datalen, pmsg);
		// printf("pos %i datalen %i\n");

	}

} 

void ContextAck(unsigned char *p, int datalen, DecodedMsg *pmsg) {

	printf("*****************************************************\n");
	printf("OOO ContextAck\n");

	printf("teid 0x%x\n", pmsg->teid);

	int pos=0;
	while(pos<datalen) {

		pos = DecodeIE(p, pos, datalen, pmsg);
		// printf("pos %i datalen %i\n");

	}

} 

void ReleaseAccessBearersRequest(unsigned char *p, int datalen, DecodedMsg *pmsg) {

	// printf("*****************************************************\n");
	// printf("OOO ReleaseAccessBearersRequest\n");
	// printf("teid 0x%x\n", pmsg->teid);

	int pos=0;
	while(pos<datalen) {

		pos = DecodeIE(p, pos, datalen, pmsg);
		// printf("pos %i datalen %i\n");

	}

	//printf("src: ");
	//printaddr(pmsg->src_addr);
	//printf(" dst: ");
	//printaddr(pmsg->dst_addr);
	//printf(" teid: %0x\n", pmsg->teid);

	FTEID sgw;
	sgw.addr = pmsg->dst_addr;
	sgw.teid = pmsg->teid;

	num_notification_ack++;

	it = hmap_sgw.find(sgw);
	if(it == hmap_sgw.end()) {
		// printf("XXX SESSION NOT FOUND+++++++++++++++++++++++++++++++++++\n");
		num_notification_ack_notfound++;
		// sgw.print();
		return;
	}

	PDNSession *pdnSession = it->second;

	// printf("PDNSession_ID=%i\n", pdnSession->session_id);

	pdnSession->touch = pmsg->timestamp;

	pdnSession->paging_start=0;

	if(pdnSession->active_update_start>0) {
		// printf("CLOSE TUNNEL\n");

		// pdnSession->print();

		pdnSession->CloseTunnelSession(pmsg);

		pdnSession->active_update_start=0;

	} else {
		// printf("OPEN TUNNEL NOT FOUND!\n");
	}



	// printf("*****************************************************\n");

}      

void ReleaseAccessBearersResponse(unsigned char *p, int datalen, DecodedMsg *pmsg) {

	// printf("*****************************************************\n");
	// printf("OOO ReleaseAccessBearersResponse\n");
	// printf("teid 0x%x\n", pmsg->teid);

	int pos=0;
	while(pos<datalen) {

		pos = DecodeIE(p, pos, datalen, pmsg);
		// printf("pos %i datalen %i\n");

	}

	// printf("*****************************************************\n");
}      


bool PDNSortFunc(const PDNSession* d1, const PDNSession* d2)
{
	return d1->touch < d2->touch;
}


void purgeOldSessions(double last_time) {
	// printf("ManageHash\n");

	int i=0;

	vector<PDNSession *> vec ;

	it = hmap_mme.begin();
	while(it != hmap_mme.end()) {

		PDNSession *pdnSession = it->second;

		if(last_time - pdnSession->touch > 3600*24) {
			vec.push_back(pdnSession);
		}

		std::sort(vec.begin(), vec.end(), PDNSortFunc);

		it++;

		i++;
	}

	// printf("Number of sessions: %i old %i\n", i, vec.size());

	int old = vec.size();

	if(old>1000) {

		for (int index=0; index<old-1000; ++index) {
			PDNSession *s = vec.at(index) ;
			// printf("Delete %f\n", s->touch);
			EraseSession(s);
		}
	}

}


int last_ipid=0;
int last_teid=0;
int last_src=0;
int last_dst=0;

int main(int argc, char **argv)
{
	int i;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	const u_char *packet;
	struct pcap_pkthdr pkthdr;     /* pcap.h */
	struct ether_header *eptr;  /* net/ethernet.h */
	double last_time = -1;

	bool live = false;

	u_char *ptr; /* printing out hardware header info */

	/* open the device for sniffing.

       pcap_t *pcap_open_live(char *device,int snaplen, int prmisc,int to_ms,
       char *ebuf)

       snaplen - maximum size of packets to capture in bytes
       promisc - set card in promiscuous mode?
       to_ms   - time to wait for packets in miliseconds before read
       times out
       errbuf  - if something happens, place error string here

       Note if you change "prmisc" param to anything other than zero, you will
       get all packets your device sees, whether they are intendeed for you or
       not!! Be sure you know the rules of the network you are running on
       before you set your card in promiscuous mode!!     */

	double update_time=60;

	if(argv[1][0]=='e' && argv[1][1]=='t' && argv[1][2]=='h' ||
			argv[1][0]=='a' && argv[1][1]=='n' && argv[1][2]=='y') {
		descr = pcap_open_live(argv[1],BUFSIZ,1,1000,errbuf);
		live = true;
	} else {
		descr = pcap_open_offline(argv[1],errbuf);
		update_time = 3600;
		live = false;
	}

	if(descr == NULL)
	{
		printf("pcap_open_live(): %s\n",errbuf);
		exit(1);
	}

	int linktype = pcap_datalink(descr);
	printf("link type: %i\n", linktype);
	if(linktype==1) printf("ETHERNET\n");
	else if(linktype==113) printf("COOKED HEADER\n");
	else {
		printf("UNKNOWN DATALINK TYPE\n");
		exit(0);
	}

	/*
    // Log Files
    char *perfmonDirName="/perfmon_source/LTE/S11";

    char log_tmp_pdn[1000];
    char log_tmp_eps[1000];
    char log_tmp_tun[1000];

    sprintf(log_tmp_pdn, "%s/pdn.tmp",perfmonDirName);
    sprintf(log_tmp_eps, "%s/eps.tmp",perfmonDirName);
    sprintf(log_tmp_tun, "%s/tun.tmp",perfmonDirName);

    char log_pdn[1000];
    char log_eps[1000];
    char log_tun[1000];
	 */

	double lastpacket=0;

	do {

		packet = pcap_next(descr,&pkthdr);


		double 	time = pkthdr.ts.tv_sec + pkthdr.ts.tv_usec/1e6;

		// will not yet write if timeout!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!1


		if(time-last_time > update_time || last_time==-1 || packet == NULL) {


			if(last_time > 0) {

				purgeOldSessions(last_time);

			}

			printf("STAT num_create_session_response %i num_create_session_response_notfound %i\n", num_create_session_response, num_create_session_response_notfound);

			printf("STAT num_modify_request %i num_modify_request_notfound %i\n", num_modify_request, num_modify_request_notfound);

			printf("STAT num_modify_response %i num_modify_response_notfound %i\n",num_modify_response, num_modify_response_notfound);

			printf("STAT num_notification %i num_notification_notfound %i\n", num_notification, num_notification_notfound);

			printf("STAT num_notification_ack %i num_notification_ack_notfound %i\n", num_notification_ack, num_notification_ack_notfound);


			num_create_session_response_notfound=0;
			num_modify_request_notfound=0;
			num_modify_response_notfound=0;
			num_notification_notfound=0;
			num_notification_ack_notfound=0;

			num_create_session_response=0;
			num_modify_request=0;
			num_modify_response=0;
			num_notification=0;
			num_notification_ack=0;

			last_time = time;
		}



		if(packet == NULL)
		{/* dinna work *sob* */
			printf("Didn't grab packet\n");

			if(live == false) exit(0);//end of file

			continue;
		}

		/*  struct pcap_pkthdr {
            struct timeval ts;   time stamp 
            bpf_u_int32 caplen;  length of portion present 
            bpf_u_int32;         lebgth this packet (off wire) 
            }
		 */

		const struct my_ip* ip;
		int length = pkthdr.len;

		if(linktype == 1) {
			/* lets start with the ether header... */
			eptr = (struct ether_header *) packet;

			/* Do a couple of checks to see what packet type we have..*/

			int ethertype = ntohs (eptr->ether_type);

			if (ethertype == ETHERTYPE_IP) {
				ip = (struct my_ip*)(packet + sizeof(struct ether_header));
				length -= sizeof(struct ether_header);
			} else if(ethertype == ETHERTYPE_VLAN) {
				ip = (struct my_ip*)(packet + sizeof(struct ether_header) + 4);
				length -= sizeof(struct ether_header)+4;

			} else continue;

		} else if(linktype==113) {

			if(packet[14]!=0x08 || packet[15]!=0x00) continue;

			ip = (struct my_ip*)(packet + 16);
			length -= 16;

		}

		/* check to see we have a packet of valid length */
		if (length < sizeof(struct my_ip))
		{
			printf("truncated ip %d",length);
			continue;
		}

		int len     = ntohs(ip->ip_len);
		int hlen    = IP_HL(ip); /* header length */
		int version = IP_V(ip);/* ip version */

		/* check version */
		if(version != 4)
		{
			fprintf(stdout,"%f Unknown version %d\n",time, version);
			continue;
			// return 0;
		}

		/* check header length */
		if(hlen < 5 )
		{
			fprintf(stdout,"bad-hlen %d \n",hlen);
		}

		/* see if we have as much packet as we should */
		if(length < len)
			printf("\ntruncated IP - %d %d\n",len, length);

		/* Check to see if we have the first fragment */
		int off = ntohs(ip->ip_off);

		int ipid = ip->ip_id;

		int ttl = ip->ip_ttl;
		//printf("ttl %i\n", ttl);

		int proto = ip->ip_p;
		//printf("proto 0x%x\n", proto);

		unsigned int src_addr=0;
		unsigned int dst_addr=0;
		for(int i=0; i<4; i++) {
			src_addr = src_addr*256 +((unsigned char*)&ip->ip_src)[i];
			dst_addr = dst_addr*256 +((unsigned char*)&ip->ip_dst)[i];
		}

		// if not UDP
		if(proto!=0x11) continue;


		unsigned char* udp = (unsigned char*)ip+hlen*4;

		unsigned short sport = udp[0]*256 + udp[1];
		unsigned short dport = udp[2]*256 + udp[3];

		// printf("sport %i dport %i\n", sport, dport);

		// check GTP
		if(sport != 2123 && dport != 2123) continue;

		unsigned char* gtp = udp+8;

		unsigned char flags = gtp[0];

		// printf("flags: %x\n", flags);


		if((flags & 0xe0) != 0x40) {
			// printf("Not GTPv2\n");
			continue;
		}

		printf("\n========= %f ================================================\n", time);

		//printf("src: ");
		//printaddr(src_addr);
		//printf(" dst: ");
		//printaddr(dst_addr);
		//printf("\n");

		struct DecodedMsg msg;

		int k,n,m;
		if(flags & 8) {
			// printf("TEID present\n") ;

			k = 1;
			m = 5;
			n = 9;

			msg.teid = ntohl(*(unsigned int *)(gtp+4));


		} else {
			msg.teid = -1;
			n = 5;
		}

		int gtp_hlen = n+3;

		if(flags & 16) printf("Piggybacking\n");


		unsigned char msgtype = gtp[1];

		unsigned short int gtplen = gtp[2]*256+gtp[3];

		// printf("gtplen %i gtp_hlen %i\n", gtplen, gtp_hlen);

		msg.timestamp = pkthdr.ts.tv_sec + pkthdr.ts.tv_usec/1e6;

		msg.src_addr = src_addr;
		msg.dst_addr = dst_addr;


		// HACK ============================================
		if(msg.teid == last_teid && last_src == src_addr && last_dst == dst_addr && msg.timestamp-lastpacket<1e-5) {
			printf("Duplicate?\n");
			continue;
		}
		lastpacket=msg.timestamp;

		last_teid = msg.teid;
		last_src = src_addr;
		last_dst = dst_addr;

		// printf("msgtype %i gtplen %i teid 0x%x\n", msgtype, gtplen, msg.teid);

		unsigned char *data=gtp+gtp_hlen;

		int datalen = gtplen - 8  ; // EZ BIZTOS ROSSZ!
		// printf("datalen %i\n", datalen);

		// data now points to information elements

		SetLog(false);

		switch (msgtype) {

		case 1:
			// printf("Echo Request\n");
			break;
		case 2:
			// printf("Echo Response\n");
			break;
		case 3:
			printf("Version not supported\n");
			break;

		case 32:
			CreateSessionRequest(data, datalen, &msg);
			break;

		case 33:
			CreateSessionResponse(data, datalen, &msg);
			break;

		case 34:
			ModifyBearerRequest(data, datalen, &msg);
			break;

		case 35:
			ModifyBearerResponse(data, datalen, &msg);
			break;

		case 36:
			DeleteSessionRequest(data, datalen, &msg);
			break;

		case 37:
			// printf("Delete Session response\n");
			// DeleteSessionResponse(data, datalen, &msg);
			break;

		case 70:
			DownlinkDataNotificationFailure(data, datalen, &msg);
			break;

		case 130:
			SetLog(true);
			ContextRequest(data, datalen, &msg);
			break;

		case 131:
			SetLog(true);
			ContextResponse(data, datalen, &msg);
			break;

		case 132:
			ContextAck(data, datalen, &msg);
			break;

		case 170:
			ReleaseAccessBearersRequest(data, datalen, &msg);
			break;

		case 171:
			ReleaseAccessBearersResponse(data, datalen, &msg);
			break;

		case 176:
			// printf("Downlink data notification\n");
			DownlinkDataNotification(data, datalen, &msg);
			break;

		case 177:
			// printf("Downlink data notification ACK\n");
			DownlinkDataNotificationAck(data, datalen, &msg);
			break;


		default:
			printf("******************* undecoded message type %i\n", msgtype);
		}

	} while(1);
}

