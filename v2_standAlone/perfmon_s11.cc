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
#include <string.h>
#include <ext/hash_map>

#include "libpq-fe.h"

#include "gtp_ie.h"

using namespace std;
using namespace __gnu_cxx;

FILE *file_pdn=NULL;
FILE *file_eps=NULL;
FILE *file_tun=NULL;
int records_written=0;


PGconn *conn;


struct FTEID {
   unsigned int addr;
   unsigned int teid;
   
   void print() {
   	unsigned char *a = (unsigned char*)&addr;
	printf("FTEID: %i.%i.%i.%i %0x\n", a[3],a[2],a[1],a[0],teid);
	
   }
   
};


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
   
   double time_pdn_response;
   double time_update_request;
   double time_update_response;
   
   double active_update_start;
   
   unsigned long long imsi;   

   struct FTEID mme;
   struct FTEID sgw_c, sgw_d;
   struct FTEID enb;
   
   char apn[100];
   unsigned long long msisdn;
   unsigned int ue_addr;
   unsigned char nsapi;
   
   unsigned char pdn_cause;
   unsigned char update_cause;
   
   PDNSession() {
      time_pdn_response=0;
      time_update_request=0;
      time_update_response=0;
      active_update_start=0;
      imsi=0;  
      pdn_cause=0;
      update_cause=0;
      msisdn=0;
   }
   
   void print() {
   
      unsigned char* pmmeaddr=(unsigned char*)&(mme.addr);
      unsigned char* psgwcaddr=(unsigned char*)&(sgw_c.addr);
      unsigned char* psgwdaddr=(unsigned char*)&(sgw_d.addr);
      unsigned char* penbaddr=(unsigned char*)&(enb.addr);
      unsigned char* pueaddr=(unsigned char*)&(ue_addr);
   
      printf("\nPDNSESSSION_PRINT********************************************************\n");
      printf("XXX start %f imsi %llu msisdn %llu mme %i.%i.%i.%i %0x sgw_c %i.%i.%i.%i %0x sgw_d %i.%i.%i.%i %0x enb %i.%i.%i.%i %0x apn %s ue_addr %i.%i.%i.%i nsapi %i\n", 
      	       start, imsi, msisdn,
	       pmmeaddr[3], pmmeaddr[2], pmmeaddr[1], pmmeaddr[0], mme.teid, 	       
	       psgwcaddr[3], psgwcaddr[2], psgwcaddr[1], psgwcaddr[0], sgw_c.teid, 	       
	       psgwdaddr[3], psgwdaddr[2], psgwdaddr[1], psgwdaddr[0], sgw_d.teid, 	       
	       penbaddr[3], penbaddr[2], penbaddr[1], penbaddr[0], enb.teid, 	       
	       apn, 
	       pueaddr[3], pueaddr[2], pueaddr[1], pueaddr[0], 	       
	       nsapi);
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
      
      PGresult *res;
      char buff[1000];

      sprintf(buff, "insert into pdn_session.all values ( \
                     %f, %f, %f, %f, \
		     %i, %i, \
		     null, \
		     %llu, \
		     '%s', \
		     %i,\
		     '%i.%i.%i.%i'::inet,\
		     null \
	     )", 
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

      printf("\n*************************************************************************\n");
      printf(buff);
      res = PQexec(conn, buff);

      
   };

   void printTunnelSession() {
   
      unsigned char* pmmeaddr=(unsigned char*)&(mme.addr);
      unsigned char* psgwcaddr=(unsigned char*)&(sgw_c.addr);
      unsigned char* psgwdaddr=(unsigned char*)&(sgw_d.addr);
      unsigned char* penbaddr=(unsigned char*)&(enb.addr);
      unsigned char* pueaddr=(unsigned char*)&(ue_addr);

      records_written++;
      
      /*
      printf("TunnelSession start %f end - imsi %llu eps_bearer_id %i mme_addr_c %i.%i.%i.%i mme_teid_c %0x sgw_addr_c %i.%i.%i.%i sgw_teid_c %0x sgw_addr_u %i.%i.%i.%i sgw_teid_u %0x enb_addr_u %i.%i.%i.%i enb_teid_u %0x\n",
      	       start, imsi, nsapi,
	       pmmeaddr[3], pmmeaddr[2], pmmeaddr[1], pmmeaddr[0], mme.teid,
	       psgwcaddr[3], psgwcaddr[2], psgwcaddr[1], psgwcaddr[0], sgw_c.teid,
	       psgwdaddr[3], psgwdaddr[2], psgwdaddr[1], psgwdaddr[0], sgw_d.teid,   	       penbaddr[3], penbaddr[2], penbaddr[1], penbaddr[0], enb.teid
	       );
      */
   
      /*
      // null is the end time
      fprintf(file_tun, "%f\t\\N\t%llu\t%i\t%i.%i.%i.%i\t%i\t%i.%i.%i.%i\t%i\t%i.%i.%i.%i\t%i\t%i.%i.%i.%i\t%i\n",
      	       start, imsi, nsapi,
	       pmmeaddr[3], pmmeaddr[2], pmmeaddr[1], pmmeaddr[0], 
	       mme.teid,
	       psgwcaddr[3], psgwcaddr[2], psgwcaddr[1], psgwcaddr[0], 
	       sgw_c.teid,
	       psgwdaddr[3], psgwdaddr[2], psgwdaddr[1], psgwdaddr[0], 
	       sgw_d.teid,   	       
	       penbaddr[3], penbaddr[2], penbaddr[1], penbaddr[0], 
	       enb.teid
	       );
      */
	       
      PGresult *res;
      char buff[1000];
      sprintf(buff, "insert into tunnel_session.all values ( \
               %f, null, %llu, %i, '%s',  \
	       '%i.%i.%i.%i'::inet,     \
	       '%i.%i.%i.%i'::inet, %i, \
	       '%i.%i.%i.%i'::inet, %i, \
	       '%i.%i.%i.%i'::inet, %i, \
	       '%i.%i.%i.%i'::inet, %i  \
      	             		    )",
      	       active_update_start, imsi, nsapi, apn,
  	       pueaddr[3], pueaddr[2], pueaddr[1], pueaddr[0],
	       pmmeaddr[3], pmmeaddr[2], pmmeaddr[1], pmmeaddr[0], mme.teid,
	       psgwcaddr[3], psgwcaddr[2], psgwcaddr[1], psgwcaddr[0], sgw_c.teid,
	       psgwdaddr[3], psgwdaddr[2], psgwdaddr[1], psgwdaddr[0], sgw_d.teid,   	       
	       penbaddr[3], penbaddr[2], penbaddr[1], penbaddr[0], enb.teid
	       );

      printf("\n*************************************************************************\n");
      printf(buff);
      res = PQexec(conn, buff);


   };
   
   void CloseTunnelSession(DecodedMsg *pmsg) {
      PGresult *res;
      char buff[1000];

      sprintf(buff,"update tunnel_session.all set duration = %f where imsi = %llu and start = %f",
      	             pmsg->timestamp - active_update_start,
		     imsi, 
		     active_update_start);

      printf("\n*************************************************************************\n");
      printf(buff);
      res = PQexec(conn, buff);
   
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

      PGresult *res;
      char buff[1000];
      sprintf(buff, "insert into epsbearer_session.all values (%f, %llu, %i)", start, imsi, nsapi);

      printf("\n*************************************************************************\n");
      printf(buff);
      res = PQexec(conn, buff);

   };
  
};

hash_map<struct FTEID, struct PDNSession*, dataeq, dataeq> hmap;
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




void CreatePDPContextRequest(unsigned char *p, int datalen, DecodedMsg *pmsg) {


   printf("*****************************************************\n");
   printf("XXX CreatePDPContextRequest\n");

   printf("teid 0x%x\n", pmsg->teid);
   
   if(pmsg->teid==0) printf("Primary\n");
   else printf("Secondary\n");
     
   int pos=0;
   while(pos<datalen) {

      pos = DecodeIE(p, pos, datalen, pmsg);      
      // printf("pos %i datalen %i\n");
   
   }
   
   // GTPv1
   // teid is not set
   // teid_i = 0
   // teid_c = MME control teid
   // addr1 = MME control addr
   // addr2 = not used (would be SGSN addr for UP)

   // create new hash entry
   PDNSession *pdnSession = new PDNSession();
   FTEID mme;
   
   mme.addr = pmsg->addr1;
   mme.teid = pmsg->teid_c;
   
   hmap[mme] = pdnSession;   
   
   pdnSession->start = pmsg->timestamp;

   
   pdnSession->imsi = pmsg->imsi;
   pdnSession->nsapi = pmsg->nsapi;
   strcpy(pdnSession->apn, pmsg->apn);
   
   pdnSession->mme.addr = pmsg->addr1;
   pdnSession->mme.teid = pmsg->teid_c;
   pdnSession->msisdn = pmsg->msisdn;
   pdnSession->print();

   printf("*****************************************************\n");


}

void CreatePDPContextResponse(unsigned char *p, int datalen, DecodedMsg *pmsg) {

   printf("XXX CreatePDPContextResponse\n");

   printf("teid 0x%x\n", pmsg->teid);
   
   int pos=0;
   while(pos<datalen) {

      pos = DecodeIE(p, pos, datalen, pmsg);      
      // printf("pos %i datalen %i\n");   
   }        
   
   // GTPv1:
   // teid = MME control teid
   // teid_i = SGW data teid
   // teid_c = SGW control teid
   // addr1 = SGW control addr
   // addr2 = SGW data addr   
   
   
   FTEID mme;
   mme.addr = pmsg->dst_addr;
   mme.teid = pmsg->teid;
      
   it = hmap.find(mme);   
   if(it == hmap.end()) {
      printf("XXX SESSION NOT FOUND+++++++++++++++++++++++++++++++++++\n");
      mme.print();
      return;
   }
   
   PDNSession *pdnSession = it->second;

   pdnSession->sgw_d.addr = pmsg->addr2;
   pdnSession->sgw_d.teid = pmsg->teid_d;
   
   pdnSession->sgw_c.addr = pmsg->addr1;
   pdnSession->sgw_c.teid = pmsg->teid_c;
   
   pdnSession->ue_addr = pmsg->ue_addr;
   
   
   pdnSession->time_pdn_response = pmsg->timestamp;

   if(pmsg->cause_present) pdnSession->pdn_cause = pmsg->cause;   
   
   pdnSession->print();
}

void UpdatePDPContextRequest(unsigned char *p, int datalen, DecodedMsg *pmsg) {

   printf("XXX UpdatePDPContextRequest\n");
   
   printf("teid 0x%x\n", pmsg->teid);

   int pos=0;
   while(pos<datalen) {

      pos = DecodeIE(p, pos, datalen, pmsg);      
      // printf("pos %i datalen %i\n");
   
   }  
   
   // GTPv1:
   // teid = SGW control teid
   // teid_c = MME control teid
   // teid_d = eNB teid ?
   // addr1 = ?? MME addr???
   // addr2 = eNB addr?
   
   
   FTEID mme;
   mme.addr = pmsg->src_addr;
   mme.teid = pmsg->teid_c;
      
   it = hmap.find(mme);   
   if(it == hmap.end()) {
      printf("XXX SESSION NOT FOUND+++++++++++++++++++++++++++++++++++\n");
      mme.print();
      return;
   }
   
   PDNSession *pdnSession = it->second;

   
   if(pdnSession->time_update_request>0) {
      printf("CHANGE TUNNEL, CLOSE EARLIER");
      
      pdnSession->CloseTunnelSession(pmsg);      
      
      pdnSession->print();
      return;
   }
   
   
   pdnSession->enb.addr = pmsg->addr2;
   pdnSession->enb.teid = pmsg->teid_d;
   
   pdnSession->time_update_request = pmsg->timestamp;
   pdnSession->active_update_start = pmsg->timestamp;
   
   pdnSession->print();
   
   
}

void UpdatePDPContextResponse(unsigned char *p, int datalen, DecodedMsg *pmsg) {

   printf("XXX UpdatePDPContextResponse\n");

   printf("teid 0x%x\n", pmsg->teid);
   
   int pos=0;
   while(pos<datalen) {

      pos = DecodeIE(p, pos, datalen, pmsg);      
      // printf("pos %i datalen %i\n");
   
   }  
   
   // GTPv1:
   // teid = MME teid
   
   FTEID mme;
   mme.addr = pmsg->dst_addr;
   mme.teid = pmsg->teid;

   it = hmap.find(mme);   
   if(it == hmap.end()) {
      printf("XXX SESSION NOT FOUND+++++++++++++++++++++++++++++++++++\n");
      mme.print();
      return;
   }
   
   PDNSession *pdnSession = it->second;
   
   if(pdnSession->time_update_response>0) {
      printf("HANDOVER");
      pdnSession->print();
      return;
   }
   
   
   pdnSession->time_update_response = pmsg->timestamp;

   if(pmsg->cause_present) pdnSession->update_cause = pmsg->cause;
   
   pdnSession->print();
   
   pdnSession->printPDNSession();
   pdnSession->printEPSBearerSession();
   pdnSession->printTunnelSession();
}

void DeletePDPContextRequest(unsigned char *p, int datalen, DecodedMsg *pmsg) {

   printf("*****************************************************\n");
   printf("XXX DeletePDPContextRequest\n");

   printf("teid 0x%x\n", pmsg->teid);
   
   int pos=0;
   while(pos<datalen) {

      pos = DecodeIE(p, pos, datalen, pmsg);      
      // printf("pos %i datalen %i\n");
   
   }  
   
   FTEID sgw;
   sgw.addr = pmsg->dst_addr;
   sgw.teid = pmsg->teid;

   // HACK!
   it = hmap.begin();
	
   PDNSession *s=NULL;
   while(it != hmap.end()) {   
            
      // printf("X: %llu\n", ((*it).second)->imsi);

      PDNSession *f = (*it).second;
      
      if(f->sgw_c.addr == sgw.addr && f->sgw_c.teid == sgw.teid) {
         printf("FOUND\n"); 
	 s = f;
	 break;
      }
      
      
      it++;
   }      

   if(s == NULL) {
      printf("NOT FOUND \n");
   }
   
   if(s != NULL) {
      PGresult *res;
      char buff[1000];

      sprintf(buff,"update pdn_session.all set duration = %f where imsi = %llu and start = %f",
      	             pmsg->timestamp - s->start,
		     s->imsi, 
		     s->start);

      printf("\n*************************************************************************\n");
      printf(buff);
      res = PQexec(conn, buff);
      
      if(s->active_update_start>0) {
         s->CloseTunnelSession(pmsg);
      }
      
      
      hmap.erase(it);
      delete(s);
   }

   /*
   it = hmap.find(mme);   
   if(it == hmap.end()) {
      printf("YYY SESSION NOTFOUND\n");
      mme.print();
      return;
   } else {
      printf("ZZZ FOUND\n");
   
   }
   */
   printf("*****************************************************\n");

   
}

void DeletePDPContextResponse(unsigned char *p, int datalen, DecodedMsg *pmsg) {

   printf("*****************************************************\n");
   printf("OOO DeletePDPContextResponse\n");
   
   return; // WE DO NOT NEED IT

   printf("teid 0x%x\n", pmsg->teid);
   
   int pos=0;
   while(pos<datalen) {

      pos = DecodeIE(p, pos, datalen, pmsg);      
      // printf("pos %i datalen %i\n");
   
   }  
   
   printf("src: ");
   printaddr(pmsg->src_addr);
   printf(" dst: ");
   printaddr(pmsg->dst_addr);
   printf(" teid: %0x\n", pmsg->teid);
   
   printf("*****************************************************\n");
   
}   
   

void ManageHash() {
   printf("ManageHash\n");
   
   it = hmap.begin();

   int i=0;         
	 
   while(it != hmap.end()) {   
      it++;
      
      i++;
   }      
   
   printf("Number of sessions: %i\n", i);
}
   
void SQLConnect() {
   conn = PQconnectdb("dbname=ldb_s11 host=localhost user=perfmon password=perfpass");
   
   if(PQstatus(conn) != CONNECTION_OK) {
      printf("Connection error!\n");
   } else {
      printf("CONNECTION OK--------------------\n");
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
    
    SQLConnect();
    
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

    if(argv[1][0]=='e' && argv[1][1]=='t' && argv[1][2]=='h') {
       descr = pcap_open_live(argv[1],BUFSIZ,1,1000,errbuf);
       live = true;
    } else {
       descr = pcap_open_offline(argv[1],errbuf);
       update_time = 30000*3600;
       live = false;
    }

    if(descr == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
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


    do {

	packet = pcap_next(descr,&pkthdr);


        double 	time = pkthdr.ts.tv_sec + pkthdr.ts.tv_usec/1e6;

        // will not yet write if timeout!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!1
	
        if(time-last_time > update_time || last_time==-1 || packet == NULL) {


           if(last_time > 0) {
	   
	      ManageHash();

      	      /*
              fclose(file_pdn);
              fclose(file_eps);
              fclose(file_tun);

              if(records_written>0) {

                 sprintf(log_pdn, "%s/pdn_%i.log",perfmonDirName, (int)time);
                 sprintf(log_eps, "%s/eps_%i.log",perfmonDirName, (int)time);
                 sprintf(log_tun, "%s/tun_%i.log",perfmonDirName, (int)time);

                 rename(log_tmp_pdn, log_pdn);
                 rename(log_tmp_eps, log_eps);
                 rename(log_tmp_tun, log_tun);

                 printf("New log files available %i\n",(int)time);
	      } else {
	         printf("No records in period\n");
	      } 
	      */
	        
           }

           /*
           file_pdn = fopen(log_tmp_pdn,"w");
           file_eps = fopen(log_tmp_eps,"w");
           file_tun = fopen(log_tmp_tun,"w");
	   
           if(file_pdn==NULL || file_eps==NULL || file_tun==NULL)
           {
              printf("Error opening log file %s\n",strerror(errno));
              exit(-1);
           }
	   */

           last_time = time;
        }



	if(packet == NULL)
	{/* dinna work *sob* */
            printf("Didn't grab packet\n");
	    
	    if(live == false) exit(0);
	    
            continue;
	}

	/*  struct pcap_pkthdr {
            struct timeval ts;   time stamp 
            bpf_u_int32 caplen;  length of portion present 
            bpf_u_int32;         lebgth this packet (off wire) 
            }
	 */

	// printf("length %d\n",pkthdr.len);
	// printf("Recieved at ..... %s\n",ctime((const time_t)pkthdr.ts.tv_sec)); 
	// printf("Ethernet address length is %d\n",ETHER_HDR_LEN);

	/* lets start with the ether header... */
	eptr = (struct ether_header *) packet;

	/* Do a couple of checks to see what packet type we have..*/
	if (ntohs (eptr->ether_type) != ETHERTYPE_IP) continue;


	//printf("Ethernet type hex:%x dec:%d is an IP packet\n",
        //            ntohs(eptr->ether_type),
        //            ntohs(eptr->ether_type));


	//ptr = eptr->ether_dhost;
	//i = ETHER_ADDR_LEN;
	//printf(" Destination Address:  ");
	//do{
        //    printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
	//}while(--i>0);
	//printf("\n");

	//ptr = eptr->ether_shost;
	//i = ETHER_ADDR_LEN;
	//printf(" Source Address:  ");
	//do{
        //    printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
	//}while(--i>0);
	//printf("\n");
	
	// jump to IP header
	const struct my_ip* ip;
	
        ip = (struct my_ip*)(packet + sizeof(struct ether_header));
        int length = pkthdr.len - sizeof(struct ether_header); 

        /* check to see we have a packet of valid length */
        if (length < sizeof(struct my_ip))
        {
            printf("truncated ip %d",length);
            return 0;
        }

        int len     = ntohs(ip->ip_len);
        int hlen    = IP_HL(ip); /* header length */
        int version = IP_V(ip);/* ip version */

        /* check version */
        if(version != 4)
        {
	  fprintf(stdout,"Unknown version %d\n",version);
	  return 0;
        }

        /* check header length */
        if(hlen < 5 )
        {
           fprintf(stdout,"bad-hlen %d \n",hlen);
        }

        /* see if we have as much packet as we should */
        if(length < len)
           printf("\ntruncated IP - %d bytes missing\n",len - length);

        /* Check to see if we have the first fragment */
        int off = ntohs(ip->ip_off);
	
        // if((off & 0x1fff) == 0 )/* aka no 1's in first 13 bits */
	
        /* print SOURCE DESTINATION hlen version len offset */
        //fprintf(stdout,"IP: ");
        //fprintf(stdout,"%s ",
        //           inet_ntoa(ip->ip_src));
        //fprintf(stdout,"%s hlen %d version %d len %d off %d\n",
        //           inet_ntoa(ip->ip_dst),
        //           hlen,version,len,off);

        int ipid = ip->ip_id;
	
	
	//if(ipid == last_ipid) continue;
	//printf("ipid %i \n", ipid);
	//last_ipid = ipid;	
	
        
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
		
	if(flags & 0x30 != 0x30) {
	   printf("Not GTP rel 99 version 1\n");
	   continue;
	}
	
	//printf("src: ");
	//printaddr(src_addr);
	//printf(" dst: ");
	//printaddr(dst_addr);
	//printf("\n");
	
	
	unsigned char msgtype = gtp[1];
	
	unsigned short int gtplen = gtp[2]*256+gtp[3];
	
        struct DecodedMsg msg;
	
	msg.timestamp = pkthdr.ts.tv_sec + pkthdr.ts.tv_usec/1e6;
	
	msg.src_addr = src_addr;
	msg.dst_addr = dst_addr;
	
	msg.teid = ntohl(*(unsigned int *)(gtp+4));
	
	
	// HACK ============================================
	if(msg.teid == last_teid && last_src == src_addr && last_dst == dst_addr) continue;
	last_teid = msg.teid;
	last_src = src_addr;
	last_dst = dst_addr;
	
	// printf("msgtype %i gtplen %i teid 0x%x\n", msgtype, gtplen, msg.teid);
		
	unsigned char *data=gtp+8;
	
        if (flags&0x07) { // additional fields
	
	   data+=4;
	
           if (flags&0x04) { // extension header

              printf("Extension header\n");
	      
              while (data[-1]>0) data+=(data[0])*4;
           } 
        } 

        int datalen = gtplen - (data-gtp-8) ;
        // printf("datalen %i\n", datalen);

	// data now points to information elements
	
	printf("Time: %f ----------------------------------------------------------------\n",msg.timestamp);
	
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
	      printf("Send routing information for gprs request\n");
	      break;
	   
	   case 33:  
	      printf("Send routing information for gprs response\n");
	      break;
	    
	       	    
	
           case 0x10:
	      CreatePDPContextRequest(data, datalen, &msg);
	      break;   
	      
	   case 0x11:
	      CreatePDPContextResponse(data, datalen, &msg);
	      break;   

	   case 0x12:
	      UpdatePDPContextRequest(data, datalen, &msg);
	      break;   

	   case 0x13:
	      UpdatePDPContextResponse(data, datalen, &msg);
	      break;   
	     
	   case 0x14:
	      DeletePDPContextRequest(data, datalen, &msg);
	      break;
	   
	   case 0x15:
	      DeletePDPContextResponse(data, datalen, &msg);
	      break;


	   default:
	      printf("******************* undecoded message type %i\n", msgtype);
	 }
	
	
		
	 /*
	for(i=0; i<data_len; i++) {
	   unsigned char c;
	   c = data[i]; 
	   printf("%x ", c);
        }	*/
	// printf("\n*************************************************************************\n");
	
	// Decode_S1AP(data, data_len);
	
   } while(1);
}

