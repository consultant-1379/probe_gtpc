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
#include <time.h>

#include "gtp_ie_gtpv2.h"

bool plog;

void SetLog(bool i) {
   plog = i;
}

Bearer :: Bearer() {
   present = 0;
}

DecodedMsg :: DecodedMsg() {
   imsi_present=0;
   apn_present=addr1_present=addr2_present=0;
   msisdn_present=cause_present=ue_addr_present=0;
   src_addr = dst_addr = 0;
   eps_bearer_id=-1;
   delay_value_present = delay_value = 0;
}

int DecodeIMSI_IE(unsigned char *p, int pos, int datalen, struct DecodedMsg *pmsg) {
   
   int i;
   
   pmsg->imsi_present=1;
   pmsg->imsi=0;
   
   int n = p[pos+1]*256 + p[pos+2];
   
   for(i=0; i<n; i++) {
   
      // printf("%x ", p[pos+i+4]);
      
      int d1 = p[pos+i+4]&0x0f;      
      if(d1==15) break;
      
      pmsg->imsi *= 10;
      pmsg->imsi += d1;

      int d2 = (p[pos+i+4]&0xf0)/16;      
      if(d2==15) break;

      pmsg->imsi *= 10;
      pmsg->imsi += d2 ;
   }
   
   if(plog) printf("IMSI: %llu\n", pmsg->imsi);
   
   return pos + n + 4;
}


int DecodeMSISDN_IE(unsigned char *p, int pos, int datalen, struct DecodedMsg *pmsg) {
   
   int i;
      
   pmsg->msisdn_present=1;
   pmsg->msisdn=0;

   int n = p[pos+1]*256 + p[pos+2];   
   
   for(i=0; i<n; i++) {
      pmsg->msisdn *= 100;
      
      int d1 = p[pos+i+4]&0x0f;
      int d2 = (p[pos+i+4]&0xf0)/16;
      
      if(d1!=15) pmsg->msisdn += 10*d1;
      if(d2!=15) pmsg->msisdn += d2 ;
   }
   
   if(plog) printf("MSISDN: %llu\n", pmsg->msisdn);
   
   return pos + n + 4;
}

int DecodeMEI_IE(unsigned char *p, int pos, int datalen, struct DecodedMsg *pmsg) {
   
   int i;
      
   pmsg->mei_present=1;
   pmsg->mei=0;

   int n = p[pos+1]*256 + p[pos+2];   
   
   // printf("MEI len=%i ", n);
   
   for(i=0; i<n; i++) {      
      int d1 = p[pos+i+4]&0x0f;
      int d2 = (p[pos+i+4]&0xf0)/16;
      
      // printf(" d1:%i  d2:%i ", d1, d2);
      
      pmsg->mei *= 10;
      
      pmsg->mei += d1;
      
      if(d2!=15) {
         pmsg->mei *= 10;
         pmsg->mei += d2 ;
      }
   }
   
   if(plog) printf("MEI(IMEI): %llu\n", pmsg->mei);
   
   return pos + n + 4;
}


int DecodeIndication_IE(unsigned char *p, int pos, int datalen, struct DecodedMsg *pmsg) {
   
   int i;
      
   int n = p[pos+1]*256 + p[pos+2];   
   
   
   int f = p[4];

   if(plog) {
      printf("Indication: %i", f);

      if(f&1) printf("SGW Change Indication\n");
      if(f&2) printf("ISRAI\n");
      if(f&4) printf("ISRSI\n");
   
      if(f&8) printf("Operation Indication\n");
      if(f&16) printf("Direct Forwarding Indication\n");   
      if(f&32) printf("Handover Indication\n");   
      if(f&64) printf("Direct Tunnel Flag\n");      
      if(f&128) printf("Dual Address Bearer Flag\n");
   
      printf("\n");
   }

   return pos + n + 4;
}

int DecodeFTEID_IE(unsigned char *p, int pos, int datalen, struct DecodedMsg *pmsg) {
   
   int i;
      
   int n = p[pos+1]*256 + p[pos+2];      
   
   if(plog) printf("FTEID n=%i\n", n);

   int instance = p[pos+3] & 31;
   
   if(plog) printf("instance=%i\n", instance);

   int f = p[pos+4];
   
   if(f&128) {
      if(plog) printf("V4 present\n");

      pmsg->fteid[instance].teid =ReadInt(p, pos+5);
      if(plog) printf("teid = %i\n", pmsg->fteid[instance].teid);
      
      pmsg->fteid[instance].addr = ReadInt(p, pos+9);
      
      unsigned char *c = (unsigned char*)&(pmsg->fteid[instance].addr);
      if(plog) printf("addr= %i.%i.%i.%i\n", c[3], c[2], c[1], c[0]);
   }


   if(f&64) if(plog) printf("V6 present\n");

 
   int iftype = f&31;  
   
   if(plog) printf("iftype=%i\n",iftype);

   if(iftype==10) if(plog) printf("S11 MME GTP-C interface\n");
   if(iftype==7) if(plog) printf("S5/S8 PGW GTP-C interface\n");

   return pos + n + 4;
   
}  

int DecodeBearerContext_IE(unsigned char *p, int pos, int datalen, struct DecodedMsg *pmsg) {

   if(plog) printf("BearerContext\n");
   int n = p[pos+1]*256 + p[pos+2];  
   
   int instance = p[pos+3] & 31;
   
   if(plog) printf("instance=%i\n", instance);       
   
   unsigned char *p_group = p+pos+4;
   int datalen_group = n - 4;
   int pos_group=0;
   DecodedMsg msg_group;
   
   if(plog) printf("GROUP DECODE +++++++++++++++++++++++++++++++\n");
   
   while(pos_group<datalen_group) {
      pos_group = DecodeIE(p_group, pos_group, datalen_group, &msg_group);          
   }  
      

   if(plog) printf("END GROUP DECODE +++++++++++++++++++++++++++++++\n");
   
   // copy fteids from group decoded msg into the parent message appropriate bearer fteid list
   int id = msg_group.eps_bearer_id;
   
   if(pmsg->eps_bearer_id == -1) pmsg->eps_bearer_id = id;
   
   if(plog) printf("eps_bearer_id = %i, instance = %i\n", id, instance);
      
   if(id!=-1) {
   
      pmsg->bearer[instance][id].present = 1;

      for(int i=0; i<15; i++) { 
      
         if(msg_group.fteid[i].teid==0) continue;
         
         pmsg->bearer[instance][id].fteid[i] = msg_group.fteid[i];
      
         if(plog) printf("bearer %i [%i] ", id, i);
         if(plog) pmsg->bearer[instance][id].fteid[i].print(); 
      }
   }
      
   if(plog) printf("BearerContext END\n");

   return pos + n + 4;
}   
  
int DecodeAPN_IE(unsigned char *p, int pos, int datalen, struct DecodedMsg *pmsg) {

   // apn name
   int n = p[pos+1]*256 + p[pos+2];      

   int i=0;
   
   int part_len;
   int j;
   int c=0;
   while(i<n) {
      part_len = p[pos+4+i];
      memcpy(pmsg->apn+c, p+pos+5+i, part_len);
      c+=part_len;

      i+=part_len+1;
      if(i<n) pmsg->apn[c++]='.';
   }
	       
   pmsg->apn[c]='\0';
   if(plog) printf("apn: %s\n", pmsg->apn);
	    
   pmsg->apn_present=1;
	    
   return pos + n + 4;	 
}

int DecodePDPContext_IE(unsigned char *p, int pos, int datalen) {
   
   unsigned short int length = p[2]*256+p[3];
   
   return pos + length;
}

unsigned int ReadInt(unsigned char *p, int pos) {
   return (p[pos]<<24) + (p[pos+1]<<16) + (p[pos+2]<<8) + p[pos+3];
}

// returns new pos
int DecodeIE(unsigned char *p, int pos, int datalen,struct DecodedMsg *pmsg) {

   int n = p[pos+1]*256 + p[pos+2];
   // printf("IE: %i pos %i len %i\n", p[pos], pos, n+4);
   
   int ie = p[pos];
   
   switch (ie) {
   
      case 0: {
	 // Reserved0 
         if(plog) printf("Reserved0 skipped (length=%i)\n", n);   
         return pos + n + 4;
      }
         
      case 1:
      	 // IMSI
      	 return DecodeIMSI_IE(p, pos, datalen, pmsg);

      case 2: {
      	 // Cause
	 pmsg->cause_present=1;
	 pmsg->cause = p[pos+4];
	 if(plog) printf("Cause(n=%i): %i\n", n, pmsg->cause);
      	 return pos + n + 4;
      }

      case 71:
	 // apn
         return DecodeAPN_IE(p, pos, datalen, pmsg);   

      case 72: {
	 // AMBR
         if(plog) printf("AMBR skipped\n");   
         return pos + n + 4;

      }
      
      case 73: {
	 // EPS bearer id
	 pmsg->eps_bearer_id = p[pos+4] & 15;
	 
         if(plog) printf("EPS bearer id: %i\n", pmsg->eps_bearer_id);   
         return pos + n + 4;

      }

      
      case 75:
         return DecodeMEI_IE(p, pos, datalen, pmsg);   
  

      case 76:
	 // msisdn
         return DecodeMSISDN_IE(p, pos, datalen, pmsg);   

      case 77:
	 // indication
         return DecodeIndication_IE(p, pos, datalen, pmsg);   

      case 78: {
	 // Protocol configuration options
	 if(plog) printf("Protocol Configuration Options -- skip\n");
	 	 
         return pos + n + 4;
      }

      case 79: {
	 // PDN Address allocation
	 if(plog) printf("PDN Address\n");
	 
	 int type = p[pos+4];
	 
	 // printf("PDN type %i\n", type);
	 
	 if(type == 1) {
	    if(plog) printf("PDN type : v4\n");
	    pmsg->ue_addr_present = 1;
	    pmsg->ue_addr = ReadInt(p, pos+5);
            unsigned char *c = (unsigned char*)&(pmsg->ue_addr);
            if(plog) printf("addr: %i.%i.%i.%i\n", c[3], c[2], c[1], c[0]);	    
	 }
	 
         return pos + n + 4;
      }

      case 80: {
	 // Bearer QoS
         if(plog) printf("Bearer QOS skipped\n");   
         return pos + n + 4;

      }
      
      case 82: {
	 // RAT Type
         if(plog) {
            printf("RAT Type %i ", p[pos+4]); 
	    if(p[pos+4]==6) printf("EUTRAN\n");
            else printf("\n");
         }
         return pos + n + 4;

      }

      case 83: {
	 // Serving network (MNC+MCC)
         if(plog) printf("MNC+MCC skipped\n");   
         return pos + n + 4;

      }
      
      case 86: {
	 // User Location Id
         if(plog) printf("ULI decode skipped\n");   
         return pos + n + 4;
      }


      case 87: {
	 // FTEID
         return DecodeFTEID_IE(p, pos, datalen, pmsg);   
      }

      case 92: {
	 // Delay Value
	 pmsg->delay_value = p[pos+4];
	 pmsg->delay_value_present = 1;
         if(plog) printf("Delay Value %i\n", pmsg->delay_value);
         return pos + n + 4;
      }

 
      case 93: {
	 // Bearer context 
         return DecodeBearerContext_IE(p, pos, datalen, pmsg);   
      }

      case 95: {
	 // Charging characteristics
         if(plog) printf("Charging characteristics skipped\n");   
         return pos + n + 4;

      }
                       
      case 99: {
	 // PDN type
         if(plog) printf("PDU numbers skipped\n");   
         return pos + n + 4;
      }

      case 110: {
	 // PDU numbers
         if(plog) printf("PDN type skipped\n");   
         return pos + n + 4;
      }

      case 116: {
         if(plog) printf("Complete Request Message\n");   
         return pos + n + 4;
      }

      case 117: {
         if(plog) printf("GUTI type skipped\n");   
         return pos + n + 4;
      }

      case 127: {
	 // APN restriction
         if(plog) printf("APN restriction skipped\n");   
         return pos + n + 4;
      }
      
      case 128: {
	 // Selection mode
         if(plog) printf("Selection mode skipped\n");   
         return pos + n + 4;
      }
	 	 
      default:
      	 if(plog) printf("IE not decoded: %i\n", ie);
      	 return pos+n+4;
   }
   
   return 0;

}
