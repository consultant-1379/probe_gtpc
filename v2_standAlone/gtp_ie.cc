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

#include "gtp_ie.h"


DecodedMsg :: DecodedMsg() {
   imsi_present=0;
   teid_d_present=teid_c_present=0;
   nsapi_present=apn_present=addr1_present=addr2_present=0;
   msisdn_present=cause_present=ue_addr_present=0;
   src_addr = dst_addr = 0;
}

int DecodeIMSI_IE(unsigned char *p, int pos, int datalen, struct DecodedMsg *pmsg) {
   
   int i;
   
   pmsg->imsi_present=1;
   pmsg->imsi=0;
   
   for(i=0; i<8; i++) {
      pmsg->imsi *= 100;
      
      int d1 = p[pos+i+1]&0x0f;
      int d2 = (p[pos+i+1]&0xf0)/16;
      
      if(d1!=15) pmsg->imsi += 10*d1;
      if(d2!=15) pmsg->imsi += d2 ;
   }
   
   printf("IMSI: %llu\n", pmsg->imsi);
   
   return pos + 9;
}


int DecodeMSISDN_IE(unsigned char *p, int pos, int datalen, struct DecodedMsg *pmsg) {
   
   int i;
   
   int len = p[pos+1]*256 + p[pos+2];
   
   pmsg->msisdn_present=1;
   pmsg->msisdn=0;
   
   for(i=0; i<len-1; i++) {
      pmsg->msisdn *= 100;
      
      int d1 = p[pos+i+4]&0x0f;
      int d2 = (p[pos+i+4]&0xf0)/16;
      
      if(d1!=15) pmsg->msisdn += 10*d1;
      if(d2!=15) pmsg->msisdn += d2 ;
   }
   
   printf("MSISDN: %llu\n", pmsg->msisdn);
   
   return pos + 3 + len;
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

   // printf("IE: %i\n", p[pos]);
   
   int ie = p[pos];
   
   switch (ie) {
   
      case 1:
      	 // cause
	 pmsg->cause_present = 1;
	 pmsg->cause = p[pos+1];
	 printf("Cause %u\n", pmsg->cause);
	 return pos+2;
   
      case 2:
      	 // IMSI
      	 return DecodeIMSI_IE(p, pos, datalen, pmsg);

      case 8:
         printf("Reordering required %i\n", p[pos+1]&1);
	 return pos+2;
   
      case 15:
      	 // APN selection mode	 
	 return pos+2;

      case 16:
      	 // TEID_d
	 pmsg->teid_d_present = 1;
	 pmsg->teid_d = ReadInt(p, pos+1);
	 
	 printf("teid dataI 0x%x\n", pmsg->teid_d);
	 return pos+5;      
	 
      case 17:
      	 // TEID_C	 
	 pmsg->teid_c_present = 1;
	 pmsg->teid_c = ReadInt(p, pos+1);
	 
	 printf("teid C 0x%x\n", pmsg->teid_c);
	 
	 return pos+5;      	 
	 
      case 20:
      	 // NSAPI	 
	 pmsg->nsapi_present = 1;
	 pmsg->nsapi = p[pos+1];
	 
	 printf("nsapi %i\n", pmsg->nsapi);
	 
	 return pos+2;      	 	 	 
	 
      case 26:
      	 // charging charactestistics
	 return pos+3;

      case 127:
      	 // charging id
	 printf("Charging id - skip\n");
	 return pos+5;
	 
      case 128: {
            // IP address type
   	    printf("IP address type\n");
	    int l = p[pos+1]*256 + p[pos+2];
	    if(l==2) {
	       printf("empty address\n");
               return pos+3+l;
	    }
	    
	    if(l!=6) {
	       printf("ERROR Uknown address type\n");
               return pos+3+l;	    
	    }
	    
	    int i;
	    pmsg->ue_addr = 0;
    	    for(i=0; i<4; i++) pmsg->ue_addr = pmsg->ue_addr*256 + p[pos+5+i];
	    pmsg->ue_addr_present = 1;
	    unsigned char* c=(unsigned char*)&(pmsg->ue_addr);
	    printf("ue_addr: %i.%i.%i.%i\n", c[3], c[2], c[1], c[0]);
	    
	    return pos+3+l;
	 }
	 
      case 131: {
      	 // apn name
  	    int l=p[pos+1]*256 + p[pos+2];
	    int i=0;
	    int part_len;
	    int j;
	    int c=0;
	    while(i<l) {
	       part_len = p[pos+3+i];
   	       memcpy(pmsg->apn+c, p+pos+4+i, part_len);
	       c+=part_len;

	       i+=part_len+1;
	       if(i<l) pmsg->apn[c++]='.';
	    }
	       
   	    pmsg->apn[c]='\0';
	    printf("apn: %s\n", pmsg->apn);
	    
	    pmsg->apn_present=1;
	    
	    return pos+3+l;	 
	 }
	 
      case 133: {
      	 // PDP context
	 int i;
	 if(pmsg->addr1_present==0) {
      	    pmsg->addr1=0;
	    for(i=0; i<4; i++) pmsg->addr1 = pmsg->addr1*256 + p[pos+3+i];
	    pmsg->addr1_present = 1;
	    unsigned char *c = (unsigned char*)&(pmsg->addr1);
	    printf("addr1: %i.%i.%i.%i\n", c[3], c[2], c[1], c[0]);
	 } else {
       	    pmsg->addr2=0;
	    for(i=0; i<4; i++) pmsg->addr2 = pmsg->addr2*256 + p[pos+3+i];
	    pmsg->addr2_present = 1;
    	    unsigned char *c = (unsigned char*)&(pmsg->addr2);
	    printf("addr2: %i.%i.%i.%i\n", c[3], c[2], c[1], c[0]);
	 }
	    
   	 return pos+7;
      }
	 
      case 134:
	 // msisdn
         return DecodeMSISDN_IE(p, pos, datalen, pmsg);
      
      case 135: {
      	 // qos
         int l=p[pos+1]*256 + p[pos+2];

	 printf("QOS - skip (length=%i)\n", l);
		  
	 return pos+l+3+1;
      }
      
      default:
      	 printf("IE not decoded: %i\n", ie);
      	 return datalen;
   }
   
   return 0;

}
