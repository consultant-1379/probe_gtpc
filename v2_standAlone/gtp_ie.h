class DecodedMsg {

 public:
 
   DecodedMsg();

   double timestamp;
   
   unsigned long src_addr; // from ip addr fields 
   unsigned long dst_addr;
   
   char imsi_present;
   unsigned long long int imsi;
   
   unsigned int teid;
   
   char teid_d_present;
   unsigned int teid_d;

   char teid_c_present;
   unsigned int teid_c;

   char nsapi_present;
   unsigned char nsapi;
   
   char apn_present;
   char apn[100];
   
   char addr1_present, addr2_present;
   unsigned int addr1, addr2;
   
   char msisdn_present;
   unsigned long long msisdn;
   
   char cause_present;
   unsigned char cause;
   
   char ue_addr_present;
   unsigned int ue_addr;
};



int DecodeIMSI_IE(unsigned char *p, int pos, int datalen, struct DecodedMsg *pmsg);


int DecodeMSISDN_IE(unsigned char *p, int pos, int datalen, struct DecodedMsg *pmsg);

int DecodePDPContext_IE(unsigned char *p, int pos, int datalen);

unsigned int ReadInt(unsigned char *p, int pos) ;

int DecodeIE(unsigned char *p, int pos, int datalen,struct DecodedMsg *pmsg) ;
