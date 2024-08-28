
void SetLog(bool);

struct FTEID {
   unsigned int addr;
   unsigned int teid;
   
   FTEID() {
      addr=0;
      teid=0;
   }
   
   void print() {
   	unsigned char *a = (unsigned char*)&addr;
	printf("FTEID: %i.%i.%i.%i %0x\n", a[3],a[2],a[1],a[0],teid);
	
   }
   
};


class Bearer {

 public: 
    Bearer();
    
    int present;
    FTEID fteid[16];
};


class DecodedMsg {

 public:
 
   DecodedMsg();

   double timestamp;
   
   unsigned long src_addr; // from ip addr fields 
   unsigned long dst_addr;
   
   char imsi_present;
   unsigned long long int imsi;
   
   unsigned int teid;
   
   Bearer bearer[10][16]; // first dimension tells the instance
   
   FTEID fteid[16];
   
   int eps_bearer_id;
      
   // char teid_d_present;
   // unsigned int teid_d;

   // char teid_c_present;
   // unsigned int teid_c;

   // char nsapi_present;
   // unsigned char nsapi;
   
   char delay_value_present;
   int delay_value;
   
   char apn_present;
   char apn[100];
   
   char addr1_present, addr2_present;
   unsigned int addr1, addr2;
   
   char msisdn_present;
   unsigned long long msisdn;
   
   char mei_present;
   unsigned long long mei;
   
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
