CC=g++
CXX=g++

CCFLAGS = -g -D_TRACE -DCCP -DASN1RT -DGNU -D_GNU_SOURCE -I. -Wall

CPPFLAGS = -g -std=c++0x

extobj =  

OBJ = gtpv1.o gtp_ie.o GTPv1_packetFields.o gtpv1_utils.o gtpv2_main.o gtp_ie_gtpv2.o ArgProcessor.o 

DEPS = 

LIBS = -lpcap -lcrypto -L./lib -lmagicstring

all: gtpv1        
.PHONY : all        
        
clean:
	\rm -f *.o gtpv1

gtpv1: $(objects) $(OBJ)
	$(CXX) $(CCFLAGS) -o gtpv1 $(OBJ) $(LIBS)
