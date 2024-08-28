cc=g++

CCFLAGS = -D_TRACE -DCCP -DASN1RT -DGNU -D_GNU_SOURCE -D_OPTIMIZED

CPPFLAGS = -I/perfmon_source/transport/ipmf/libpcap/ -g

#objects = \
#	perfmon_s11_gtpv2.o \
#	gtp_ie_gtpv2.o
	# Source/S1APConverter.o\

#perfmon_s1ap: $(objects)
#	$(cc) -o perfmon_s11_gtpv2 $(objects) $(libasn) -g /perfmon_source/transport/ipmf/libpcap/libpcap.a

OBJ = perfmon_s11_gtpv2.o gtp_ie_gtpv2.o

DEPS = 

LIBS = -lpcap 

%.o: %.c $(DEPS)
	$(cc) -c -o $@ $< perfmon_s11_gtpv2.cc gtp_ie_gtpv2.cc  $(CCFLAGS)
        
all: gtpv2_standAlone        
.PHONY : all        
        
clean:
	\rm -f *.o gtpv2_standAlone

gtpv2_standAlone: $(objects) $(OBJ)
	$(cc) -g -o gtpv2_standAlone $(OBJ) $(CCFLAGS) $(LIBS)