CC=g++
CXXFLAGS=-g -Wall -pedantic -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -Wno-format -Wno-long-long -I.
CXXFLAGS+=-DHAVE_PREAD -DHAVE_PWRITE
CXXFLAGS+=-DUSE_OMEMFILE
CXXFLAGS+=-DSHOW_STATISTICS
CXXFLAGS+=-DHAVE_TPACKET_V3 -DHAVE_TPACKET_V2
#CXXFLAGS+=-DDEBUG_RING
#CXXFLAGS+=-DDEBUG_TRAFFIC

LDFLAGS=
LIBS=

MAKEDEPEND=${CC} -MM
PROGRAM=pktsaver

OBJS = string/buffer.o fs/file.o fs/omemfile.o net/filter.o net/pcap_file.o net/sniffer.o main.o

DEPS:= ${OBJS:%.o=%.d}

all: $(PROGRAM)

${PROGRAM}: ${OBJS}
	${CC} ${CXXFLAGS} ${LDFLAGS} ${OBJS} ${LIBS} -o $@

clean:
	rm -f ${PROGRAM} ${OBJS} ${OBJS} ${DEPS}

${OBJS} ${DEPS} ${PROGRAM} : Makefile

.PHONY : all clean

%.d : %.cpp
	${MAKEDEPEND} ${CXXFLAGS} $< -MT ${@:%.d=%.o} > $@

%.o : %.cpp
	${CC} ${CXXFLAGS} -c -o $@ $<

-include ${DEPS}
