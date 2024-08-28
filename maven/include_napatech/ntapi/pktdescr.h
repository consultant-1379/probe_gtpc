// $Id: pktdescr.h 17009 2012-01-24 12:56:00Z ml $
/*
 * Copyright 2012 Napatech A/S. All rights reserved.
 * CONFIDENTIAL INFORMATION.
 * 
 * 1. Copying, modification, and distribution of this file, or executable
 * versions of the file, is governed by the terms of the agreement (such
 * as an SCLA or NDA) under which the file was made available. If no such
 * agreement is currently in force between You and Napatech A/S, you may
 * not copy, modify, or distribute this file.
 * 
 * 2. This source code is confidential information of Napatech A/S, and
 * as such, may not be distributed, except to or within Napatech A/S
 * customers under a current, executed NDA or equivalent confidentiality
 * agreement governing the distribution of confidential information.
 * 
 * 3. Redistributions of source code must retain this copyright notice,
 * list of conditions and the following disclaimer.
 * 
 * THIS SOFTWARE IS PROVIDED BY NAPATECH A/S ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL NAPATECH A/S OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 * This source file contains the packet descriptors available.\n
 * It is <b>not</b> to be used directly but via the @ref PacketMacros.
 */

#ifndef DOXYGEN_INTERNAL_ONLY

#ifndef __PKT_DESCR_H__
#define __PKT_DESCR_H__

// Ensure that the following is packed.
#pragma pack(push, 1)

/**
 * This descriptor is placed in front of all packets being received by the adapter when
 * the adapter is operating in STANDARD or EXTENDED mode. One of the two modes is set
 * when creating packet feeds through NTCI_CreatePacketFeed() API call.
 * Note: The descriptor is used for both RX and TX segments but not all fields apply
 *       in both directions.
 */
typedef struct NtStd0Descr_s
{
  /* Offset 0x00. */
  uint64_t timestamp;             //!< RX & TX - 64 Bit timestamp, type set via NTCI_CreatePacketFeed()
  /* Offset 0x08. */
  uint32_t storedLength:16;       //!< RX & TX - length of stored data including 8 bytes alignment padding
  uint32_t crcError:1;            //!< RX & TX - indicates that the frame has an Ethernet CRC Error
  uint32_t TCPCsumOk:1;           //!< RX & TX - indicates TCP checksum is correct (v40+ FPGA only) (Gen2 v42+ for TX)
  uint32_t UDPCsumOk:1;           //!< RX & TX - indicates UDP checksum is correct (v40+ FPGA only) (Gen2 v42+ for TX)
  uint32_t IPCsumOk:1;            //!< RX & TX - indicates IP checksum is correct  (v40+ FPGA only) (Gen2 v42+ for TX)
  uint32_t txCrcOverride:1;       //!< RX & TX - 0 = do not recalculate CRC, 1 = recalculate the MAC frame CRC
  uint32_t cvError:1;             //!< RX & TX - indicates that this frame had a code violation
  uint32_t rxIgnore:1;            //!< RX Only - used for keep-alive packets, indicates the packet was not received from the wire
  uint32_t frameSliced:1;         //!< RX & TX - indicates that the current frame has been sliced (either soft or hard)
  uint32_t rxPort:5;              //!< RX only - the adapter port that received the current frame
  uint32_t hardSlice:1;           //!< RX & TX - the packet length is longer than the hardware can handle and has been hard sliced
  uint32_t txNow:1;               //!< TX only - 0 = preserve original IFG between frames, 1 = transmit not preserving original IFG
  uint32_t txIgnore:1;            //!< TX only - setting this bit to 1 will prevent the frame from being transmitted
  /* Offset 0x0C. */
  uint32_t wireLength:16;         //!< RX & TX - length of frame on the wire
  uint32_t txPort:5;              //!< RX & TX - the adapter port that should transmit the frame
  uint32_t TCPFrame:1;            //!< RX only - indicates the current frame is TCP (NT v40+ FPGA only)
  uint32_t UDPFrame:1;            //!< RX only - indicates the current frame is UDP (NT v40+ FPGA only)
  uint32_t IPFrame:1;             //!< RX only - indicates the current frame is IP  (NT v40+ FPGA only)
  uint32_t descriptorType:1;      //!< RX & TX - 0 = PCAP or 1 = STANDARD/EXTENDED, must be 1 for TX
  uint32_t extensionLength:3;     //!< RX & TX - extended header length in 8 byte units, must be 0 or 2 for TX
  uint32_t extensionFormat:4;     //!< RX & TX - extension format type
} NtStd0Descr_t;


#define NT_EXTENDED_DESCRIPTOR_07_LENGTH 2
#define NT_EXTENDED_DESCRIPTOR_07_TYPE   7
/**
 * The extended descriptor.
 * This structure is present if the ntservice.ini file has been
 * loaded with PacketDescriptor=Ext7.
 */
typedef struct NtExt7Descr_s
{
  /* 32bit Word0. */
  uint32_t hash:24;                  //!< 23:00 - hash value
  uint32_t hashType:5;               //!< 28:24 - hash type
  uint32_t reserved0:2;              //!< 30:29 - reserved
  uint32_t hashValid:1;              //!< 31 - hash valid, 0 if hash-config is none or inbound frame invalid for hash-calc, otherwise 1
  /* 32bit Word1. */
  uint32_t jumbo:1;                  //!< 00 - jumbo frame, 1 when PktSz > 1518 excluding ISL, VLAN, MPLS encapsulation
  uint32_t broadcastDest:1;          //!< 01 - destination MAC address is broadcast, (DMAC are all ones)
  uint32_t l4PortType:4;             //!< 05:02 - layer 4 port type, see ext07_Layer4PortType_t
  uint32_t l4FrameType:4;            //!< 09:06 - layer 4 frame type, see ext07_Layer4FrameType_t
  uint32_t l3FrameType:3;            //!< 12:10 - layer 3 type, 0 = IPv4, 1 = IPv6, 2 = IPX, 3 = other
  uint32_t l2FrameType:2;            //!< 14:13 - layer 2 type, 0 = EtherII, 1 = LLC, 2 = SNAP, 3 = Novell RAW)
  uint32_t l4Size:4;                 //!< 18:15 - layer 4 header length (in units of 32 bits). Note: Valid for L4 = TCP and UDP only
  uint32_t l3Size:7;                 //!< 25:19 - layer 3 header length (in units of 32 bits). Note: Valid for L3 = IPv4 and IPv6
  uint32_t mplsCount:3;              //!< 28:26 - number of MPLS shim labels present
  uint32_t vlanCount:2;              //!< 30:29 - Number of VLANs present
  uint32_t islPresent:1;             //!< 31 - ISL encapsulation present
  /* 32bit Word2. */
  uint32_t reserved1:14;             //!< 13:00 - reserved
  uint32_t txTsInject:1;             //!< 14 - injects TX timestamp. Note: The offset where the timestamp should be injected is located at txTsInjectOffset/layer5HeaderOffset
  uint32_t udptcpChecksumOverride:1; //!< 15 - this bit requests that the TX function overrides (recalculates) the UDP/TCP checksum
  uint32_t ipChecksumOverride:1;     //!< 16 - this bit requests that the TX function overrides (recalculates) the IP checksum
  uint32_t frameProtSmall:1;         //!< 17 - frame is "protocol small"
  uint32_t frameLarge:1;             //!< 18 - large frame, 1 when PktSz > MaxFrameSize set in ntservice.ini
  uint32_t frameSmall:1;             //!< 19 - small frame, 1 when PktSz < 64 (+ISL and/or VLAN)
  uint32_t ipv6FragmentHeader:1;     //!< 20 - IPv6 fragment header present
  uint32_t ipv6RoutingHeader:1;      //!< 21 - IPv6 routing header present
  uint32_t l4ProtocolNumber:8;       //!< 29:22 - layer 4 protocol number (TCP, UDP, SCTP etc.)
  uint32_t l3Fragmented:1;           //!< 30 - layer 3 fragmented frame (only valid for IPv4 if more fragments bit = 1 or fragment offset not equal to 0)
  uint32_t l3FirstFragment:1;        //!< 31 - layer 3 first fragment, (offset = 0) Note: Only valid for IPv4. This bit is always set on IPv6. IPv6 uses the ipv6FragmentHeader.
  /* 32bit Word3. */
  uint32_t color:6;                  //!< 05:00 - color
  uint32_t reserved3:1;              //!< 06 - reserved
#define txTsInjectOffset layer5HeaderOffset
uint32_t layer5HeaderOffset:9;     //!< 15:07 - RX: Layer 5 offset in the packet. The offset is from the end of the extension header. Note: Valid when layer is TCP/UDP and L3 is IPv4 or IPv6, otherwise 0. TX: TX timestamp inject offset. If bit 1 of word 1 is set, this is the offset where the adapter will inject a timestamp on TX
  uint32_t udptcpHeaderOffset:9;     //! 24:16 - offset to the layer 4 header, where offset is from the end of the extension header
  uint32_t ipHeaderOffset:7;         //! 31:25 - offset to the layer 3 header, where offset is from the end of the extension header
} NtExt7Descr_t;

/**
 * The descriptors have the following layout.
 */
// Ensures that the following is packed.
typedef struct NtPktDescr_s {
  struct NtStd0Descr_s std;    //!< Standard descriptor v0
  union {
    struct NtExt7Descr_s ext7; //!< Only valid for extended descriptor format 7
  } u;
} NtPktDescr_t;

// Disable 1 packing.
#pragma pack(pop)

/**
 * Segment macros
 */
#define _NT_NET_GET_SEGMENT_PTR(_hNetBuf_)              (_hNetBuf_->hHdr)
#define _NT_NET_GET_SEGMENT_LENGTH(_hNetBuf_)           (_hNetBuf_->length)
#define _NT_NET_GET_SEGMENT_TIMESTAMP(_hNetBuf_)        (*((uint64_t*)_hNetBuf_->hHdr))
#define _NT_NET_GET_SEGMENT_TIMESTAMP_TYPE(_hNetBuf_)   (_hNetBuf_->tsType)
#define _NT_NET_SET_SEGMENT_LENGTH(_hNetBuf_, _length_) do{_hNetBuf_->length=_length_;}while(0)

/**
 * Generic standard descriptor based macros.
 */

#define _NT_NET_GET_PKT_DESCRIPTOR_TYPE(_hNetBuf_)    ((((NtPktDescr_t*)_hNetBuf_->hHdr)->std.descriptorType==0)?NT_PACKET_DESCRIPTOR_TYPE_PCAP:((NtPktDescr_t*)_hNetBuf_->hHdr)->std.extensionFormat==0?NT_PACKET_DESCRIPTOR_TYPE_NT:NT_PACKET_DESCRIPTOR_TYPE_NT_EXTENDED)

#define _NT_NET_GET_PKT_DESCR(_hNetBuf_)              ((NtPktDescr_t*)_hNetBuf_->hHdr)
#define _NT_NET_GET_PKT_DESCR_LENGTH(_hNetBuf_)       (sizeof(struct NtStd0Descr_s)+(((NtPktDescr_t*)_hNetBuf_->hHdr)->std.extensionLength<<3))
#define _NT_NET_GET_PKT_TIMESTAMP(_hNetBuf_)          (((NtPktDescr_t*)_hNetBuf_->hHdr)->std.timestamp)
#define _NT_NET_GET_PKT_TIMESTAMP_TYPE(_hNetBuf_)     (_hNetBuf_->tsType)
#define _NT_NET_GET_PKT_CAP_LENGTH(_hNetBuf_)         (((NtPktDescr_t*)_hNetBuf_->hHdr)->std.storedLength)
#define _NT_NET_GET_PKT_WIRE_LENGTH(_hNetBuf_)        (((NtPktDescr_t*)_hNetBuf_->hHdr)->std.wireLength)
#define _NT_NET_GET_PKT_L2_PTR(_hNetBuf_)             ((NtPktDescr_t*)_hNetBuf_->hPkt)
#define _NT_NET_UPDATE_PKT_L2_PTR(_hNetBuf_)          ((_hNetBuf_->hPkt)=(void*)((uint8_t*)(_hNetBuf_->hHdr)+_NT_NET_GET_PKT_DESCR_LENGTH(_hNetBuf_)))

#define _NT_NET_GET_PKT_CRC_ERROR(_hNetBuf_)          (((NtPktDescr_t*)_hNetBuf_->hHdr)->std.crcError)
#define _NT_NET_GET_PKT_TCP_CSUM_OK(_hNetBuf_)        (((NtPktDescr_t*)_hNetBuf_->hHdr)->std.TCPCsumOk)
#define _NT_NET_GET_PKT_UDP_CSUM_OK(_hNetBuf_)        (((NtPktDescr_t*)_hNetBuf_->hHdr)->std.UDPCsumOk)
#define _NT_NET_GET_PKT_IP_CSUM_OK(_hNetBuf_)         (((NtPktDescr_t*)_hNetBuf_->hHdr)->std.IPCsumOk)
#define _NT_NET_GET_PKT_CV_ERROR(_hNetBuf_)           (((NtPktDescr_t*)_hNetBuf_->hHdr)->std.cvError)
#define _NT_NET_GET_PKT_SLICED(_hNetBuf_)             (((NtPktDescr_t*)_hNetBuf_->hHdr)->std.frameSliced)
#define _NT_NET_GET_PKT_HARD_SLICED(_hNetBuf_)        (((NtPktDescr_t*)_hNetBuf_->hHdr)->std.hardSlice)
#define _NT_NET_GET_PKT_RXPORT(_hNetBuf_)             ((((NtPktDescr_t*)_hNetBuf_->hHdr)->std.rxPort+_hNetBuf_->portOffset))
#define _NT_NET_GET_PKT_CALC_L2_CRC(_hNetBuf_)        (((NtPktDescr_t*)_hNetBuf_->hHdr)->std.txCrcOverride)
#define _NT_NET_GET_PKT_TXNOW(_hNetBuf_)              (((NtPktDescr_t*)_hNetBuf_->hHdr)->std.txNow)
#define _NT_NET_GET_PKT_TXIGNORE(_hNetBuf_)           (((NtPktDescr_t*)_hNetBuf_->hHdr)->std.txIgnore)
#define _NT_NET_GET_PKT_IS_TCP(_hNetBuf_)             (((NtPktDescr_t*)_hNetBuf_->hHdr)->std.TCPFrame)
#define _NT_NET_GET_PKT_IS_UDP(_hNetBuf_)             (((NtPktDescr_t*)_hNetBuf_->hHdr)->std.UDPFrame)
#define _NT_NET_GET_PKT_IS_IP(_hNetBuf_)              (((NtPktDescr_t*)_hNetBuf_->hHdr)->std.IPFrame)

#define _NT_NET_GET_PKT_TXPORT(_hNetBuf_)             (_hNetBuf_->egressPort==-1?(((NtPktDescr_t*)_hNetBuf_->hHdr)->std.txPort+_hNetBuf_->portOffset):_hNetBuf_->egressPort)

#define _NT_NET_SET_PKT_CLEAR_DESCR_EXT7(_hNetBuf_)     do{memset(_hNetBuf_->hHdr,0,sizeof(struct NtStd0Descr_s)+(NT_EXTENDED_DESCRIPTOR_07_LENGTH<<3));}while(0)
#define _NT_NET_SET_PKT_DESCR_TYPE_EXT7(_hNetBuf_)      do{((NtPktDescr_t*)_hNetBuf_->hHdr)->std.descriptorType=1;((NtPktDescr_t*)_hNetBuf_->hHdr)->std.extensionFormat=NT_EXTENDED_DESCRIPTOR_07_TYPE;((NtPktDescr_t*)_hNetBuf_->hHdr)->std.extensionLength=NT_EXTENDED_DESCRIPTOR_07_LENGTH;}while(0)
#define _NT_NET_SET_PKT_CAP_LENGTH(_hNetBuf_,_Length_)  do{((NtPktDescr_t*)_hNetBuf_->hHdr)->std.storedLength=((_Length_+(((NtPktDescr_t*)_hNetBuf_->hHdr)->std.extensionLength<<3)+sizeof(struct NtStd0Descr_s)+7)&~7);}while(0)
#define _NT_NET_SET_PKT_WIRE_LENGTH(_hNetBuf_,_Length_) do{((NtPktDescr_t*)_hNetBuf_->hHdr)->std.wireLength=_Length_;}while(0)
#define _NT_NET_SET_PKT_TXPORT(_hNetBuf_,_Port_)        do{((NtPktDescr_t*)_hNetBuf_->hHdr)->std.txPort=(_Port_-_hNetBuf_->portOffset);}while(0)

#define _NT_NET_SET_PKT_CALC_L2_CRC(_hNetBuf_, _bval_) do{((NtPktDescr_t*)_hNetBuf_->hHdr)->std.txCrcOverride=_bval_;}while(0)
#define _NT_NET_SET_PKT_TIMESTAMP(_hNetBuf_, _ts_)     do{((NtPktDescr_t*)_hNetBuf_->hHdr)->std.timestamp=_ts_;}while(0)
#define _NT_NET_SET_PKT_TXNOW(_hNetBuf_, _bval_)       do{((NtPktDescr_t*)_hNetBuf_->hHdr)->std.txNow=_bval_;}while(0)
#define _NT_NET_SET_PKT_TXIGNORE(_hNetBuf_, _bval_)    do{((NtPktDescr_t*)_hNetBuf_->hHdr)->std.txIgnore=_bval_;}while(0)
#define _NT_NET_SET_PKT_IS_IP(_hNetBuf_, _bval_)       do{((NtPktDescr_t*)_hNetBuf_->hHdr)->std.IPFrame=_bval_;}while(0)
#define _NT_NET_SET_PKT_IS_UDP(_hNetBuf_, _bval_)      do{((NtPktDescr_t*)_hNetBuf_->hHdr)->std.UDPFrame=_bval_;}while(0)
#define _NT_NET_SET_PKT_IS_TCP(_hNetBuf_, _bval_)      do{((NtPktDescr_t*)_hNetBuf_->hHdr)->std.TCPFrame=_bval_;}while(0)
#define _NT_NET_SET_PKT_CRC_ERROR(_hNetBuf_, _bval_)   do{((NtPktDescr_t*)_hNetBuf_->hHdr)->std.crcError=_bval_;}while(0)
#define _NT_NET_SET_PKT_TCP_CSUM_OK(_hNetBuf_, _bval_) do{((NtPktDescr_t*)_hNetBuf_->hHdr)->std.TCPCsumOk=_bval_;}while(0)
#define _NT_NET_SET_PKT_UDP_CSUM_OK(_hNetBuf_, _bval_) do{((NtPktDescr_t*)_hNetBuf_->hHdr)->std.UDPCsumOk=_bval_;}while(0)
#define _NT_NET_SET_PKT_IP_CSUM_OK(_hNetBuf_, _bval_)  do{((NtPktDescr_t*)_hNetBuf_->hHdr)->std.IPCsumOk=_bval_;}while(0)

/**
 * Extended descriptor type 7 macros
 */
#define _NT_NET_GET_PKT_HASH_7(_hNetBuf_)             (((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.hash)
#define _NT_NET_GET_PKT_HASH_TYPE_7(_hNetBuf_)        (((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.hashType)
#define _NT_NET_GET_PKT_HASH_VALID_7(_hNetBuf_)       (((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.hashValid)
#define _NT_NET_GET_PKT_JUMBO_7(_hNetBuf_)            (((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.jumbo)
#define _NT_NET_GET_PKT_BROADCAST_7(_hNetBuf_)        (((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.broadcastDest)
#define _NT_NET_GET_PKT_L4_PORT_TYPE_7(_hNetBuf_)     (((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.l4PortType)
#define _NT_NET_GET_PKT_L4_FRAME_TYPE_7(_hNetBuf_)    (((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.l4FrameType)
#define _NT_NET_GET_PKT_L3_FRAME_TYPE_7(_hNetBuf_)    (((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.l3FrameType)
#define _NT_NET_GET_PKT_L2_FRAME_TYPE_7(_hNetBuf_)    (((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.l2FrameType)
#define _NT_NET_GET_PKT_L4_LENGTH_7(_hNetBuf_)        (((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.l4Size)
#define _NT_NET_GET_PKT_L3_LENGTH_7(_hNetBuf_)        (((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.l3Size)
#define _NT_NET_GET_PKT_MPLS_COUNT_7(_hNetBuf_)       (((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.mplsCount)
#define _NT_NET_GET_PKT_VLAN_COUNT_7(_hNetBuf_)       (((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.vlanCount)
#define _NT_NET_GET_PKT_ISL_7(_hNetBuf_)              (((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.islPresent)
#define _NT_NET_GET_PKT_PROT_SMALL_7(_hNetBuf_)       (((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.frameProtSmall)
#define _NT_NET_GET_PKT_FRAME_LARGE_7(_hNetBuf_)      (((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.frameLarge)
#define _NT_NET_GET_PKT_FRAME_SMALL_7(_hNetBuf_)      (((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.frameSmall)
#define _NT_NET_GET_PKT_IPV6_FR_HEADER_7(_hNetBuf_)   (((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.ipv6FragmentHeader)
#define _NT_NET_GET_PKT_IPV6_RT_HEADER_7(_hNetBuf_)   (((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.ipv6RoutingHeader)
#define _NT_NET_GET_PKT_L4_PROTOCOL_NUM_7(_hNetBuf_)  (((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.l4ProtocolNumber)
#define _NT_NET_GET_PKT_L3_FRAGMENTED_7(_hNetBuf_)    (((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.l3Fragmented)
#define _NT_NET_GET_PKT_L3_FIRST_FRAG_7(_hNetBuf_)    (((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.l3FirstFragment)
#define _NT_NET_GET_PKT_COLOR_7(_hNetBuf_)            (_hNetBuf_->colorMap[((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.color])
#define _NT_NET_GET_PKT_L5_OFFSET_7(_hNetBuf_)        (((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.layer5HeaderOffset)
#define _NT_NET_GET_PKT_L4_OFFSET_7(_hNetBuf_)        (((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.udptcpHeaderOffset)
#define _NT_NET_GET_PKT_L3_OFFSET_7(_hNetBuf_)        (((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.ipHeaderOffset)

#define _NT_NET_SET_PKT_INJECT_TIMESTAMP_7(_hNetBuf_, _offset_) do{((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.txTsInject=1;((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.txTsInjectOffset=_offset_;}while(0)
#define _NT_NET_SET_PKT_ISL_7(_hNetBuf_, _bval_)                do{((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.islPresent=_bval_;}while(0)
#define _NT_NET_SET_PKT_VLAN_COUNT_7(_hNetBuf_, _count_)        do{((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.vlanCount=_count_;}while(0)
#define _NT_NET_SET_PKT_MPLS_COUNT_7(_hNetBuf_, _count_)        do{((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.mplsCount=_count_;}while(0)
#define _NT_NET_SET_PKT_L2_FRAME_TYPE_7(_hNetBuf_, _type_)      do{((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.l2FrameType=_type_;}while(0)
#define _NT_NET_SET_PKT_L3_FRAME_TYPE_7(_hNetBuf_, _type_)      do{((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.l3FrameType=_type_;}while(0)
#define _NT_NET_SET_PKT_L4_FRAME_TYPE_7(_hNetBuf_, _type_)      do{((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.l4FrameType=_type_;}while(0)
#define _NT_NET_SET_PKT_L3_OFFSET_7(_hNetBuf_, _offset_)        do{((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.ipHeaderOffset=_offset_;}while(0)
#define _NT_NET_SET_PKT_L4_OFFSET_7(_hNetBuf_, _offset_)        do{((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.udptcpHeaderOffset=_offset_;}while(0)
#define _NT_NET_SET_PKT_L3_LENGTH_7(_hNetBuf_, _u32len_)        do{((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.l3Size=_u32len_;}while(0)
#define _NT_NET_SET_PKT_L4_LENGTH_7(_hNetBuf_, _u32len_)        do{((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.l4Size=_u32len_;}while(0)
#define _NT_NET_SET_PKT_CALC_L3_CHECKSUM_7(_hNetBuf_, _bval_)   do{((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.ipChecksumOverride=_bval_;}while(0)
#define _NT_NET_SET_PKT_CALC_L4_CHECKSUM_7(_hNetBuf_, _bval_)   do{((NtPktDescr_t*)_hNetBuf_->hHdr)->u.ext7.udptcpChecksumOverride=_bval_;}while(0)

// If _NTAPI_EXTDESCR_7_ has been set use _NET_xxx_7 macros for extended descriptor info
#if defined(_NTAPI_EXTDESCR_7_)

#define _NT_NET_GET_PKT_HASH(_hNetBuf_)                _NT_NET_GET_PKT_HASH_7(_hNetBuf_)
#define _NT_NET_GET_PKT_HASH_TYPE(_hNetBuf_)           _NT_NET_GET_PKT_HASH_TYPE_7(_hNetBuf_)
#define _NT_NET_GET_PKT_HASH_VALID(_hNetBuf_)          _NT_NET_GET_PKT_HASH_VALID_7(_hNetBuf_)
#define _NT_NET_GET_PKT_JUMBO(_hNetBuf_)               _NT_NET_GET_PKT_JUMBO_7(_hNetBuf_)
#define _NT_NET_GET_PKT_BROADCAST(_hNetBuf_)           _NT_NET_GET_PKT_BROADCAST_7(_hNetBuf_)
#define _NT_NET_GET_PKT_L4_PORT_TYPE(_hNetBuf_)        _NT_NET_GET_PKT_L4_PORT_TYPE_7(_hNetBuf_)
#define _NT_NET_GET_PKT_L4_FRAME_TYPE(_hNetBuf_)       _NT_NET_GET_PKT_L4_FRAME_TYPE_7(_hNetBuf_)
#define _NT_NET_GET_PKT_L3_FRAME_TYPE(_hNetBuf_)       _NT_NET_GET_PKT_L3_FRAME_TYPE_7(_hNetBuf_)
#define _NT_NET_GET_PKT_L2_FRAME_TYPE(_hNetBuf_)       _NT_NET_GET_PKT_L2_FRAME_TYPE_7(_hNetBuf_)
#define _NT_NET_GET_PKT_L4_LENGTH(_hNetBuf_)           _NT_NET_GET_PKT_L4_LENGTH_7(_hNetBuf_)
#define _NT_NET_GET_PKT_L3_LENGTH(_hNetBuf_)           _NT_NET_GET_PKT_L3_LENGTH_7(_hNetBuf_)
#define _NT_NET_GET_PKT_MPLS_COUNT(_hNetBuf_)          _NT_NET_GET_PKT_MPLS_COUNT_7(_hNetBuf_)
#define _NT_NET_GET_PKT_VLAN_COUNT(_hNetBuf_)          _NT_NET_GET_PKT_VLAN_COUNT_7(_hNetBuf_)
#define _NT_NET_GET_PKT_ISL(_hNetBuf_)                 _NT_NET_GET_PKT_ISL_7(_hNetBuf_)
#define _NT_NET_GET_PKT_PROT_SMALL(_hNetBuf_)          _NT_NET_GET_PKT_PROT_SMALL_7(_hNetBuf_)
#define _NT_NET_GET_PKT_FRAME_LARGE(_hNetBuf_)         _NT_NET_GET_PKT_FRAME_LARGE_7(_hNetBuf_)
#define _NT_NET_GET_PKT_FRAME_SMALL(_hNetBuf_)         _NT_NET_GET_PKT_FRAME_SMALL_7(_hNetBuf_)
#define _NT_NET_GET_PKT_IPV6_FR_HEADER(_hNetBuf_)      _NT_NET_GET_PKT_IPV6_FR_HEADER_7(_hNetBuf_)
#define _NT_NET_GET_PKT_IPV6_RT_HEADER(_hNetBuf_)      _NT_NET_GET_PKT_IPV6_RT_HEADER_7(_hNetBuf_)
#define _NT_NET_GET_PKT_L4_PROTOCOL_NUM(_hNetBuf_)     _NT_NET_GET_PKT_L4_PROTOCOL_NUM_7(_hNetBuf_)
#define _NT_NET_GET_PKT_L3_FRAGMENTED(_hNetBuf_)       _NT_NET_GET_PKT_L3_FRAGMENTED_7(_hNetBuf_)
#define _NT_NET_GET_PKT_L3_FIRST_FRAG(_hNetBuf_)       _NT_NET_GET_PKT_L3_FIRST_FRAG_7(_hNetBuf_)
#define _NT_NET_GET_PKT_COLOR(_hNetBuf_)               _NT_NET_GET_PKT_COLOR_7(_hNetBuf_)
#define _NT_NET_GET_PKT_L5_OFFSET(_hNetBuf_)           _NT_NET_GET_PKT_L5_OFFSET_7(_hNetBuf_)
#define _NT_NET_GET_PKT_L4_OFFSET(_hNetBuf_)           _NT_NET_GET_PKT_L4_OFFSET_7(_hNetBuf_)
#define _NT_NET_GET_PKT_L3_OFFSET(_hNetBuf_)           _NT_NET_GET_PKT_L3_OFFSET_7(_hNetBuf_)

#define _NT_NET_SET_PKT_INJECT_TIMESTAMP(_hNetBuf_, _offset_)  _NT_NET_SET_PKT_INJECT_TIMESTAMP_7(_hNetBuf_, _offset_)
#define _NT_NET_SET_PKT_ISL(_hNetBuf_, _bval_)                 _NT_NET_SET_PKT_ISL_7(_hNetBuf_, _bval_)
#define _NT_NET_SET_PKT_VLAN_COUNT(_hNetBuf_, _count_)         _NT_NET_SET_PKT_VLAN_COUNT_7(_hNetBuf_, _count_)
#define _NT_NET_SET_PKT_MPLS_COUNT(_hNetBuf_, _count_)         _NT_NET_SET_PKT_MPLS_COUNT_7(_hNetBuf_, _count_)
#define _NT_NET_SET_PKT_L2_FRAME_TYPE(_hNetBuf_, _type_)       _NT_NET_SET_PKT_L2_FRAME_TYPE_7(_hNetBuf_, _type_)
#define _NT_NET_SET_PKT_L3_FRAME_TYPE(_hNetBuf_, _type_)       _NT_NET_SET_PKT_L3_FRAME_TYPE_7(_hNetBuf_, _type_)
#define _NT_NET_SET_PKT_L4_FRAME_TYPE(_hNetBuf_, _type_)       _NT_NET_SET_PKT_L4_FRAME_TYPE_7(_hNetBuf_, _type_)
#define _NT_NET_SET_PKT_L3_OFFSET(_hNetBuf_, _offset_)         _NT_NET_SET_PKT_L3_OFFSET_7(_hNetBuf_, _offset_)
#define _NT_NET_SET_PKT_L4_OFFSET(_hNetBuf_, _offset_)         _NT_NET_SET_PKT_L4_OFFSET_7(_hNetBuf_, _offset_)
#define _NT_NET_SET_PKT_L3_LENGTH(_hNetBuf_, _u32len_)         _NT_NET_SET_PKT_L3_LENGTH_7(_hNetBuf_, _u32len_)
#define _NT_NET_SET_PKT_L4_LENGTH(_hNetBuf_, _u32len_)         _NT_NET_SET_PKT_L4_LENGTH_7(_hNetBuf_, _u32len_)
#define _NT_NET_SET_PKT_CALC_L3_CHECKSUM(_hNetBuf_, _bval_)    _NT_NET_SET_PKT_CALC_L3_CHECKSUM_7(_hNetBuf_, _bval_)
#define _NT_NET_SET_PKT_CALC_L4_CHECKSUM(_hNetBuf_, _bval_)    _NT_NET_SET_PKT_CALC_L4_CHECKSUM_7(_hNetBuf_, _bval_)

#else
/**
 * Determines on the basis of @ref NtStd0Descr_t::extensionFormat what descriptor macros to use
 */
#if !defined(_NTAPI_EXTDESCR_ALL_)
#ifndef WIN32
#warning No specific extended descriptor has been selected and support for all has been enabled. This will not utilize optimal performance in applications. Use e.g.  _NTAPI_EXTDESCR_7_ if ntservice.ini has PacketDescriptor=Ext7 or use _NTAPI_EXTDESCR_ALL_ to support all extended descriptors.
#endif
#endif

/**
 * Look at the extended descriptor type to determine what macros to use
 */
#define _NT_NET_GET_PKT_HASH(_hNetBuf_)            ((((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)?_NT_NET_GET_PKT_HASH_7(_hNetBuf_):~0)
#define _NT_NET_GET_PKT_HASH_TYPE(_hNetBuf_)       ((((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)?_NT_NET_GET_PKT_HASH_TYPE_7(_hNetBuf_):~0)
#define _NT_NET_GET_PKT_HASH_VALID(_hNetBuf_)      ((((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)?_NT_NET_GET_PKT_HASH_VALID_7(_hNetBuf_):~0)
#define _NT_NET_GET_PKT_JUMBO(_hNetBuf_)           ((((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)?_NT_NET_GET_PKT_JUMBO_7(_hNetBuf_):~0)
#define _NT_NET_GET_PKT_BROADCAST(_hNetBuf_)       ((((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)?_NT_NET_GET_PKT_BROADCAST_7(_hNetBuf_):~0)
#define _NT_NET_GET_PKT_L4_PORT_TYPE(_hNetBuf_)    ((((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)?_NT_NET_GET_PKT_L4_PORT_TYPE_7(_hNetBuf_):~0)
#define _NT_NET_GET_PKT_L4_FRAME_TYPE(_hNetBuf_)   ((((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)?_NT_NET_GET_PKT_L4_FRAME_TYPE_7(_hNetBuf_):~0)
#define _NT_NET_GET_PKT_L3_FRAME_TYPE(_hNetBuf_)   ((((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)?_NT_NET_GET_PKT_L3_FRAME_TYPE_7(_hNetBuf_):~0)
#define _NT_NET_GET_PKT_L2_FRAME_TYPE(_hNetBuf_)   ((((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)?_NT_NET_GET_PKT_L2_FRAME_TYPE_7(_hNetBuf_):~0)
#define _NT_NET_GET_PKT_L4_LENGTH(_hNetBuf_)       ((((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)?_NT_NET_GET_PKT_L4_LENGTH_7(_hNetBuf_):~0)
#define _NT_NET_GET_PKT_L3_LENGTH(_hNetBuf_)       ((((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)?_NT_NET_GET_PKT_L3_LENGTH_7(_hNetBuf_):~0)
#define _NT_NET_GET_PKT_MPLS_COUNT(_hNetBuf_)      ((((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)?_NT_NET_GET_PKT_MPLS_COUNT_7(_hNetBuf_):~0)
#define _NT_NET_GET_PKT_VLAN_COUNT(_hNetBuf_)      ((((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)?_NT_NET_GET_PKT_VLAN_COUNT_7(_hNetBuf_):~0)
#define _NT_NET_GET_PKT_ISL(_hNetBuf_)             ((((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)?_NT_NET_GET_PKT_ISL_7(_hNetBuf_):~0)
#define _NT_NET_GET_PKT_PROT_SMALL(_hNetBuf_)      ((((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)?_NT_NET_GET_PKT_PROT_SMALL_7(_hNetBuf_):~0)
#define _NT_NET_GET_PKT_FRAME_LARGE(_hNetBuf_)     ((((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)?_NT_NET_GET_PKT_FRAME_LARGE_7(_hNetBuf_):~0)
#define _NT_NET_GET_PKT_FRAME_SMALL(_hNetBuf_)     ((((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)?_NT_NET_GET_PKT_FRAME_SMALL_7(_hNetBuf_):~0)
#define _NT_NET_GET_PKT_IPV6_FR_HEADER(_hNetBuf_)  ((((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)?_NT_NET_GET_PKT_IPV6_FR_HEADER_7(_hNetBuf_):~0)
#define _NT_NET_GET_PKT_IPV6_RT_HEADER(_hNetBuf_)  ((((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)?_NT_NET_GET_PKT_IPV6_RT_HEADER_7(_hNetBuf_):~0)
#define _NT_NET_GET_PKT_L4_PROTOCOL_NUM(_hNetBuf_) ((((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)?_NT_NET_GET_PKT_L4_PROTOCOL_NUM_7(_hNetBuf_):~0)
#define _NT_NET_GET_PKT_L3_FRAGMENTED(_hNetBuf_)   ((((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)?_NT_NET_GET_PKT_L3_FRAGMENTED_7(_hNetBuf_):~0)
#define _NT_NET_GET_PKT_L3_FIRST_FRAG(_hNetBuf_)   ((((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)?_NT_NET_GET_PKT_L3_FIRST_FRAG_7(_hNetBuf_):~0)
#define _NT_NET_GET_PKT_COLOR(_hNetBuf_)           ((((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)?_NT_NET_GET_PKT_COLOR_7(_hNetBuf_):~0)
#define _NT_NET_GET_PKT_L5_OFFSET(_hNetBuf_)       ((((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)?_NT_NET_GET_PKT_L5_OFFSET_7(_hNetBuf_):~0)
#define _NT_NET_GET_PKT_L4_OFFSET(_hNetBuf_)       ((((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)?_NT_NET_GET_PKT_L4_OFFSET_7(_hNetBuf_):~0)
#define _NT_NET_GET_PKT_L3_OFFSET(_hNetBuf_)       ((((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)?_NT_NET_GET_PKT_L3_OFFSET_7(_hNetBuf_):~0)

#define _NT_NET_SET_PKT_INJECT_TIMESTAMP(_hNetBuf_, _offset_)  do{if(((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)_NT_NET_SET_PKT_INJECT_TIMESTAMP_7(_hNetBuf_, _offset_);}while(0)
#define _NT_NET_SET_PKT_ISL(_hNetBuf_, _bval_)                 do{if(((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)_NT_NET_SET_PKT_ISL_7(_hNetBuf_, _bval_);}while(0)
#define _NT_NET_SET_PKT_VLAN_COUNT(_hNetBuf_, _count_)         do{if(((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)_NT_NET_SET_PKT_VLAN_COUNT_7(_hNetBuf_, _count_);}while(0)
#define _NT_NET_SET_PKT_MPLS_COUNT(_hNetBuf_, _count_)         do{if(((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)_NT_NET_SET_PKT_MPLS_COUNT_7(_hNetBuf_, _count_);}while(0)
#define _NT_NET_SET_PKT_L2_FRAME_TYPE(_hNetBuf_, _type_)       do{if(((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)_NT_NET_SET_PKT_L2_FRAME_TYPE_7(_hNetBuf_, _type_);}while(0)
#define _NT_NET_SET_PKT_L3_FRAME_TYPE(_hNetBuf_, _type_)       do{if(((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)_NT_NET_SET_PKT_L3_FRAME_TYPE_7(_hNetBuf_, _type_);}while(0)
#define _NT_NET_SET_PKT_L4_FRAME_TYPE(_hNetBuf_, _type_)       do{if(((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)_NT_NET_SET_PKT_L4_FRAME_TYPE_7(_hNetBuf_, _type_);}while(0)
#define _NT_NET_SET_PKT_L3_OFFSET(_hNetBuf_, _offset_)         do{if(((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)_NT_NET_SET_PKT_L3_OFFSET_7(_hNetBuf_, _offset_);}while(0)
#define _NT_NET_SET_PKT_L4_OFFSET(_hNetBuf_, _offset_)         do{if(((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)_NT_NET_SET_PKT_L4_OFFSET_7(_hNetBuf_, _offset_);}while(0)
#define _NT_NET_SET_PKT_L3_LENGTH(_hNetBuf_, _u32len_)         do{if(((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)_NT_NET_SET_PKT_L3_LENGTH_7(_hNetBuf_, _u32len_);}while(0)
#define _NT_NET_SET_PKT_L4_LENGTH(_hNetBuf_, _u32len_)         do{if(((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)_NT_NET_SET_PKT_L4_LENGTH_7(_hNetBuf_, _u32len_);}while(0)
#define _NT_NET_SET_PKT_CALC_L3_CHECKSUM(_hNetBuf_, _bval_)    do{if(((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)_NT_NET_SET_PKT_CALC_L3_CHECKSUM_7(_hNetBuf_, _bval_);}while(0)
#define _NT_NET_SET_PKT_CALC_L4_CHECKSUM(_hNetBuf_, _bval_)    do{if(((NtStd0Descr_t*)_hNetBuf_->hHdr)->extensionFormat==7)_NT_NET_SET_PKT_CALC_L4_CHECKSUM_7(_hNetBuf_, _bval_);}while(0)

#endif // _NTAPI_EXTDESCR_7_

#endif /* __PKT_DESCR_H__ */

#endif // DOXYGEN_INTERNAL_ONLY
