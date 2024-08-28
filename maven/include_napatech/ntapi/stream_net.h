// $Id: stream_net.h 17164 2012-01-31 13:48:16Z ml $
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
 *
 * This is header file of the network stream interface
 */
#ifndef __STREAM_NET_H__
#define __STREAM_NET_H__

#ifdef WIN32
#define INLINE __forceinline
#else
#define INLINE inline
#endif

/** @addtogroup NetworkStream
 *
 * Network streams are used to receive and transmit data packets to
 * and from the adapters. They are an extension build on top of the
 * hardware-based host buffers.
 * Three types of network streams exist:
 * @li @ref StreamRx is used to receive data
 * @li @ref StreamTx is used to transmit data
 * @li @ref StreamFile is used to receive data to a file
 */

/** @addtogroup StreamRx
 * The RX network stream is used for both capture and in-line
 * scenarios. The capture scenarios can deliver packets either
 * packet-by-packet or as segments. The segment delivery is used for
 * store to disk scenarios followed by offline analysis via the
 * file-based network stream.
 *
 * @section PacketInterface Packet Interface
 *
 * The main interface is the packet interface. The packet interface is
 * an interface for applications to do packet-by-packet
 * processing. Please note that this approach will move some CPU load
 * from the application to the driver compared to the segment
 * interface. To open an RX network stream using the packet interface,
 * call the @ref NT_NetRxOpen function with the interface type set to
 * @ref NtNetInterface_e::NT_NET_INTERFACE_PACKET
 * "NT_NET_INTERFACE_PACKET". To receive a packet, call @ref NT_NetRxGet
 * and use the @ref PacketMacros "packet macros" to access the
 * data. When finished with the packet, call @ref NT_NetRxRelease to release
 * it again. When finished with the stream, call @ref NT_NetRxClose to close
 * it.
 *
 * For an example on how to use the packet interface see @ref
 * net/analysis/analysis.c "net/analysis/analysis.c".
 *
 * @section SegmentInterface Segment Interface
 *
 * The segment interface is only intended to be used for writing data
 * to the disc and to do this the application will have to add a file
 * header, provided by the system, to the beginning of the file. To read
 * back data from the file, the application will have to use the
 * @ref StreamFile to open the file and process the saved data packet
 * by packet. To open an RX network stream using the segment interface,
 * call the @ref NT_NetRxOpen function with the interface type set to
 * @ref NtNetInterface_e::NT_NET_INTERFACE_SEGMENT
 * "NT_NET_INTERFACE_SEGMENT". To receive a segment, call @ref NT_NetRxGet
 * and use the @ref SegmentMacros "segment macros" to access the
 * data. When finished with the segment, call @ref NT_NetRxRelease to release
 * it again. When finished with the stream, call @ref NT_NetRxClose to
 * close it.
 *
 * For an example on how to use the segment interface see @ref
 * net/capture/capture.c "net/capture/capture.c".
 *
 * @section DataSharing Data Sharing
 *
 * Data sharing is a feature that will allow multiple applications to
 * access the same shared host buffer.
 *
 * Data sharing is supported at the host buffer level. This allows
 * multiple applications to access the same host buffer, at the
 * same time, and individually decide if they want to use the packet
 * interface or the segment interface. Data sharing is zero copy but
 * will take up some extra CPU power to handle the synchronization of
 * the host buffers. The service daemon is responsible for handling the
 * host buffer exchange with the hardware and the data sharing is
 * transparent to the application.
 *
 * @note Be aware that the slowest application sets the speed. This
 * means that a packet/segment will not be returned to the hardware
 * before all applications that share the host buffer have
 * processed it. To avoid this use @ref MainDocMainFeaturesTraffic_ReceiveHb_HostBufferAllowance
 *
 * @section DataMerging Data Merging
 *
 * Data merging is used for merging data packets received from
 * multiple host buffers into one stream. This feature is used to merge
 * data from multiple ports on multiple adapters, or multiple host buffers from one
 * inline adapter. On entry level adapters, it is used to merge data from multiple ports as these adapters have
 * one host buffer per port. The Napatech Software Suite supports
 * merging of data from up to 42 host buffers, making it possible to
 * merge data from 42 NT adapters or 42 ports on entry level
 * adapters. See the @ref NtplOverview "NTPL" for a
 * description on how to configure data merging.
 *
 * @note Data merging is only possible for packet streams.
 */

/** @addtogroup StreamTx
 * The TX network stream is used for transmitting data. Packets sent
 * via this stream will be interleaved with traffic from in-line
 * streams or other transmit streams.
 *
 * To open a TX network stream, call the @ref NT_NetTxOpen function. To
 * get an empty packet, call the @ref NT_NetTxGet function with the
 * desired length of the packet. The length includes the 4 bytes for
 * the Ethernet CRC. Now fill data into the buffer and use the
 * @ref TxMacros "TX Macros" for setting the desired timestamp, force CRC
 * generation, etc. When finished with the packet, call @ref NT_NetTxRelease
 * to release and transmit it. When finished with the stream, call @ref
 * NT_NetTxClose to close it.
 *
 * @note On entry level adapters, the timestamp is ignored and all packages
 * are sent at line rate.
 *
 * For an example on how to use the packet interface, see @ref
 * net/transmit/transmit.c "net/transmit/transmit.c".
 *
 */

/** @addtogroup StreamFile
 * The File network stream is used for packet-by-packet offline
 * analysis of the packets captured with the segment RX interface. See
 * @ref SegmentInterface "Segment interface" for a description of how
 * to accomplish this.
 *
 * To open a file network stream, call the @ref NT_NetFileOpen with the
 * name of the captured file as argument. To get the next packet from
 * the file network stream, call the @ref NT_NetFileGet. Use the
 * @ref PacketMacros "packet macros" to access the packet data. When
 * finished with the packet, call @ref NT_NetFileRelease to release it
 * again. When finished with the stream, call @ref NT_NetFileClose to close
 * it.
 *
 * For an example on how to use the file network stream interface, see
 * @ref net/replay/replay.c "net/replay/replay.c".
 *
 */

/**
 * The network interface types.
 * Used to select PACKET or NETWORK interface.
 */
enum NtNetInterface_e {
  NT_NET_INTERFACE_UNKNOWN=0, //!< Unknown interface
  NT_NET_INTERFACE_PACKET,    //!< Packet interface
  NT_NET_INTERFACE_SEGMENT    //!< Segment interface
};

#ifndef DOXYGEN_INTERNAL_ONLY
/**
 * Internal structures used in @ref NtNetBuf_s
 */
typedef struct NtNetBufData_s*         NtNetBufData_t; //!< Confidential data
typedef struct NtNetBufPkt_s*          NtNetBufPkt_t;  //!< Packet data
typedef struct NtNetBufHdr_s*          NtNetBufHdr_t;  //!< Header data
#endif

/**
 * This structure is used by the @ref NetworkStream Get/Release functions and provides a handle to the returned data.
 * The layout of the structure is confidential and must only be accessed via @ref DataMacros.
 * The layout of the structure might change between major releases of NTAPI.
 */
typedef struct NtNetBuf_s {
#ifndef DOXYGEN_INTERNAL_ONLY
  int version;                   //!< The version of the NetworkData header
  NtNetBufData_t hData;          //!< A handle to confidential data
  NtNetBufPkt_t hPkt;            //!< A handle to packet data
  NtNetBufHdr_t hHdr;            //!< A handle to header data
  uint32_t length;               //!< Data field length
  enum NtNetInterface_e netIf;   //!< The network interface
  enum NtTimestampType_e tsType; //!< The timestamp type
  int portOffset;                //!< The port offset - used to identify virtual ports
  int adapterNo;                 //!< The adapter from which the data originated
  int egressPort;                //!< The destination port (in-line)
  uint8_t *colorMap;             //!< The filter color map table
#endif
} *NtNetBuf_t;

/** @addtogroup StreamRx
 *@{
 */

/**
 * Possible NetRx stream commands
 */
enum NtNetRxCmd_e {
  NT_NETRX_READ_CMD_UNKNOWN=0,       //!< Unknown read command
  NT_NETRX_READ_CMD_GET_FILE_HEADER, //!< Gets the file header for the stream
  NT_NETRX_READ_CMD_STREAM_DROP,     //!< Returns the drop counters for each stream. The counters increment when packets are dropped because of the hostbuffer allowance (hysteresis) being activated.
};

/**
 *  File header return structure.
 *  Note: This header can only be read once all NTPL assignments have completed.
 */
struct NtNetRxFileHeader_s {
  uint8_t data[128]; //!< The actual file header
};

/**
 * Stream drop counter return structure.
 */
struct NtNetRxStreamDrop_s {
  uint64_t pktsDropped;   //!< Packets dropped because the application is affected by the hostbuffer allowance (hysteresis)
  uint64_t octetsDropped; //!< Bytes dropped because the application is affected by the hostbuffer allowance (hysteresis)
};

/**
 * NetRx structure. Network RX data is read via this structure via @ref NT_NetRxRead().
 */
typedef struct NtNetRx_s {
  enum NtNetRxCmd_e cmd; //!< The read command - specified what to read from NetRx
  /**
   *  Union of all possible return structures from NetRxRead()
  */
  union NtNetRx_u {
    struct NtNetRxFileHeader_s fileheader;  //!< The structure to use for @ref NtNetRx_s::cmd==NT_NETRX_READ_CMD_GET_FILE_HEADER
    struct NtNetRxStreamDrop_s streamDrop;  //!< The structure to use for @ref NtNetRx_s::cmd==NT_NETRX_READ_CMD_STREAM_DROP
  } u ;
} NtNetRx_t;

/**
 * The Network RX stream handle - used for both in-line and capture streams
 */
typedef struct NtNetStreamRx_s* NtNetStreamRx_t;

/**
 * @brief Opens in-line or capture host buffer(s) and returns a NtNetStreamRx_t handle
 *
 * This function is called to retrieve a handle to an in-line or capture network stream.
 * <em>Note:</em> It is important to start calling NT_NetRxGet() and NT_NetRxRelease() soon
 * after this call to avoid packet drop. Host buffers are assigned/released to the streamid within
 * NT_NetRxGet() and NT_NetRxRelease().
 *
 * @param[out] hStream                    Reference to a NtNetStreamRx_t stream pointer.
 * @param[in]  name                       Stream friendly name. Used in, for example, logging statements.
 * @param[in]  netIntf                    Interface type; segment or packet.
 * @param[in]  streamId                   The network stream ID to open. Can be opened a number of times which will cause sharing of the host buffers in the streamId.
 * @param[in]  hostBufferAllowance        Drop level for the hostbuffer allowance (hysteresis) -1 means disabled.
 *
 * @retval  0    Success.
 * @retval !=0   Error.
 */
int NT_NetRxOpen(NtNetStreamRx_t *hStream, const char *name, enum NtNetInterface_e netIntf, uint32_t streamId, int hostBufferAllowance);

/**
 * @brief Gets data from an in-line or capture stream
 *
 * This function is called to retrieve packets/segments from a in-line or capture stream
 *
 * @param[in]    hStream     Network RX stream handle
 * @param[out]   netBuf      Segment/packet container reference
 * @param[in]    timeout     The timeout in milliseconds. The call will return when this timeout is reached unless data is available. A timeout of -1 will wait indefinitely for a new buffer.
 *
 * @note This function has no mutex protection, therefore the same hStream cannot be used by multiple threads
 *
 * @retval  NT_SUCCESS          Data has been returned and must be released again via NT_NetRxRelease()
 * @retval  NT_STATUS_TIMEOUT   No data has been returned and a timeout has occured
 * @retval  NT_STATUS_TRYAGAIN  The resource is temporarily unavailable because of reconfiguration. Call NT_NetRxGet() again.
 * @retval  Error
 */
int NT_NetRxGet(NtNetStreamRx_t hStream, NtNetBuf_t *netBuf, int timeout);

/**
 * @brief Gets data from an in-line or capture stream
 *
 * This function is called to retrieve packets/segments from a in-line or capture stream. The function will
 * automatically release the previous packet when called, hence it is not possible to keep packets and if necessary
 * the packets must be copied to a safe buffer before calling the function to get the next packet.
 *
 * @param[in]    hStream     Network RX stream handle
 * @param[out]   netBuf      Segment/packet container reference
 * @param[in]    timeout     The timeout in milliseconds. The call will return when this timeout is reached unless data is available. A timeout of -1 will wait indefinitely for a new buffer.
 *
 * @note This function has no mutex protection, therefore the same hStream cannot be used by multiple threads
 *
 * @retval  NT_SUCCESS          Data has been returned and will be valid until the next @ref NT_NetRxGetNextPacket() call
 * @retval  NT_STATUS_TIMEOUT   No data has been returned and a timeout has occured
 * @retval  NT_STATUS_TRYAGAIN  The resource is temporarily unavailable because of reconfiguration. Call NT_NetRxGetNextPacket() again.
 * @retval  Error
 */
int NT_NetRxGetNextPacket(NtNetStreamRx_t hStream, NtNetBuf_t *netBuf, int timeout);

/**
 * @brief Reads data from the stream
 *
 * This function will read on-line generated data from the stream, for example, file header
 *
 * @param[in] hStream  NetRx stream handle
 * @param[in] cmd      NetRx read structure
 *
 * @retval  0    Success
 * @retval !=0   Error
 */
int NT_NetRxRead(NtNetStreamRx_t hStream, NtNetRx_t *cmd);


/**
 * @brief Releases network buffer
 *
 * This function will release the netBuf data obtained via NT_RxGet
 *
 * @note This function has no mutex protection, therefore the same hStream cannot be used by multiple threads
 *
 * @param[in] hStream NetRx stream handle
 * @param[in] netBuf  Net buffer received via NT_RxGet
 *
 * @retval  0    Success
 * @retval !=0   Error
 */
int NT_NetRxRelease(NtNetStreamRx_t hStream, NtNetBuf_t netBuf);

/**
 * @brief Closes an in-line or capture stream
 *
 * This function is called to close an in-line or capture stream
 *
 * @param[in] hStream  In-line or capture stream handle to close
 *
 * @retval  0    Success
 * @retval !=0   Error
 */
int NT_NetRxClose(NtNetStreamRx_t hStream);

/** @} */


/** @addtogroup StreamTx
 *@{
 */
/**
 * Network TX stream handle - used for TX streams
 */
typedef struct NtNetStreamTx_s* NtNetStreamTx_t;

/**
 * Network TX packet options
 */
enum NtNetTxPacketOption_e {
  NT_NETTX_PACKET_OPTION_UNKNOWN=0,                         //!< Unknown option
  NT_NETTX_PACKET_OPTION_DEFAULT,                           //!< Gets a TX buffer with a pre-configured packet descriptor. Use this option to transmit L2 data. This option uses packetSize as wire length.
  NT_NETTX_PACKET_OPTION_L2=NT_NETTX_PACKET_OPTION_DEFAULT, //!< Same as default
  NT_NETTX_PACKET_OPTION_RAW,                               //!< Gets a raw TX packet buffer without packet descriptor. Care needs to be taken when using this option. Use this option in replay scenarios where packets already have a correct descriptor, e.g. data recorded using @ref StreamFile. Uses packetSize as the stored length. With this option packetSize must be a multiple of 8.
  NT_NETTX_SEGMENT_OPTION_RAW,                              //!< Gets a raw TX segment buffer. Care needs to be taken when using this option. Use this option in replay scenarios where the segment length is known prior to calling @ref NT_NetTxGet. Use packetSize as the segment length. The port parameter in @ref NT_NetTxGet is used to control that the segment returned belongs to the adapter on which the port resides. It is required that the txPort in the packet descriptors within the segment are set before releasing the segment.
};

/**
 * @brief Opens a TX host buffer and returns a NtNetStreamTx_t handle
 *
 * This function is called to retrieve a TX stream handle.
 * Note that the TX stream on capture-only adapters (NT4E Capture, NT4E_STD Capture ant NT20E Capture)
 * will have very limited transmit capabilities. They will not be able to transmit at line rate
 * and their transmit sizes and statistics will also be limited.
 *
 * @param[out] hStream    Reference to a NtNetStreamTx_t stream pointer
 * @param[in]  name       Stream friendly name - used in, for example, logging statements
 * @param[in]  portMask   Bitmask for ports this stream will use for transmitting
 * @param[in]  NUMA       NUMA node on which the host buffer is be located
 * @param[in]  minHostBufferSize Minimum size of host buffer needed. Must be in MBytes. The smallest host buffer found that is larger or equal to minHostBufferSize is used. If set to 0, the first host buffer found is used regardsless of the size.
 *
 * @retval  0    Success
 * @retval !=0   Error
 */
int NT_NetTxOpen(NtNetStreamTx_t *hStream, const char *name, uint64_t portMask, uint32_t NUMA, uint32_t minHostBufferSize);


/**
 * @brief Gets a TX port buffer
 *
 * This function is called to acquire a TX buffer
 *
 * @note This function has no mutex protection, therefore the same hStream cannot be used by multiple threads
 *
 * @param[in]    hStream      Network TX stream handle
 * @param[out]   netBuf       Segment/packet container reference
 * @param[in]    port         Port to receive a TX buffer from
 * @param[in]    packetSize   Size of the packet to transmit including 4 byte CRC
 * @param[in]    packetOption Option to control the properties of the buffer, see @ref NtNetTxPacketOption_e for details
 * @param[in]    timeout      Time in milliseconds to wait for a new buffer. A timeout of -1 will wait indefinitely for a new buffer.
 *
 * @retval  0    Success
 * @retval !=0   Error
 */
int NT_NetTxGet(NtNetStreamTx_t hStream, NtNetBuf_t *netBuf, uint32_t port, size_t packetSize, enum NtNetTxPacketOption_e packetOption, int timeout);

/**
 * @brief Releases the network buffer
 *
 * This function releases the netBuf data obtained via NT_TxGet
 *
 * @note This function has no mutex protection and can therefore the same hStream cannot be used by multiple threads
 *
 * @param[in] hStream Network TX stream handle
 * @param[in] netBuf  Net buffer is received via NT_TxGet
 *
 * @retval  0    Success
 * @retval !=0   Error
 */
int NT_NetTxRelease(NtNetStreamTx_t hStream, NtNetBuf_t netBuf);

/**
 * @brief Closes a TX stream
 *
 * This function is called to close a TX stream
 *
 * @param[in] hStream  The TX stream handle to close
 *
 * @retval  0    Success
 * @retval !=0   Error
 */
int NT_NetTxClose(NtNetStreamTx_t hStream);

/** @page HwL3L4Checksum HW IP/UDP/TCP checksum
 * @{
 * The NT20E2 and NT4E adapters support IPv4, UDP and TCP calculations in hardware on transmit.
 * In order to use the feature, the packet descriptor must be configured prior to calling
 * @ref NT_NetTxRelease().\n
 * <b>Note:</b> The feature only works on non-fragmented packets.\n\n
 * Here is an example on the configuration required before transmitting a packet.
 *
 @verbatim
          NT_NET_SET_PKT_IS_IP(hNetBuf, 1);
          NT_NET_SET_PKT_IS_UDP(hNetBuf, 1);
          NT_NET_SET_PKT_IP_CSUM_OK(hNetBuf, 1);
          NT_NET_SET_PKT_UDP_CSUM_OK(hNetBuf, 1);
          if(NT_NET_GET_PKT_DESCRIPTOR_TYPE(hNetBuf) == NT_PACKET_DESCRIPTOR_TYPE_NT_EXTENDED) {
            NT_NET_SET_PKT_ISL(hNetBuf, 0);
            NT_NET_SET_PKT_VLAN_COUNT(hNetBuf, 0);
            NT_NET_SET_PKT_MPLS_COUNT(hNetBuf, 0);
            NT_NET_SET_PKT_L2_FRAME_TYPE(hNetBuf, NT_L2_FRAME_TYPE_ETHER_II);
            NT_NET_SET_PKT_L3_FRAME_TYPE(hNetBuf, NT_L3_FRAME_TYPE_IPv4);
            NT_NET_SET_PKT_L4_FRAME_TYPE(hNetBuf, NT_L4_FRAME_TYPE_UDP);
            NT_NET_SET_PKT_L3_OFFSET(hNetBuf, sizeof(struct MACHeader_s));
            NT_NET_SET_PKT_L4_OFFSET(hNetBuf, sizeof(struct MACHeader_s)+sizeof(struct IPv4Header_s));
            NT_NET_SET_PKT_L3_LENGTH(hNetBuf, sizeof(struct IPv4Header_s)>>2);
            NT_NET_SET_PKT_L4_LENGTH(hNetBuf, sizeof(struct UDPHeader_s)>>2);
            NT_NET_SET_PKT_CALC_L3_CHECKSUM(hNetBuf, 1);
            NT_NET_SET_PKT_CALC_L4_CHECKSUM(hNetBuf, 1);
         }
 @endverbatim

 @} */

/** @page PacketBasedTransmit Packet based transmit
 * @{
 *
 * For packet based transmit see the example @ref transmit.c "net/transmit/transmit.c"
 @} */

/** @page SegmentBasedTransmit Segment based transmit
 * @{
 *
 * For segment based transmit see the example @ref transmitSegment.c "net/transmitSegment/transmitSegment.c"
 @} */

/** @} */


/** @addtogroup StreamFile
 *@{
 */
/**
 * Network file stream handle - used for file streams
 */
typedef struct NtNetStreamFile_s* NtNetStreamFile_t;

/**
 * @brief Opens a capture file
 *
 * This function is called to open a capture file, captured with a segment-based stream.
 * The capture file must have an NT file header, otherwise it will fail when opening the capture
 * file.
 *
 * @param[out] hStream       Reference to a NetFile_t stream pointer
 * @param[in]  name          A stream friendly name - used in, for example, logging statements
 * @param[in]  netIntf       Deliver packets or segments
 * @param[in]  file          The capture file to open
 *
 * @retval  0    Success
 * @retval  !=0  Error - use NT_ExplainError for an error description
 */
int NT_NetFileOpen(NtNetStreamFile_t *hStream, const char *name, enum NtNetInterface_e netIntf, const char *file);

/**
 * @brief Gets packets/segments from a file stream
 *
 * This function is called to retrieve packets or segments from a capture file
 *
 * @note This function has no mutex protection, therefore the same hStream cannot be used by multiple threads
 *
 * @param[in]    hStream     NetFile stream handle
 * @param[out]   netBuf      Packet/segment container reference
 *
 * @retval  0    Success
 * @retval !=0   Error
 */
int NT_NetFileGet(NtNetStreamFile_t hStream, NtNetBuf_t *netBuf);

/**
 * @brief Releases the network buffer
 *
 * This function will release the netBuf data obtained via NT_FileGet
 *
 * @note This function has no mutex protection, therefore the same hStream cannot be used by multiple threads
 *
 * @param[in] hStream  NetStreamFile stream handle
 * @param[in] netBuf   The network buffer is received via NT_FileGet
 *
 * @retval  0    Success
 * @retval !=0   Error
 */
int NT_NetFileRelease(NtNetStreamFile_t hStream, NtNetBuf_t netBuf);

/**
 * @brief Closes a file stream
 *
 * This function is called to close a file stream
 *
 * @param[in] hStream The file stream handle to close
 *
 * @retval  0    Success
 * @retval !=0   Error
 */
int NT_NetFileClose(NtNetStreamFile_t hStream);

/** @} */

/**
 * MACROs to access network data
 */

/**
 * Layer 2 types.
 */
enum NtL2FrameType_e {
  NT_L2_FRAME_TYPE_ETHER_II=0, //!< Ether type II frame
  NT_L2_FRAME_TYPE_LLC,        //!< LLC frame
  NT_L2_FRAME_TYPE_SNAP,       //!< SNAP frame
  NT_L2_FRAME_TYPE_NOVELL_RAW  //!< Novell Raw frame
};

/**
 * Layer 3 types.
 */
enum NtL3FrameType_e {
  NT_L3_FRAME_TYPE_IPv4=0, //!< IPv4 frame
  NT_L3_FRAME_TYPE_IPv6,   //!< IPV6 frame
  NT_L3_FRAME_TYPE_IPX,    //!< IPX frame
  NT_L3_FRAME_TYPE_OTHER,  //!< Other frame
};

/**
 * Layer 4 frame types.
 */
enum NtL4FrameType_e {
  NT_L4_FRAME_TYPE_TCP=0, //!< TCP frame
  NT_L4_FRAME_TYPE_UDP,   //!< UDP frame
  NT_L4_FRAME_TYPE_ICMP,  //!< ICMP frame
  NT_L4_FRAME_TYPE_OTHER, //!< Other frame
  NT_L4_FRAME_TYPE_GRE,   //!< GRE frame
  NT_L4_FRAME_TYPE_SCTP,  //!< SCTP frame
};

/**
 * Layer 4 port types.
 */
enum NtL4PortType_e {
  NT_L4_PORT_OTHER=0,    //!< Other port
  NT_L4_PORT_GTPV0_U,    //!< GTPV0_U port
  NT_L4_PORT_GTPV1V2_C,  //!< GTPV1V2_C port
  NT_L4_PORT_GTPV1_U     //!< GTPV1_U port
};

/** @addtogroup NetworkStream
 *@{
 */

/** @defgroup DataMacros Network Macros
 * @{
 * The network stream delivers data to the application. In order to access data
 * content, such as packet length or packet receive time stamp, a set of macros are
 * provided. These macros are divided into 2 major groups:
 * - @ref SegmentMacros
 * - @ref PacketMacros
 *
 * The @ref SegmentMacros are used with the segment-based interface.
 * The @ref PacketMacros are used with the packet-based interface.
 */

/** @defgroup PacketMacros Packet Macros
 *  @{
 * The following is only possible on packet-based streams
 */
#define NT_NET_GET_PKT_DESCRIPTOR_TYPE(_hNetBuf_)           _NT_NET_GET_PKT_DESCRIPTOR_TYPE(_hNetBuf_) //!< Returns enum PacketDescriptor_e

/** @defgroup BasicDescriptorMacros Basic Descriptor Macros
 * @{
 * The following Macros are always available.
 */
#define NT_NET_GET_PKT_DESCR(_hNetBuf_)                 _NT_NET_GET_PKT_DESCR(_hNetBuf_)               //!< A pointer to the packet descriptor
#define NT_NET_GET_PKT_DESCR_LENGTH(_hNetBuf_)          _NT_NET_GET_PKT_DESCR_LENGTH(_hNetBuf_)        //!< The length of the packet descriptor
#define NT_NET_GET_PKT_TIMESTAMP(_hNetBuf_)             _NT_NET_GET_PKT_TIMESTAMP(_hNetBuf_)           //!< The time when the packet was captured
#define NT_NET_GET_PKT_TIMESTAMP_TYPE(_hNetBuf_)        _NT_NET_GET_PKT_TIMESTAMP_TYPE(_hNetBuf_)      //!< The packet time stamp type
#define NT_NET_GET_PKT_CAP_LENGTH(_hNetBuf_)            _NT_NET_GET_PKT_CAP_LENGTH(_hNetBuf_)          //!< The packet capture length
#define NT_NET_GET_PKT_WIRE_LENGTH(_hNetBuf_)           _NT_NET_GET_PKT_WIRE_LENGTH(_hNetBuf_)         //!< The packet wire length
#define NT_NET_GET_PKT_L2_PTR(_hNetBuf_)                _NT_NET_GET_PKT_L2_PTR(_hNetBuf_)              //!< A pointer to the L2 packet data
#define NT_NET_UPDATE_PKT_L2_PTR(_hNetBuf_)             _NT_NET_UPDATE_PKT_L2_PTR(_hNetBuf_)           //!< When creating packets within a segment it is required to update the L2 pointer using this macro after applying the descriptor info

#define NT_DESCR_EXT7_LENGTH  (sizeof(struct NtStd0Descr_s)+sizeof(struct NtExt7Descr_s))              //!< Length of the NT Extended 7 descriptor
#define NT_DESCR_NT_LENGTH    (sizeof(struct NtStd0Descr_s))                                           //!< Length of the NT standard descriptor

/** @} */

/** @defgroup NtDescriptorMacros NT Descriptor Macros
 * @{

 * The following is only available if "PacketDescriptor = NT or Ext7" has been selected in the ntservice.ini file
 * and if @ref NT_NET_GET_PKT_DESCRIPTOR_TYPE returns @ref NT_PACKET_DESCRIPTOR_TYPE_NT || @ref NT_PACKET_DESCRIPTOR_TYPE_NT_EXTENDED.
 * The following macros constitute the collection extracting data from the "NT" descriptor.
 * @note Entry level adapters only support "PacketDescriptor = NT" and only a subset of that is used. Only the following
 * macros are supported on entry level adapters:
 *   - @ref NT_NET_GET_PKT_CRC_ERROR
 *   - @ref NT_NET_GET_PKT_SLICED
 *   - @ref NT_NET_GET_PKT_HARD_SLICED
 *   - @ref NT_NET_GET_PKT_RXPORT
 */
#define NT_NET_GET_PKT_CRC_ERROR(_hNetBuf_)             _NT_NET_GET_PKT_CRC_ERROR(_hNetBuf_)           //!< Does the packet have an L2 CRC error
#define NT_NET_GET_PKT_TCP_CSUM_OK(_hNetBuf_)           _NT_NET_GET_PKT_TCP_CSUM_OK(_hNetBuf_)         //!< Does the packet have a TCP checksum error
#define NT_NET_GET_PKT_UDP_CSUM_OK(_hNetBuf_)           _NT_NET_GET_PKT_UDP_CSUM_OK(_hNetBuf_)         //!< Does the packet have a UDP checksum error
#define NT_NET_GET_PKT_IP_CSUM_OK(_hNetBuf_)            _NT_NET_GET_PKT_IP_CSUM_OK(_hNetBuf_)          //!< Does the packet have an IP checksum error
#define NT_NET_GET_PKT_CV_ERROR(_hNetBuf_)              _NT_NET_GET_PKT_CV_ERROR(_hNetBuf_)            //!< Does the packet have coding violations
#define NT_NET_GET_PKT_SLICED(_hNetBuf_)                _NT_NET_GET_PKT_SLICED(_hNetBuf_)              //!< Has the packet been sliced
#define NT_NET_GET_PKT_HARD_SLICED(_hNetBuf_)           _NT_NET_GET_PKT_HARD_SLICED(_hNetBuf_)         //!< Has the packet been hard sliced
#define NT_NET_GET_PKT_RXPORT(_hNetBuf_)                _NT_NET_GET_PKT_RXPORT(_hNetBuf_)              //!< The port that received this packet
#define NT_NET_GET_PKT_IS_TCP(_hNetBuf_)                _NT_NET_GET_PKT_IS_TCP(_hNetBuf_)              //!< Does the packet have a TCP header
#define NT_NET_GET_PKT_IS_UDP(_hNetBuf_)                _NT_NET_GET_PKT_IS_UDP(_hNetBuf_)              //!< Does the packet have a UDP header
#define NT_NET_GET_PKT_IS_IP(_hNetBuf_)                 _NT_NET_GET_PKT_IS_IP(_hNetBuf_)               //!< Does the packet have an IP header
#define NT_NET_GET_PKT_TXPORT(_hNetBuf_)                _NT_NET_GET_PKT_TXPORT(_hNetBuf_)              //!< The port this packet is to be transmitted on
#define NT_NET_GET_PKT_CALC_L2_CRC(_hNetBuf_)           _NT_NET_GET_PKT_CALC_L2_CRC(_hNetBuf_)         //!< Does the packet have L2 CRC override set
#define NT_NET_GET_PKT_TXNOW(_hNetBuf_)                 _NT_NET_GET_PKT_TXNOW(_hNetBuf_)               //!< Does the packet have TxNow set
#define NT_NET_GET_PKT_TXIGNORE(_hNetBuf_)              _NT_NET_GET_PKT_TXIGNORE(_hNetBuf_)            //!< Does the packet have TxIgnore set

/** @} */

/** @defgroup ExtendedNtDescriptorMacros Extended NT Descriptor Macros.
 * @{
 * The following is only available if "PacketDescriptor = Ext7" has been set in the ntservice.ini file
 * and if @ref NT_NET_GET_PKT_DESCRIPTOR_TYPE returns @ref NT_PACKET_DESCRIPTOR_TYPE_NT_EXTENDED
 */
#define NT_NET_GET_PKT_HASH(_hNetBuf_)                  _NT_NET_GET_PKT_HASH(_hNetBuf_)                //!< The packet hash value
#define NT_NET_GET_PKT_HASH_TYPE(_hNetBuf_)             _NT_NET_GET_PKT_HASH_TYPE(_hNetBuf_)           //!< The packet hash type
#define NT_NET_GET_PKT_HASH_VALID(_hNetBuf_)            _NT_NET_GET_PKT_HASH_VALID(_hNetBuf_)          //!< Is the hash value/type valid
#define NT_NET_GET_PKT_JUMBO(_hNetBuf_)                 _NT_NET_GET_PKT_JUMBO(_hNetBuf_)               //!< Is the packet a jumbo frame
#define NT_NET_GET_PKT_BROADCAST(_hNetBuf_)             _NT_NET_GET_PKT_BROADCAST(_hNetBuf_)           //!< Is the destination MAC a broadcast address
#define NT_NET_GET_PKT_L4_PORT_TYPE(_hNetBuf_)          _NT_NET_GET_PKT_L4_PORT_TYPE(_hNetBuf_)        //!< The L4 port type - see @ref NtL4PortType_e
#define NT_NET_GET_PKT_L4_FRAME_TYPE(_hNetBuf_)         _NT_NET_GET_PKT_L4_FRAME_TYPE(_hNetBuf_)       //!< The L4 frame type - see @ref NtL4FrameType_e
#define NT_NET_GET_PKT_L3_FRAME_TYPE(_hNetBuf_)         _NT_NET_GET_PKT_L3_FRAME_TYPE(_hNetBuf_)       //!< The L3 frame type - see @ref NtL3FrameType_e
#define NT_NET_GET_PKT_L2_FRAME_TYPE(_hNetBuf_)         _NT_NET_GET_PKT_L2_FRAME_TYPE(_hNetBuf_)       //!< The L2 frame type - see @ref NtL2FrameType_e
#define NT_NET_GET_PKT_L4_LENGTH(_hNetBuf_)             _NT_NET_GET_PKT_L4_LENGTH(_hNetBuf_)           //!< The L4 header length in units of 32 bits (valid for L4 = TCP only)
#define NT_NET_GET_PKT_L3_LENGTH(_hNetBuf_)             _NT_NET_GET_PKT_L3_LENGTH(_hNetBuf_)           //!< The L4 header length in units of 32 bits (valid for L3 = IPv4/IPv6 only)
#define NT_NET_GET_PKT_MPLS_COUNT(_hNetBuf_)            _NT_NET_GET_PKT_MPLS_COUNT(_hNetBuf_)          //!< The number of MPLS shim labels present
#define NT_NET_GET_PKT_VLAN_COUNT(_hNetBuf_)            _NT_NET_GET_PKT_VLAN_COUNT(_hNetBuf_)          //!< The number of VLANs present
#define NT_NET_GET_PKT_ISL(_hNetBuf_)                   _NT_NET_GET_PKT_ISL(_hNetBuf_)                 //!< ISL encapsulation present
#define NT_NET_GET_PKT_PROT_SMALL(_hNetBuf_)            _NT_NET_GET_PKT_PROT_SMALL(_hNetBuf_)          //!< Frame is protocol small
#define NT_NET_GET_PKT_FRAME_LARGE(_hNetBuf_)           _NT_NET_GET_PKT_FRAME_LARGE(_hNetBuf_)         //!< Large frame - is 1 when PktSz > MaxFrameSize is set in ntservice.ini
#define NT_NET_GET_PKT_FRAME_SMALL(_hNetBuf_)           _NT_NET_GET_PKT_FRAME_SMALL(_hNetBuf_)         //!< Small frame - is 1 when PktSz < 64 (+ISL and/or VLAN)
#define NT_NET_GET_PKT_IPV6_FR_HEADER(_hNetBuf_)        _NT_NET_GET_PKT_IPV6_FR_HEADER(_hNetBuf_)      //!< IPv6 fragment header present
#define NT_NET_GET_PKT_IPV6_RT_HEADER(_hNetBuf_)        _NT_NET_GET_PKT_IPV6_RT_HEADER(_hNetBuf_)      //!< IPv6 routing header present
#define NT_NET_GET_PKT_L4_PROTOCOL_NUM(_hNetBuf_)       _NT_NET_GET_PKT_L4_PROTOCOL_NUM(_hNetBuf_)     //!< L4 protocol number (TCP, UDP, SCTP etc.)
#define NT_NET_GET_PKT_L3_FRAGMENTED(_hNetBuf_)         _NT_NET_GET_PKT_L3_FRAGMENTED(_hNetBuf_)       //!< L3 fragmented frame (only valid for IPv4 if more fragments bit = 1 or fragment offset not equal to 0)
#define NT_NET_GET_PKT_L3_FIRST_FRAG(_hNetBuf_)         _NT_NET_GET_PKT_L3_FIRST_FRAG(_hNetBuf_)       //!< L3 First fragment (offset = 0). Note: Only valid for IPv4. Always set on IPv6 so use IPV6_FR_HEADER instead.
#define NT_NET_GET_PKT_COLOR(_hNetBuf_)                 _NT_NET_GET_PKT_COLOR(_hNetBuf_)               //!< The color of the packet
#define NT_NET_GET_PKT_L5_OFFSET(_hNetBuf_)             _NT_NET_GET_PKT_L5_OFFSET(_hNetBuf_)           //!< Offset from L2 pointer to where L5 starts
#define NT_NET_GET_PKT_L4_OFFSET(_hNetBuf_)             _NT_NET_GET_PKT_L4_OFFSET(_hNetBuf_)           //!< Offset from L2 pointer to where L4 starts
#define NT_NET_GET_PKT_L3_OFFSET(_hNetBuf_)             _NT_NET_GET_PKT_L3_OFFSET(_hNetBuf_)           //!< Offset from L2 pointer to where L3 starts

/** @} */

/** @defgroup TxMacros TX Macros
 * @{
 * The following can only be used on TX or in-line based streams.
 * @note Entry level adapters only support "PacketDescriptor = NT" and only a subset of that is used. Only the following
 * macros are supported on entry level adapters:
 *   - @ref NT_NET_SET_PKT_CAP_LENGTH
 *   - @ref NT_NET_SET_PKT_WIRE_LENGTH
 *   - @ref NT_NET_SET_PKT_CALC_L2_CRC
 *   - @ref NT_NET_SET_PKT_TXIGNORE
 *   - @ref NT_NET_SET_PKT_TXPORT
 *
 */
#define NT_NET_SET_PKT_CLEAR_DESCR_EXT7(_hNetBuf_)     _NT_NET_SET_PKT_CLEAR_DESCR_EXT7(_hNetBuf_)    //!< Clears the EXT7 descriptor
#define NT_NET_SET_PKT_DESCR_TYPE_EXT7(_hNetBuf_)      _NT_NET_SET_PKT_DESCR_TYPE_EXT7(_hNetBuf_)     //!< Sets the packet descriptor type to EXT7
#define NT_NET_SET_PKT_CAP_LENGTH(_hNetBuf_,_Length_)  _NT_NET_SET_PKT_CAP_LENGTH(_hNetBuf_,_Length_) //!< Sets the packet capture length
#define NT_NET_SET_PKT_WIRE_LENGTH(_hNetBuf_,_Length_) _NT_NET_SET_PKT_WIRE_LENGTH(_hNetBuf_,_Length_)//!< Sets the packet wire length
#define NT_NET_SET_PKT_CALC_L2_CRC(_hNetBuf_,_bval_)  _NT_NET_SET_PKT_CALC_L2_CRC(_hNetBuf_,_bval_)  //!< Asks the adapter to generate a CRC
#define NT_NET_SET_PKT_TIMESTAMP(_hNetBuf_, _ts_)     _NT_NET_SET_PKT_TIMESTAMP(_hNetBuf_,_ts_)      //!< Sets the packet time stamp - useful when controlling the traffic rate
#define NT_NET_SET_PKT_TXNOW(_hNetBuf_, _bval_)       _NT_NET_SET_PKT_TXNOW(_hNetBuf_, _bval_)       //!< If set the IPG is ignored - this will result in line rate TX
#define NT_NET_SET_PKT_TXIGNORE(_hNetBuf_, _bval_)    _NT_NET_SET_PKT_TXIGNORE(_hNetBuf_, _bval_)    //!< Marks the packet not to be sent - useful in in-line scenarios where some packets should not be retransmitted
#define NT_NET_SET_PKT_IS_IP(_hNetBuf_, _bval_)       _NT_NET_SET_PKT_IS_IP(_hNetBuf_, _bval_)       //!< Sets if the packet is IP
#define NT_NET_SET_PKT_IS_UDP(_hNetBuf_, _bval_)      _NT_NET_SET_PKT_IS_UDP(_hNetBuf_, _bval_)      //!< Sets if the packet is UDP
#define NT_NET_SET_PKT_IS_TCP(_hNetBuf_, _bval_)      _NT_NET_SET_PKT_IS_TCP(_hNetBuf_, _bval_)      //!< Sets if the packet is TCP
#define NT_NET_SET_PKT_CRC_ERROR(_hNetBuf_, _bval_)   _NT_NET_SET_PKT_CRC_ERROR(_hNetBuf_, _bval_)   //!< Sets if the packet has a CRC error
#define NT_NET_SET_PKT_IP_CSUM_OK(_hNetBuf_, _bval_)  _NT_NET_SET_PKT_IP_CSUM_OK(_hNetBuf_, _bval_)  //!< Sets if the packet has an OK IP checksum
#define NT_NET_SET_PKT_TCP_CSUM_OK(_hNetBuf_, _bval_) _NT_NET_SET_PKT_TCP_CSUM_OK(_hNetBuf_, _bval_) //!< Sets if the packet has an OK TCP checksum
#define NT_NET_SET_PKT_UDP_CSUM_OK(_hNetBuf_, _bval_) _NT_NET_SET_PKT_UDP_CSUM_OK(_hNetBuf_, _bval_) //!< Sets if the packet has an OK UDP checksum
#define NT_NET_SET_PKT_TXPORT(_hNetBuf_,_Port_)       _NT_NET_SET_PKT_TXPORT(_hNetBuf_,_Port_)       //!< Sets the packet port where this packets should be transmitted @note This feature only works on the CaptureReplay profile and the Tx port can only be within the range of one adapter


/** @defgroup ExtendedTxMacros Extended TX Macros
 * @{
 * The following can only be used if the TX buffer has an extended NT descriptor
 */
#define NT_NET_SET_PKT_INJECT_TIMESTAMP(_hNetBuf_, _offset_) _NT_NET_SET_PKT_INJECT_TIMESTAMP(_hNetBuf_,_offset_)  //!< Injects a time stamp on TX - the time stamp is injected into the payload at the offset provided @note The offset must be in multiples of 64 bits
#define NT_NET_SET_PKT_ISL(_hNetBuf_, _bval_)                _NT_NET_SET_PKT_ISL(_hNetBuf_, _bval_)                //!< Sets if frame is ISL encapsulated
#define NT_NET_SET_PKT_VLAN_COUNT(_hNetBuf_, _count_)        _NT_NET_SET_PKT_VLAN_COUNT(_hNetBuf_, _count_)        //!< Sets the number of VLAN tags
#define NT_NET_SET_PKT_MPLS_COUNT(_hNetBuf_, _count_)        _NT_NET_SET_PKT_MPLS_COUNT(_hNetBuf_, _count_)        //!< Sets the number of MPLS shim labels
#define NT_NET_SET_PKT_L2_FRAME_TYPE(_hNetBuf_, _type_)      _NT_NET_SET_PKT_L2_FRAME_TYPE(_hNetBuf_, _type_)      //!< Sets the L2 frame type, see @ref NtL2FrameType_e
#define NT_NET_SET_PKT_L3_FRAME_TYPE(_hNetBuf_, _type_)      _NT_NET_SET_PKT_L3_FRAME_TYPE(_hNetBuf_, _type_)      //!< Sets the L3 frame type, see @ref NtL3FrameType_e
#define NT_NET_SET_PKT_L4_FRAME_TYPE(_hNetBuf_, _type_)      _NT_NET_SET_PKT_L4_FRAME_TYPE(_hNetBuf_, _type_)      //!< Sets the L4 frame type, see @ref NtL4FrameType_e
#define NT_NET_SET_PKT_L3_OFFSET(_hNetBuf_, _offset_)        _NT_NET_SET_PKT_L3_OFFSET(_hNetBuf_, _offset_)        //!< Sets the offset from L2 to where L3 starts
#define NT_NET_SET_PKT_L4_OFFSET(_hNetBuf_, _offset_)        _NT_NET_SET_PKT_L4_OFFSET(_hNetBuf_, _offset_)        //!< Sets the offset from L2 to where L4 starts
#define NT_NET_SET_PKT_L3_LENGTH(_hNetBuf_, _u32len_)        _NT_NET_SET_PKT_L3_LENGTH(_hNetBuf_, _u32len_)        //!< L3 length in 32-bit units
#define NT_NET_SET_PKT_L4_LENGTH(_hNetBuf_, _u32len_)        _NT_NET_SET_PKT_L4_LENGTH(_hNetBuf_, _u32len_)        //!< L4 length in 32-bit units
#define NT_NET_SET_PKT_CALC_L3_CHECKSUM(_hNetBuf_, _bval_)   _NT_NET_SET_PKT_CALC_L3_CHECKSUM(_hNetBuf_, _bval_)   //!< If set, the adapter will calculate an IPv4 checksum on transmit
#define NT_NET_SET_PKT_CALC_L4_CHECKSUM(_hNetBuf_, _bval_)   _NT_NET_SET_PKT_CALC_L4_CHECKSUM(_hNetBuf_, _bval_)   //!< If set, the adapter will calculate an TCP/UDP checksum on transmit


/** @} */

/** @} */

/** @} */

/** @defgroup SegmentMacros Segment Macros
 *  @{
 * The following is only possible on segment-based streams
 */
#define NT_NET_GET_SEGMENT_PTR(_hNetBuf_)               _NT_NET_GET_SEGMENT_PTR(_hNetBuf_)              //!< Returns the segment pointer
#define NT_NET_GET_SEGMENT_LENGTH(_hNetBuf_)            _NT_NET_GET_SEGMENT_LENGTH(_hNetBuf_)           //!< Returns the segment length
#define NT_NET_GET_SEGMENT_TIMESTAMP(_hNetBuf_)         _NT_NET_GET_SEGMENT_TIMESTAMP(_hNetBuf_)        //!< The time stamp of the first packet in the segment
#define NT_NET_GET_SEGMENT_TIMESTAMP_TYPE(_hNetBuf_)    _NT_NET_GET_SEGMENT_TIMESTAMP_TYPE(_hNetBuf_)   //!< The time stamp type
#define NT_NET_SET_SEGMENT_LENGTH(_hNetBuf_, _length_)  _NT_NET_SET_SEGMENT_LENGTH(_hNetBuf_, _length_) //!< Sets the segment length - used when generating a TX segment (Use with care)

/** @defgroup SegmentFunctions In-line functions to handle segment data
 * @{
 */
// This function is not do be disclosed because we do not yet wish to disclose packet gen.
/**
 * @brief In-line function to create a segment NtNetBuf_t
 *
 * This function is used when creating segments in application memory, e.g.
 * when constructing a transmit segment
 *
 * @param[in] size        Size of the memory provided by the "mem" pointer
 * @param[in] mem         Pointer to the segment memory allocated
 * @param[in] portOffset  Segments are per adapter and ports are relative to the port offset. The port offset can be found in @ref NtInfoAdapter_s::portOffset. If 0 is provided then the possible values in @ref NT_NET_SET_PKT_TXPORT can only be from 0 to 3.
 * @param[out] segNetBuf Destination segment NtNetBuf_t structure
 *
 */
static INLINE void _nt_net_create_segment_netbuf(uint32_t size, void *mem, int portOffset, struct NtNetBuf_s * segNetBuf)
{
  memset(segNetBuf, 0, sizeof(struct NtNetBuf_s));
  segNetBuf->length=size-8; // We must have 8 bytes left in the segment
  segNetBuf->portOffset=portOffset;
  segNetBuf->hHdr=(NtNetBufHdr_t)(mem);
  segNetBuf->hPkt=(NtNetBufPkt_t)(mem);
  *((uint64_t*)mem+0)=0;
  *((uint64_t*)mem+1)=0;
  *((uint64_t*)mem+2)=0;
  *((uint64_t*)mem+3)=0;
}

/**
 * @brief In-line function to use when traversing segments. The
 * function will update the NetBuf to the next packet
 * in the segment.
 *
 * @param[in] segNetBuf   Segment NtNetBuf_s * structure
 * @param[in] segLength   Length of the segment - used to know when there is no more data
 * @param[out] pktNetBuf  Packet NtNetBuf_s * structure
 *
 * @retval Returns the amount of data left in the segment
 */
static INLINE int _nt_net_get_next_packet(struct NtNetBuf_s * segNetBuf, uint32_t segLength, struct NtNetBuf_s * pktNetBuf)
{
  if(segLength) {
    pktNetBuf->hHdr=(NtNetBufHdr_t)((uint8_t*)pktNetBuf->hHdr+NT_NET_GET_PKT_CAP_LENGTH(pktNetBuf));
    pktNetBuf->hPkt=(NtNetBufPkt_t)((uint8_t*)pktNetBuf->hHdr+NT_NET_GET_PKT_DESCR_LENGTH(pktNetBuf));
    // Check if this is the last packet
    if((uint8_t*)pktNetBuf->hHdr >= ((uint8_t*)segNetBuf->hHdr+segLength)) {
      return 0;
    }
    return (((uint8_t*)segNetBuf->hHdr+segLength)-(uint8_t*)pktNetBuf->hHdr);
  } else {
    return 0;
  }
}

/**
 * @brief In-line function to build a packet based NtNetBuf_t
 * from a segment based NtNetBuf_t
 *
 * @param[in] segNetBuf Segment NtNetBuf_t structure
 * @param[out] pktNetBuf Destination packet NtNetBuf_t structure
 *
 */
static INLINE void _nt_net_build_pkt_netbuf(struct NtNetBuf_s * segNetBuf, struct NtNetBuf_s * pktNetBuf)
{
  memcpy((void*)pktNetBuf, (void*)segNetBuf, sizeof(struct NtNetBuf_s));
  pktNetBuf->hHdr=(NtNetBufHdr_t)(segNetBuf->hHdr);
  pktNetBuf->hPkt=(NtNetBufPkt_t)((uint8_t*)segNetBuf->hHdr+NT_NET_GET_PKT_DESCR_LENGTH(segNetBuf));
}

/** @} */

/** @} */

/** @} */
/** @} */
/** @} */


#endif /* __STREAM_NET_H__ */
