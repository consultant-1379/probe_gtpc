// $Id: stream_info.h 17165 2012-01-31 13:56:35Z lm $
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
 * This is the header file of the STREAMTYPE_INFO interface.
 */
#ifndef __STREAM_INFO_H__
#define __STREAM_INFO_H__

/** @addtogroup InfoStream
 * @{
 *
 * Info streams are used to access system information. The info
 * stream is read only.
 *
 * To open an info stream call @ref NT_InfoOpen. Once the info stream
 * is open the info read command needs to be set in the @ref NtInfo_t
 * structure and depending on the info command an adapter number, port
 * number or similar also needs to be set. Once the @ref NtInfo_t
 * structure query is filled out, a call to @ref NT_InfoRead makes the
 * system read out the requested data. When done, call @ref
 * NT_InfoClose to close the stream.
 *
 * The info stream read commands currently supported are:
 * @li <tt>System info</tt> - this includes the number of ports, adapters and sensors
 * @li <tt>Adapter info</tt> - this includes the number of sensors, ports, PCI ID and bus ID
 * @li <tt>Port info</tt> - this includes the port state, speed and duplex
 * @li <tt>Sensor info</tt> - this includes the sensor type, name and value
 * @li <tt>Host buffer info</tt> - this includes the NUMA node, size and feed
 * @li <tt>Time sync info</tt> - this includes the time sync connector and time sync data
 *
 * For an example of using the info stream see @ref info/info.c "info/info.c"
 */

/**
 * Possible info stream read commands
 */
enum NtInfoCmd_e {
  NT_INFO_CMD_READ_UNKNOWN=0,   //!< Unknown stream read command
  NT_INFO_CMD_READ_SYSTEM,      //!< System info - the number of ports, adapters and sensors
  NT_INFO_CMD_READ_ADAPTER,     //!< Adapter info - the number of sensors, ports, PCI ID and bus ID
  NT_INFO_CMD_READ_PORT,        //!< Port info - the port state, speed and duplex
  NT_INFO_CMD_READ_SENSOR,      //!< Sensor info - the sensor type, name and value
  NT_INFO_CMD_READ_HOSTBUFFER,  //!< Host buffer info - the NUMA node, size and feed
  NT_INFO_CMD_READ_STREAM,      //!< Info about active streams in the system
  NT_INFO_CMD_READ_TIMESYNC,    //!< Time sync info - the time sync connector and time sync data
};

/**
 * This structure will return the system-wide information
 */
struct NtInfoSystem_s {
  uint32_t numNumaNodes; //!< The number of NUMA nodes in the system
  uint32_t numAdapters;  //!< The number of adapters in the system
  uint32_t numPorts;     //!< The number of ports in the system
  /**
   * Version info
   */
  struct {
    int32_t major;  //!< The major release number
    int32_t minor;  //!< The minor release number
    int32_t patch;  //!< The major/minor patch release
    int32_t tag;    //!< The release tag number
  } version;
};

/**
 * This structure will return the adapter specific info
 */
struct NtInfoAdapter_s {
  uint32_t numSensors;                     //!< The number of sensors on this adapter
  uint32_t numLevel1Sensors;               //!< The number of level 1 sensors on this adapter
  uint32_t portOffset;                     //!< The port numbers of this adapter start at this port offset
  uint32_t numPorts;                       //!< The number of ports on this adapter
  uint32_t numPhysicalAdapters;            //!< The number of physical adapters grouped in this virtual adapter
  uint32_t numHostBuffersRx;               //!< The number of RX host buffers on this adapter
  uint32_t numHostBuffersTx;               //!< The number of TX host buffers on this adapter
  uint32_t numTsConnectors;                //!< The number of time sync connectors on this adapter
  enum NtAdapterType_e adapterType;        //!< The adapter type
  enum NtProductType_e productType;        //!< The product line type
  enum NtProfileType_e profile;            //!< The profile the adapter is using
  enum NtProductFamily_e productFamily;    //!< The product family
  char name[128];                          //!< The adapter name
  char serialNo[50];                       //!< The adapter serial number
  /**
   * AVR version for Gen2 adapters:
   *   avr[0] = Main board AVR,
   *   avr[1] = Front board AVR
   */
  struct NtversionAvr_s {
    uint8_t valid;                      //!< Does this structure contain valid data. Not all adapters use this structure.
    #define AVR_NOT_VALID 0             //!< No valid AVR data
    #define AVR_VALID     1             //!< Valid AVR data has been filled in the structure
    struct {
      uint8_t version_major;            //!< The major version
      uint8_t version_minor;            //!< The minor version
      uint8_t version_build;            //!< The build number
    } avr[2];
  } avr;
  /**
   * The bus ID is read as:
   *   32-bit value,
   *   4 x 8-bit values defining
   *      function,
   *      device,
   *      bus and
   *      slot
   */
  union Ntbusid_u {
    /**
     * The bus ID is read as:
     *   4 x 8-bit values defining
     *      function,
     *      device,
     *      bus and
     *      slot
     */
    struct Ntbusid_s {
      uint32_t function:8; //!< The PCI function number
      uint32_t device:8;   //!< The PCI device number
      uint32_t bus:8;      //!< The PCI bus number
      uint32_t slot:8;     //!< The PCI slot number
    }s;
    uint32_t value;      //!< The slot, bus, device and function as a 32-bit value
  } busid;
  /**
   * PCI  ID is read as:
   *   32-bit value,
   *   2 x 16-bit values defining
   *      device ID and
   *      vendor ID
   */
  union Ntpciid_u {
    /**
     * PCI ID can be read as:
     *   32-bit value,
     *   2 x 16-bit values defining
     *      device ID and
     *      vendor ID
     */
    struct Ntpciid_s {
      uint16_t device; //!< The device ID, for example, NT20E in-line 0x64
      uint16_t vendor; //!< The vendor ID, for example, Napatech 0x18F4
    }s;
    uint32_t value;    //!< The PCI ID, for example, 0x18540064
  } pciid;
  /**
   * The FPGA ID of the image currently running on the adapter.
   * The format is: item-product-version-revision-build.
   * For example, 200-9114-40-01-1023.
   */
  union {
    struct {
      uint64_t rev:8;      //!< The FPGA revision
      uint64_t ver:8;      //!< The FPGA version
      uint64_t product:16; //!< The FPGA product code
      uint64_t item:12;    //!< The FPGA item type (200 is FPGA, 201 is CPLD)
      uint64_t build:11;   //!< The build number - non-zero for R&D builds
      uint64_t reserved:9;
    }s;
    uint64_t value;      //!< The raw 64-bit FPGA ID
  } fpgaid;
  uint32_t extendedDescriptor;                  //!< Is the adapter running with extended descriptors
  enum NtPacketDescriptorType_e descriptorType; //!< The descriptor type to use, PCAP or NT
  enum NtTimestampType_e timestampType;         //!< The timestamp type used by the adapter
  enum NtTimestampMethod_e timestampMethod;     //!< The timestamp method (SOF/EOF) used by the adapter
};

enum NtPortFeatureMask_e {
  NT_PORT_FEATURE_DMA_TRANSMIT=1LL<<0,              //!< The port is able to perform DMA transmit. Ports that do not have this bit set will only be able to transmit at a limited rate.
  NT_PORT_FEATURE_HARDSLICE_AT_MAXFRAMESIZE=1LL<<1, //!< The port will hard slice packets when they exceed the maximum frame size
  NT_PORT_FEATURE_IPV4_TX_CHECKSUM_CALC=1LL<<2,     //!< The port can calculate the IPv4 checksum on transmit
  NT_PORT_FEATURE_UDP_TX_CHECKSUM_CALC=1LL<<3,      //!< The port can calculate the UDP checksum on transmit
  NT_PORT_FEATURE_TCP_TX_CHECKSUM_CALC=1LL<<4,      //!< The port can calculate the TCP checksum on transmit
  NT_PORT_FEATURE_INJECT_TX_TS=1LL<<5,              //!< The port can inject a timestamp when transmitting packets
  NT_PORT_FEATURE_TIMED_TX=1LL<<6,                  //!< The port can transmit timed using the timestamps in each packet
};

enum NtNimIdentifier_e {
  NT_NIM_GBIC         = 0x01, //!< Nim Type = GBIC
  NT_NIM_FIXED        = 0x02, //!< Nim Type = FIXED
  NT_NIM_SFP_SFP_PLUS = 0x03, //!< Nim Type = SFP/SFP+
  NT_NUM_300_PIN_XBI  = 0x04, //!< Nim Type = 300 pin XBI
  NT_NIM_XEN_PAK      = 0x05, //!< Nim Type = XEN-PAK
  NT_NIM_XFP          = 0x06, //!< Nim Type = XFP
  NT_NIM_XFF          = 0x07, //!< Nim Type = XFF
  NT_NIM_XFP_E        = 0x08, //!< Nim Type = XFP-E
  NT_NIM_X2           = 0x0A, //!< Nim Type = X2
  NT_NIM_DWDM         = 0x0B, //!< Nim Type = DWDM
  NT_NIM_QSFP         = 0x0C, //!< Nim Type = QSFP
  NT_NIM_QSFP_PLUS    = 0x0D, //!< Nim Type = QSFP+
};

/**
 * This structure will return the port specific information
 */
struct NtInfoPort_s {
  enum NtPortType_e type;     //!< The interface type
  enum NtLinkState_e state;   //!< The port up or down
  enum NtLinkSpeed_e speed;   //!< The interface speed
  enum NtLinkDuplex_e duplex; //!< The duplex mode
  int32_t flow;               //!< 0 = No flow control, 1 = Flow control
  enum NtLinkMDI_e mdi;       //!< 0 = auto, 1 = MDI, 2 = MDIX
  uint8_t macAddress[6];      //!< The MAC address of the interface
  uint16_t maxFrameSize;      //!< The current maximum frame size
  /**
   * Capabilities reflect what the port is capable of, that is what speed/duplex is possible. For example,
   * if only 100 M full duplex is available, the capabilities would
   * show:
   * halfDuplexMask=0.
   * fullDuplexMask=NT_LINK_SPEED_100M.
   * Other capabilities are min/max transmit sizes.
   */
  struct NtLinkCapabilities_s {
    uint32_t halfDuplexMask;              //!< The available half duplex (use @ref NtLinkSpeed_e as the bitmask)
    uint32_t fullDuplexMask;              //!< The available full duplex (use @ref NtLinkSpeed_e as the bitmask)
    uint32_t speed;                       //!< The available speed (use @ref NtLinkSpeed_e as the bitmask)
    uint32_t mdi;                         //!< The available mdi mode (use @ref NtLinkMDI_e as the bitmask)
    uint32_t AutoNeg;                     //!< The available link mode (use @ref NtLinkAutoNeg_e as the bitmask)
    uint32_t duplex;
    uint16_t minTxPktSize;                //!< The minimum transmit packet size
    uint16_t maxTxPktSize;                //!< The maximum transmit packet size
    enum NtPortFeatureMask_e featureMask; //!< The feature mask of the port
  } capabilities;                //!< The link capabilities
  uint32_t adapterNo;            //!< The adapter that has the port
  uint32_t numSensors;           //!< The number of sensors on this port
  uint32_t numLevel1Sensors;     //!< Number of level 1 sensors on this port
  uint32_t numLevel2Sensors;     //!< Number of level 2 sensors on this port

  /**
   *  NIM model information
   */
  enum NtNimIdentifier_e nim_id; //!< NIM identifier
  uint8_t vendor_name[17];       //!< NIM Vendor name
  uint8_t product_no[17];        //!< NIM product number
  uint8_t serial_no[17];         //!< NIM serial number
  uint8_t date[9];               //!< NIM vendors manufacturing date
  uint8_t revision[5];           //!< NIM vendor revision
  uint8_t power_level_req;       //!< NIM required power level
  uint8_t power_level_curr;      //!< NIM current power level
  struct NtNIMLinkLength_s {
    uint16_t sm;                  //!< NIM link length supported SM (9um)
    uint16_t ebw;                 //!< NIM link length supported EBW (50um)
    uint16_t mm50;                //!< NIM link length supported MM (50um)
    uint16_t mm62;                //!< NIM link length supported MM (62.5um)
    uint16_t copper;              //!< NIM link length supported copper
  } link_length;
};

/**
 * This structure will return the sensor specific information
 */
typedef struct NtInfoSensor_s {
  enum NtSensorSource_e source;     //!< The source of the sensor (port or adapter on which the sensor resides)
  uint32_t sourceIndex;             //!< The source index - the adapter number for adapter sensors and port number for port sensors
  uint32_t sensorIndex;             //!< The sensor index within the source index (sensor number on the adapter or sensor number on the port)
  enum NtSensorType_e type;         //!< The sensor type
  enum NtSensorSubType_e subType;   //!< The sensor subtype (if applicable)
  enum NtSensorState_e state;       //!< The current state (normal or alarm)
  int32_t value;                    //!< The current value
  int32_t valueLowest;              //!< The lowest value registered
  int32_t valueHighest;             //!< The highest value registered
  int32_t limitLow;                 //!< The minimum sensor value before an alarm is triggered
  int32_t limitHigh;                //!< The maximum sensor value before an alarm is triggered
  char name[50];                    //!< The sensor name
  enum NtAdapterType_e adapterType; //!< The adapter type where the sensor resides
} NtInfoSensor_t;


/**
 * Host buffer specific information
 */
struct NtInfoHostBuffer_s {
  uint32_t numaNode; //!< The NUMA node on which the host buffer resides
  uint32_t size;     //!< The size of the host buffer in MB
  uint32_t feed;     //!< The feed index per adapter and type
};

/**
 * Structure to hold information about currently active streams
 */
struct NtInfoStreams_s {
  int streamIDList[256];  //!< Holds all the stream IDs currently created in the system
  uint32_t count;         //!< The number of stream IDs from the streamIDList
};

/**
 * Time sync specific info
 */
struct NtInfoTimeSync_s {
  uint32_t timeSyncSupported;         //!< Is the time sync supported by this adapter
  uint32_t timeSyncProtocol;          //!< The time sync protocol
  uint32_t timeSyncPpsEnable;         //!< The time sync PPS enable
  uint32_t timeSyncConnectorIn;       //!< The time sync input connector
  uint32_t timeSyncConnectorOut;      //!< The time sync output connectors
  uint32_t timeSyncConnectorRepeat;   //!< The time sync repeater connectors
  uint32_t timeSyncTimeJumpThreshold; //!< The time sync time jump threshold in seconds
  uint32_t timeSyncTimeOffset;        //!< The time sync offset in nanoseconds
  uint64_t timeSyncPpsSampled;        //!< The sampled PPS time (0 if not applicable)
  int64_t timeSyncTimeSkew;           //!< The time skew
  uint32_t timeSyncStatus;            //!< The time sync status
};


/**
 * NT_INFO_CMD_READ_SYSTEM specific data
 */
struct NtInfoCmdSystem_s {
  struct NtInfoSystem_s data; //!< System data
};

/**
 * NT_INFO_CMD_READ_ADAPTER specific data.
 * The adapterNo must be initialized for the relevant adapter.
 */
struct NtInfoCmdAdapter_s {
  uint32_t adapterNo;          //!< The adapter to query
  struct NtInfoAdapter_s data; //!< The adapter data
};

/**
 * NT_INFO_CMD_READ_PORT specific data.
 * The portNo must be initialized for the relevant port.
 */
struct NtInfoCmdPort_s {
  uint32_t portNo;          //!< The port to query
  struct NtInfoPort_s data; //!< The port data
};

/**
 * NT_INFO_CMD_READ_SENSOR specific data.
 * The group, adapterNo/portNo and grpIndex must be initialized for the relevant sensor.
 * For example, to read sensor 2 from port 4, do the following:
 *   info.u.cmd = NT_INFO_CMD_READ_SENSOR;
 *   info.u.sensor.source = NT_SENSOR_SOURCE_PORT;
 *   info.u.sensor.sourceIndex= 4;
 *   info.u.sensor.sensorIndex = 2;
 *   NT_ReadInfo(h, &info);
 */
struct NtInfoCmdSensor_s {
  enum NtSensorSource_e source; //!< The source of the sensor - either a port or adapter sensor
  int sourceIndex;              //!< The source index - either adapter number or port number on which the sensor resides
  int sensorIndex;              //!< The sensor index within the source index, for example, 2 for sensor 2 on port 4
  struct NtInfoSensor_s data;   //!< The sensor data
};

/**
 * NT_INFO_CMD_READ_HOSTBUFFER specific data.
 * The adapterNo, hostBufferNo and hostBufferType must be initialized for the relevant adapter, host buffer number and host buffer type
 */
struct NtInfoCmdHostBuffer_s {
  uint32_t adapterNo;                        //!< The adapter to query
  uint32_t hostBufferNo;                     //!< The host buffer to query
  enum NtNetHostBufferType_e hostBufferType; //!< The host buffer type, that is CAPTURE or TX
  struct NtInfoHostBuffer_s data;            //!< The host buffer data
};

/**
 * NT_INFO_CMD_READ_STREAM specific data.
 * Returning information about streams. Currently only the list of active streams is supported.
 */
struct NtInfoCmdStream_s {
  struct NtInfoStreams_s data;
};

/**
 * NT_INFO_CMD_READ_TIMESYNC specific data.
 * The adapterNo must be initialized for the relevant adapter.
 */
struct NtInfoCmdTimeSync_s {
  uint32_t adapterNo;           //!< The adapter to query
  struct NtInfoTimeSync_s data; //!< The time sync data
};


/**
 * Read command structure. Query used for info via NT_InfoRead().
 */
typedef struct NtInfo_s {
  enum NtInfoCmd_e cmd;           //!< Info stream command
  /**
   * Union of data structures for each info stream command
  */
  union NtInfo_u {
    struct NtInfoCmdSystem_s system;          //!< NT_INFO_CMD_READ_SYSTEM specific data
    struct NtInfoCmdAdapter_s adapter;        //!< NT_INFO_CMD_READ_ADAPTER specific data.
    struct NtInfoCmdPort_s port;              //!< NT_INFO_CMD_READ_PORT specific data.
    struct NtInfoCmdSensor_s sensor;          //!< NT_INFO_CMD_READ_SENSOR specific data.
    struct NtInfoCmdHostBuffer_s  hostBuffer; //!< NT_INFO_CMD_READ_HOSTBUFFER specific data.
    struct NtInfoCmdStream_s stream;          //!< NT_INFO_CMD_READ_STREAM specific data.
    struct NtInfoCmdTimeSync_s timeSync;      //!< NT_INFO_CMD_READ_TIMESYNC specific data.
  }u;
} NtInfo_t;

/**
 * Info stream handle
 */
typedef struct NtInfoStream_s* NtInfoStream_t;

/**
 * @brief Opens an info stream
 *
 * This function is called to retrieve a handle to an info stream
 *
 * @param[out] hStream          Reference to an NtInfoStream_t stream pointer
 * @param[in]  name             The stream friendly name - used in, for example logging statements
 *
 * @retval  0    Success
 * @retval !=0   Error
 */
int NT_InfoOpen(NtInfoStream_t *hStream, const char *name);

/**
 * @brief Reads data from an info stream
 *
 * Returns system stream data
 *
 * @param[in]      hStream   NtSystemStream_t handle
 * @param[in,out]  info      The info structure containing query info, which serves as an output buffer for data
 *
 * @retval  0    Success
 * @retval !=0   Error
 */
int NT_InfoRead(NtInfoStream_t hStream, NtInfo_t *info);

/**
 * @brief Closes an info stream
 *
 * This function is called to close an info stream
 *
 * @param[in] hStream          Reference to an NtInfoStream_t stream pointer
 *
 * @retval  0    Success
 * @retval !=0   Error
 */
int NT_InfoClose(NtInfoStream_t hStream);

/** @} */

#endif // __STREAM_INFO_H__

