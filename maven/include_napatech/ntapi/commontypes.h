// $Id: commontypes.h 17057 2012-01-25 12:53:26Z bk $
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
 * This file contains the common types that can be used by any interface
 */

#ifndef __COMMONTYPES_H__
#define __COMMONTYPES_H__

/**
 * The stream types supported.
 */
enum NtStreamType_e {
  NT_STREAMTYPE_UNKNOWN=0,             //!< Unknown stream type
  NT_STREAMTYPE_NET=0x1000,            //!< Network stream
  NT_STREAMTYPE_CONFIG=0x2000,         //!< Configuration stream
  NT_STREAMTYPE_STATISTICS=0x3000,     //!< Statistics stream
  NT_STREAMTYPE_EVENT=0x4000,          //!< Event stream
  NT_STREAMTYPE_INFO=0x5000,           //!< Info stream
};

/**
 * Timestamp type.
 */
enum NtTimestampType_e {
  NT_TIMESTAMP_TYPE_NATIVE = 0,    //!< 64-bit 10 ns resolution timer from a base of 0
  NT_TIMESTAMP_TYPE_NATIVE_NDIS,   //!< 64-bit 10 ns resolution timer from a base of January 1, 1601
  NT_TIMESTAMP_TYPE_NATIVE_UNIX,   //!< 64-bit 10 ns resolution timer from a base of January 1, 1970
};


/**
 * Timestamp method
 */
enum NtTimestampMethod_e {
  NT_TIMESTAMP_METHOD_UNKNOWN = 0, //!< Timestamp method unknown
  NT_TIMESTAMP_METHOD_SOF,         //!< Timestamp at start of frame
  NT_TIMESTAMP_METHOD_EOF          //!< Timestamp at end of frame
};



/**
 * Host buffer types.
 * Used to select between RX or TX host buffers.
 */
enum NtNetHostBufferType_e {
  NT_NET_HOSTBUFFER_TYPE_UNKNOWN=0, //!< Host buffer type is unknown
  NT_NET_HOSTBUFFER_TYPE_RX,        //!< Host buffer type is RX (ini-file tag: HostBufferRx)
  NT_NET_HOSTBUFFER_TYPE_TX         //!< Host buffer type is TX (ini-file tag: HostBufferTx)
};

/**
 * Adapter types.
 */
enum NtAdapterType_e {
  NT_ADAPTER_TYPE_UNKNOWN=0,   //!< Unknown adapter type
  NT_ADAPTER_TYPE_NT4E,        //!< NT4E network adapter
  NT_ADAPTER_TYPE_NT20E,       //!< NT20E network adapter
  NT_ADAPTER_TYPE_NT4E_STD,    //!< NT4E-STD network adapter
  NT_ADAPTER_TYPE_NT4E_PORT,   //!< NTPORT4E expansion adapter
  NT_ADAPTER_TYPE_NTBPE,       //!< NTBPE bypass adapter
  NT_ADAPTER_TYPE_NT20E2,      //!< NT20E2 network adapter
  NT_ADAPTER_TYPE_NT4E2_EL,    //!< Intel 82580 based adapter
  NT_ADAPTER_TYPE_NT20E2_EL,   //!< Intel 82599 based adapter
  NT_ADAPTER_TYPE_NT40E2_1,    //!< NT40E2-1 network adapter
  NT_ADAPTER_TYPE_NT40E2_4,    //!< NT40E2-4 network adapter
};

/**
 * Packet descriptor type
 */
enum NtPacketDescriptorType_e {
  NT_PACKET_DESCRIPTOR_TYPE_UNKNOWN,      //!< Unknown descriptor type
  NT_PACKET_DESCRIPTOR_TYPE_PCAP,         //!< Descriptor type is PCAP
  NT_PACKET_DESCRIPTOR_TYPE_NT,           //!< Descriptor type is NT
  NT_PACKET_DESCRIPTOR_TYPE_NT_EXTENDED,  //!< Descriptor type is NT extended
};

/**
 * Product types
 */
enum NtProductType_e {
  NT_PRODUCT_TYPE_UNKNOWN=0,      //!< Unknown product type
  NT_PRODUCT_TYPE_CAPTURE,        //!< Capture product type
  NT_PRODUCT_TYPE_INLINE,         //!< In-line product type
  NT_PRODUCT_TYPE_CAPTURE_REPLAY, //!< Capture-Replay product type
  NT_PRODUCT_TYPE_TRAFFIC_GEN,    //!< Traffic generator product type
};

/**
 * Profile types
 */
enum NtProfileType_e {
  NT_PROFILE_TYPE_UNKNOWN=0,           //!< Unknown profile type
  NT_PROFILE_TYPE_CAPTURE=1<<0,        //!< Capture profile type
  NT_PROFILE_TYPE_INLINE=1<<1,         //!< In-line profile type
  NT_PROFILE_TYPE_CAPTURE_REPLAY=1<<2, //!< Capture-Replay profile type
  NT_PROFILE_TYPE_TRAFFIC_GEN=1<<3,    //!< Traffic generator profile type
};

/**
 * Product family
 */
enum NtProductFamily_e {
  NT_PRODUCT_FAMILY_UNKNOWN=0, //!< Unknown product family
  NT_PRODUCT_FAMILY_NT,        //!< NT adapter family
  NT_PRODUCT_FAMILY_NIC,       //!< Standard NIC product family
};

/**
 * SDRAM module sizes
 */
enum NtSdramSize_e {
  NT_SDRAM_SIZE_UNKNOWN=0,      //!< Unknown RAM size
  NT_SDRAM_SIZE_512M = 0x1,     //!< RAM size 512 megabytes
  NT_SDRAM_SIZE_1G = 0x2,       //!< RAM size 1 gigabyte
  NT_SDRAM_SIZE_2G = 0x4,       //!< RAM size 2 gigabytes
  NT_SDRAM_SIZE_4G = 0x8,       //!< RAM size 4 gigabytes
};

/**
 * SDRAM module type
 */
enum NtSdramType_e {
  NT_SDRAM_TYPE_UNKNOWN=0,       //!< Unknown RAM type
  NT_SDRAM_TYPE_DDR2 = 0x1,      //!< RAM is DDR2
  NT_SDRAM_TYPE_DDR3 = 0x2,      //!< RAM is DDR3
};

/**
 * Port types
 */
enum NtPortType_e {
  NT_PORT_TYPE_NOT_AVAILABLE= 0,       //!< The interface is not available
  NT_PORT_TYPE_NOT_RECOGNISED,         //!< The interface type cannot be recognized
  NT_PORT_TYPE_RJ45,                   //!< RJ45 type
  NT_PORT_TYPE_SFP_NOT_PRESENT,        //!< SFP type but slot is empty
  NT_PORT_TYPE_SFP_SX,                 //!< SFP SX
  NT_PORT_TYPE_SFP_SX_DD,  	           //!< SFP SX digital diagnostic
  NT_PORT_TYPE_SFP_LX,		             //!< SFP LX
  NT_PORT_TYPE_SFP_LX_DD,              //!< SFP LX digital diagnostic
  NT_PORT_TYPE_SFP_ZX,                 //!< SFP ZX
  NT_PORT_TYPE_SFP_ZX_DD,              //!< SFP ZX digital diagnostic
  NT_PORT_TYPE_SFP_CU,                 //!< SFP copper
  NT_PORT_TYPE_SFP_CU_DD,              //!< SFP copper digital diagnostic
  NT_PORT_TYPE_SFP_NOT_RECOGNISED,     //!< SFP unknown
  NT_PORT_TYPE_XFP,                    //!< XFP
  NT_PORT_TYPE_XPAK,                   //!< XPAK
  NT_PORT_TYPE_SFP_CU_TRI_SPEED,       //!< SFP copper tri-speed
  NT_PORT_TYPE_SFP_CU_TRI_SPEED_DD,    //!< SFP copper tri-speed digital diagnostic
  NT_PORT_TYPE_SFP_PLUS,               //!< SFP+ type
  NT_PORT_TYPE_SFP_PLUS_NOT_PRESENT,   //!< SFP+ type but slot is empty
  NT_PORT_TYPE_XFP_NOT_PRESENT,        //!< XFP type but slot is empty
};

/**
 * Link state
 */
enum NtLinkState_e {
  NT_LINK_STATE_UNKNOWN = 0,
  NT_LINK_STATE_DOWN    = 1,
  NT_LINK_STATE_UP      = 2
};

/**
 * Link speeds.
 * Note this is a bitmask.
 */
enum NtLinkSpeed_e {
  NT_LINK_SPEED_UNKNOWN=0,
  NT_LINK_SPEED_10M =0x01, //!< 10 Mbps
  NT_LINK_SPEED_100M=0x02, //!< 100 Mbps
  NT_LINK_SPEED_1G  =0x04, //!< 1 Gbps
  NT_LINK_SPEED_10G =0x08, //!< 10 Gbps
  NT_LINK_SPEED_40G =0x10, //!< 40 Gbps
};

/**
 * Link duplex mode
 */
enum NtLinkDuplex_e {
  NT_LINK_DUPLEX_UNKNOWN=0,
  NT_LINK_DUPLEX_HALF = 0x01, //!< Half duplex
  NT_LINK_DUPLEX_FULL = 0x02, //!< Full duplex
};

/**
 * Link MDI mode
 */
enum NtLinkMDI_e {
  NT_LINK_MDI_AUTO = 0x01,  //!< MDI auto
  NT_LINK_MDI_MDI  = 0x02,  //!< MDI mode
  NT_LINK_MDI_MDIX = 0x04,  //!< MDIX mode
};

/**
 * Link MDI mode
 */
enum NtLinkAutoNeg_e {
  NT_LINK_AUTONEG_MANUAL = 0x01, //!< Manual link
  NT_LINK_AUTONEG_AUTO   = 0x02, //!< Auto link
};

/**
 * TX laser power mode
 */
enum NtTxPower_e {
  NT_TX_POWER_UNKNOWN=0, //!< Illegal value - should newer be read or written
  NT_TX_POWER_NA,        //!< Reading: Changing TX Power is not supported.\n Writing: Not valid for writing.
  NT_TX_POWER_ON,        //!< Reading: TX power is on.\n Writing: Turns on the TX power
  NT_TX_POWER_OFF        //!< Reading: TX power is off.\n Writing: Turns off the TX power
};

/**
 * Time sync protocol
 */
enum NtTimeSyncProtocol_e {
  NT_TIMESYNC_PROTOCOL_NT=0,
  NT_TIMESYNC_PROTOCOL_OS,
  NT_TIMESYNC_PROTOCOL_PPS_REL,
  NT_TIMESYNC_PROTOCOL_PPS_ABS,
  NT_TIMESYNC_PROTOCOL_FREE,
};

/**
 * Time sync PPS actions
 */
enum NtTimeSyncPpsAction_e {
  NT_TIMESYNC_PPS_ACTION_REFERENCE_TIME=0,
  NT_TIMESYNC_PPS_ACTION_ENABLE,
  NT_TIMESYNC_PPS_ACTION_DISABLE,
};

/**
 * Time sync connectors
 */
enum NtTimeSyncConnector_e {
  NT_TIMESYNC_CONNECTOR_NONE = 0,
  NT_TIMESYNC_CONNECTOR_EXT  = 0x01,
  NT_TIMESYNC_CONNECTOR_INT1 = 0x02,
  NT_TIMESYNC_CONNECTOR_INT2 = 0x04,
};

/**
 * Time sync status
 */
enum NtTimeSyncStatus_e {
  NT_TIMESYNC_STATUS_NONE = 0,
  NT_TIMESYNC_STATUS_SIGNAL_LOST = 0x01,
  NT_TIMESYNC_STATUS_SIGNAL_PRESENT = 0x02,
};

/**
 * Time sync PPS status
 */
enum NtTimeSyncPpsStatus_e {
  NT_TIMESYNC_PPS_STATUS_NONE = 0,
  NT_TIMESYNC_PPS_STATUS_ENABLED = 0x01,
  NT_TIMESYNC_PPS_STATUS_DISABLED = 0x02,
};

/**
 * Sensor types
 */
enum NtSensorType_e {
  NT_SENSOR_TYPE_UNKNOWN      = 0,
  NT_SENSOR_TYPE_TEMPERATURE  = 1, //!< 1/10th of a degree Celsius
  NT_SENSOR_TYPE_VOLTAGE      = 2, //!< 1/100th of a Volt
  NT_SENSOR_TYPE_CURRENT      = 3, //!< Amps uA
  NT_SENSOR_TYPE_POWER        = 4, //!< Watts 1/10th uW
  NT_SENSOR_TYPE_FAN          = 5, //!< Revolutions Per Minute
  NT_SENSOR_TYPE_HIGH_POWER   = 6, //!< Watts
};

/**
 * Sensor subtypes
 */
enum NtSensorSubType_e {
  NT_SENSOR_SUBTYPE_NA = 0,
  NT_SENSOR_SUBTYPE_POWER_OMA,    //!< Subtype for NT_SENSOR_TYPE_POWER type on optical modules (optical modulation amplitude measured)
  NT_SENSOR_SUBTYPE_POWER_AVERAGE //!< Subtype for NT_SENSOR_TYPE_POWER type on optical modules (average power measured)
};

/**
 * Sensor source
 */
enum NtSensorSource_e {
  NT_SENSOR_SOURCE_UNKNOWN        = 0x00,  //!< Unknown source
  NT_SENSOR_SOURCE_PORT           = 0x01,  //!< Sensors located in NIMs
  NT_SENSOR_SOURCE_LEVEL1_PORT    = 0x02,  //!< Level 1 sensors located in NIMs
#ifndef DOXYGEN_INTERNAL_ONLY
  NT_SENSOR_SOURCE_LEVEL2_PORT    = 0x04,  //!< Level 2 sensors located in NIMs
#endif
  NT_SENSOR_SOURCE_ADAPTER        = 0x08,  //!< Sensors mounted on the adapter
  NT_SENSOR_SOURCE_LEVEL1_ADAPTER = 0x10,  //!< Level 2 sensors mounted on the adapter
#ifndef DOXYGEN_INTERNAL_ONLY
  NT_SENSOR_SOURCE_LEVEL2_ADAPTER = 0x20,  //!< Level 3 sensors mounted on the adapter
#endif
};

/**
 * Sensor state
 */
enum NtSensorState_e {
  NT_SENSOR_STATE_UNKNOWN      = 0, //!< Unknown state
  NT_SENSOR_STATE_INITIALIZING = 1, //!< The sensor is initializing
  NT_SENSOR_STATE_NORMAL       = 2, //!< Sensor values are within range
  NT_SENSOR_STATE_ALARM        = 3, //!< Sensor values are out of range
  NT_SENSOR_STATE_NOT_PRESENT  = 4  //!< The sensor is not present. For example, SFP without diagnostic.
};

/**
 * Master/Slave
 */
enum NtBondingType_e {
  NT_BONDING_UNKNOWN,       //!< Unknown bonding type
  NT_BONDING_MASTER,        //!< Adapter is master in the bonding
  NT_BONDING_SLAVE,         //!< Adapter is slave in the bonding
};

/**
 * Maximum name length for streams
 */
#define NT_MAX_STREAM_NAME_LENGTH 20


/**
 * NT20E2 Adapter sensors
 *
 * When reading sensors using the @ref InfoStream @ref NtInfoSensor_t
 * the source must be @ref NtSensorSource_e::NT_SENSOR_SOURCE_ADAPTER to
 * read the public sensors or @ref NtSensorSource_e::NT_SENSOR_SOURCE_LEVEL1_ADAPTER
 * to read the Diagnostic sensors.
 */
enum NtSensorsAdapterNT20E2_e {
  // Public sensors
  NT_SENSOR_NT20E2_FPGA,              //!< FPGA temperature sensor
  NT_SENSOR_NT20E2_FAN,               //!< FAN speed sensor
  NT_SENSOR_NT20E2_MAIN_EXAR1_TEMP,   //!< Mainboard power supply 1 temperature sensor
  NT_SENSOR_NT20E2_MAIN_EXAR2_TEMP,   //!< Mainboard power supply 2 temperature sensor
  NT_SENSOR_NT20E2_FRONT_EXAR_TEMP,   //!< Frontboard power supply temperature sensor
  NT_SENSOR_NT20E2_FRONT_TEMP_PBA,    //!< Frontboard PBA temperature sensor

  // Diagnostic sensors (Level 1)
  NT_SENSOR_NT20E2_NT20E2_POWER,      //!< Total power consumption. Virtual sensor. Does not generate alarms.
  NT_SENSOR_NT20E2_FPGA_POWER,        //!< FPGA power consumption. Virtual sensor. Does not generate alarms.
  NT_SENSOR_NT20E2_DDR3_POWER,        //!< DDR3 RAM power consumption. Virtual sensor. Does not generate alarms.
  NT_SENSOR_NT20E2_PHY_POWER,         //!< PHY power consumption. Virtual sensor. Does not generate alarms.
  NT_SENSOR_NT20E2_SFP_0_POWER,       //!< SFP 0 power consumption. Virtual sensor. Does not generate alarms.
  NT_SENSOR_NT20E2_SFP_1_POWER,       //!< SFP 1 power consumption. Virtual sensor. Does not generate alarms.
  NT_SENSOR_NT20E2_ADAPTER_MAX,       //!< Number of NT20E2 adapter sensors
};

enum NtSensorsPortNT20E2_e {
  // Public sensors
  NT_SENSOR_NT20E2_NIM,               //!< SFP temperature sensor

  // Diagnostic sensors (Level 1)
  NT_SENSOR_NT20E2_SUPPLY,            //!< SFP supply voltage sensor. Does not generate alarms.
  NT_SENSOR_NT20E2_TX_BIAS,           //!< SFP TX bias current sensor. Does not generate alarms.
  NT_SENSOR_NT20E2_TX,                //!< SFP TX power sensor. Does not generate alarms.
  NT_SENSOR_NT20E2_RX,                //!< SFP RX power sensor. Does not generate alarms.
  NT_SENSOR_NT20E2_PORT_MAX,          //!< Number of NT20E2 port sensors
};

enum NtSensorsAdapterNT20E_e {
  // Public sensors
  NT_SENSOR_NT20E_FPGA,               //!< FPGA temperature sensor (Junction temperature)
  NT_SENSOR_NT20E_PBA,                //!< PCB temperature sensor (PCB temperature)
  NT_SENSOR_NT20E_ADAPTER_MAX,        //!< Number of NT20E adapter sensors
};

enum NtSensorsPortNT20E_e {
  // Public sensors
  NT_SENSOR_NT20E_XFP,               //!< XFP temperature sensor

  // Diagnostic sensors (Level 1)
  NT_SENSOR_NT20E_TX_BIAS,           //!< XFP TX bias current sensor. Does not generate alarms.
  NT_SENSOR_NT20E_TX,                //!< XFP TX power sensor. Does not generate alarms.
  NT_SENSOR_NT20E_RX,                //!< XFP RX power sensor. Does not generate alarms.
  NT_SENSOR_NT20E_PORT_MAX,          //!< Number of NT20E port sensors
};

enum NtSensorsAdapterNT4E_e {
  // Public sensors
  NT_SENSOR_NT4E_FPGA,               //!< FPGA temperature sensor (Junction temperature)
  NT_SENSOR_NT4E_PBA,                //!< PCB temperature sensor (PCB temperature)
  NT_SENSOR_NT4E_ADAPTER_MAX,        //!< Number of NT4E adapter sensors
};

enum NtSensorsPortNT4E_e {
  // Public sensors
  NT_SENSOR_NT4E_SFP,                //!< XFP temperature sensor

  // Diagnostic sensors (Level 1)
  NT_SENSOR_NT4E_SUPPLY,             //!< SFP supply voltage sensor. Does not generate alarms.
  NT_SENSOR_NT4E_TX_BIAS,            //!< SFP TX bias current sensor. Does not generate alarms.
  NT_SENSOR_NT4E_TX,                 //!< SFP TX power sensor. Does not generate alarms.
  NT_SENSOR_NT4E_RX,                 //!< SFP RX power sensor. Does not generate alarms.
  NT_SENSOR_NT4E_PORT_MAX,           //!< Number NT4E of port sensors
};

#endif //__COMMONTYPES_H__
