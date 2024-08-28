// $Id: stream_config.h 17165 2012-01-31 13:56:35Z lm $
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
 * This header file is the STREAMTYPE_CONFIG interface
 *
 */
#ifndef __STREAM_CONFIG_H__
#define __STREAM_CONFIG_H__

/** @addtogroup ConfigStream
 * @{
 * @brief Configuration stream interface
 *
 * Configuration streams are used to read and write configuration data
 * and to set the filter configuration using NTPL commands. This
 * includes everything that can be changed on the fly. All static
 * configuration is done in the <tt>ntservice.ini</tt> file.
 *
 * All configuration parameters are organized in a parameter tree
 * structure @ref NtConfig_t where some parameters are read only (static
 * configuration parameters) and some parameters are read and write
 * (dynamic configuration parameters).
 *
 * To open a configuration stream call @ref NT_ConfigOpen. Once the
 * configuration stream is open use @ref NT_ConfigRead and @ref
 * NT_ConfigWrite with the @ref NtConfig_t structure to retrieve and
 * change the configuration. When done, call @ref NT_ConfigClose to close
 * the stream.
 *
 * @note Changing a configuration setting will trigger an @ref
 * NtEventSource_e::NT_EVENT_SOURCE_CONFIG
 * "NT_EVENT_SOURCE_CONFIG" when the changes have been made
 *
 * The configuration parameter types currently supported are:
 * @li <tt>Port settings</tt> - retrieves or changes link speed, IFG, MDI mode
 * @li <tt>Time stamp type</tt> Retrieves or changes time stamp configuration
 * @li <tt>Time synchronization</tt> Retrieves or changes time synchronization configuration
 *
 * To set up or change filter configuration using NTPL commands use
 * the @ref NT_NTPL function call on an open configuration stream. For
 * a complete description of the NTPL syntax see @ref
 * NtplOverview "NTPL Overview".
 *
 * For an example of using the configuration stream see @ref
 * config/config.c "config/config.c".
 */

/**
 * Configuration parameters
 */
enum NtConfigParm_e {
  NT_CONFIG_PARM_PORT_SETTINGS = 1,    //!< Port settings configuration parameter - Use @ref NtConfigReadPort_s
  NT_CONFIG_PARM_ADAPTER_TIMESTAMP,    //!< Time stamp configuration parameter - Use @ref NtConfigTimestampRead_s or @ref NtConfigTimestampWrite_s
  NT_CONFIG_PARM_ADAPTER_TIMESYNC,     //!< Time synchronization configuration parameter - Use @ref NtConfigTimesyncWrite_s
  NT_CONFIG_PARM_SENSOR,               //!< Sensor configuration parameter - Use @ref NtConfigSensor_s
  NT_CONFIG_PARM_STREAM,               //!< Stream configuration parameter - Use @ref NtConfigReadStream_s or NtConfigWriteStream_s
};

/**
 * Configuration stream handle
 */
typedef struct NtConfigStream_s* NtConfigStream_t;

/**
 * The settings reflect how the interface should be configured.
 * The advertise section tells what should be advertised when
 * autonegotiation is enabled.
 * halfDuplexMask=0.
 * fullDuplexMask=NT_LINK_SPEED_100M.
 *
 * @internal
 * Note: This is part of the NTDS structure. Changing this requires the service to be recompiled.
 */
struct NtPortSettings_s {
  int enable;           //!< 0 = Disable interface, 1 = Enable interface
  int flow;             //!< 0 = No flow control, 1 = Flow control
  enum NtLinkMDI_e mdi; //!< MDI mode
  enum NtLinkAutoNeg_e autoNegotiation;  //!< Manual speed, Auto
  /**
   * Array of manual port setting parameters
   */
  struct NtPortSettingsManual_s {
    enum NtLinkSpeed_e speed;   //!< The interface speed - this is in effect if autoNegotiation = 0
    enum NtLinkDuplex_e duplex; //!< The duplex mode - this is in effect if autoNegotiation = 0
  } manual;
  /**
   * Array of parameters to be advertised when autonegotiation is enabled
   */
  struct NtPortSettingsAdvertise_s {
    uint32_t halfDuplexMask; //!< Available half duplex (Uses @ref NtLinkSpeed_e as bitmask)
    uint32_t fullDuplexMask; //!< Available full duplex (Uses @ref NtLinkSpeed_e as bitmask)
  } advertise;
  uint32_t minIFG; //!< The minimum inter-frame gap
  uint32_t maxIFG; //!< The maximum inter-frame gap

  enum NtTxPower_e TxPower; //!< TX power state on read and cmd on write. Controls laser power on/off on fiber SFP, XFP, SFP+ and QSFP+ modules. Note that not all modules support enable/disable of the laser. An error code is returned if not supported.
};


/***********************************************************************
 * Config read and write port settings - NT_CONFIG_PARM_PORT_SETTINGS. *
 ***********************************************************************/
struct NtConfigReadPort_s {
  uint32_t portNo;                //!< Port number to read from
  struct NtPortSettings_s data;   //!< Port settings
};

/************************************************************
 * Config read timestamp - NT_CONFIG_PARM_ADAPTER_TIMESTAMP *
 ************************************************************/
struct NtConfigTimestampRead_s {
  uint32_t adapter;                //!< Adapter number to read from
  struct NtConfigTimestampReadData_s {
    uint64_t ts;                    //!< The time stamp
    uint64_t nativeUnixTs;          //!< Value converted to native Unix (read only)
    enum NtTimestampType_e tsType;  //!< The time stamp type used by the adapter
  } data;
};

/*************************************************************
 * Config write timestamp - NT_CONFIG_PARM_ADAPTER_TIMESTAMP *
 *************************************************************/
struct NtConfigTimestampWrite_s {
  uint32_t adapter;               //!< Adapter number to write to
  struct NtConfigTimestampWriteData_s {
    uint64_t ts;                  //!< The time stamp
    uint32_t bCurrent;            //!< Uses current OS time
  } data;
};

/****************************************************************
 * Config write timesync data - NT_CONFIG_PARM_ADAPTER_TIMESYNC *
 ****************************************************************/
struct NtConfigTimesyncWrite_s {
  uint32_t adapter;               //!< Adapter number to write to
  struct NtConfigTimesyncWriteData_s {
    uint32_t action;              //!< 0 = Reference time, 1 = Enable PPS, 2 = Disable PPS
    uint64_t refTime;             //!< PPS reference time
  } data;
};

/****************************************************
 * Config write sensor data - NT_CONFIG_PARM_SENSOR *
 ****************************************************/
struct NtConfigSensor_s {
  enum NtSensorSource_e source; //!< The source of the sensor - either a port or an adapter sensor
  int sourceIndex;              //!< The source index - either adapter number or port number on which the sensor resides
  int sensorIndex;              //!< The sensor index within the sensor group, see @ref MainDocMainFeaturesInfo_Sensors
  struct NtConfigSensorData_s {
    int32_t limitLow;           //!< The minimum sensor value before an alarm is triggered
    int32_t limitHigh;          //!< The maximum sensor value before an alarm is triggered
  } data;
};

/*******************************************************
 * Config read stream settings - NT_CONFIG_PARM_STREAM *
 *******************************************************/
struct NtConfigReadStream_s {
  int streamId;
  struct NtConfigReadStreamData_s {
    int hostBufferAllowance;    // TODO:
  } data;
};

/********************************************************
 * Config write stream settings - NT_CONFIG_PARM_STREAM *
 ********************************************************/
struct NtConfigWriteStream_s {
  int streamId;
  struct NtConfigWriteStreamData_s {
    int hostBufferAllowance;    // TODO:
  } data;
};

/**
 * Config change information
 */
typedef struct NtConfig_s {
  enum NtConfigParm_e parm;  //!<Configuration parameter
  union NtConfig_u {
    struct NtConfigReadPort_s  portSettings;               //!< Port setting struct is used when reading or writing using command @ref NT_CONFIG_PARM_PORT_SETTINGS
    struct NtConfigTimestampRead_s timestampRead;          //!< Time stamp read struct is used when reading using command @ref NT_CONFIG_PARM_ADAPTER_TIMESTAMP
    struct NtConfigTimestampWrite_s timestampWrite;        //!< Time stamp write struct is used when writing using command @ref NT_CONFIG_PARM_ADAPTER_TIMESTAMP
    struct NtConfigTimesyncWrite_s  timesyncWrite;         //!< Time sync write struct is used when writing using command @ref NT_CONFIG_PARM_ADAPTER_TIMESYNC
    struct NtConfigSensor_s  sensorWrite;                  //!< Sensor write struct is used when writing using command @ref NT_CONFIG_PARM_SENSOR
    struct NtConfigReadStream_s streamRead;                //!< Stream read struct is used when reading using command @ref NT_CONFIG_PARM_STREAM
    struct NtConfigWriteStream_s streamWrite;              //!< Stream write struct is used when writing using command @ref NT_CONFIG_PARM_STREAM
  } u;
} NtConfig_t;

/****************************************************************/
/* NTPL Info data structures                                       */
/****************************************************************/
/**
 * NTPL commands
 */
enum NtNTPLCommands_e {
  NT_NTPL_PARSER_VALIDATE_NORMAL,
  NT_NTPL_PARSER_VALIDATE_PARSE_ONLY,
};

/**
 * NTPL parser error description and error code
 */
struct NtNtplParserErrorData_s {
#define NT_MAX_NTPL_BUFFER_SIZE (4*1024)            //!< NTPL maximum buffer size
  char     errBuffer[3][NT_MAX_NTPL_BUFFER_SIZE];   //!< NTPL error description
  int32_t  errCode;                                 //!< NTPL error code
};

/**
 * NTPL filter counters
 */
struct NtNtplFilterCounters_s {
  uint8_t	sizeCount;        //!< Number of frame length filters used
  uint8_t	protocolCount;    //!< Number of protocol filters used
  uint8_t	errorCount;       //!< Number of error filters used
  uint8_t	patternCount;     //!< Number of data filters used
  uint8_t	dynOffsetCount;   //!< Number of dynamic offsets used
  uint8_t	group4PlusCount;  //!< Number of group filters used combining 4 patterns with 4 different dynamic offsets
  uint8_t	group8Count;      //!< Number of group filters used combining 8 patterns with 2 different dynamic offsets
};

/**
 * NTPL return values
 */
enum NtNTPLReturnType_e {
  NT_NTPL_PARSER_NORMAL,          //!< No error data returned
  NT_NTPL_PARSER_ERROR_DATA,      //!< Error data returned - errorData is filled
  NT_NTPL_PARSER_FILTERINFO,      //!< Filter info data returned
};

/**
 * NTPL Info
 */
typedef struct NtNtplInfo_s {
  enum NtNTPLReturnType_e eType;          //!< Returned status
  uint32_t                ntplId;         //!< ID of the NTPL command
  uint32_t                streamId;       //!< The selected stream ID
  uint64_t                ts;             //!< Time when the NTPL command is in effect
  enum NtTimestampType_e  timestampType;  //!< The time stamp type of NtNtplInfo_t::ts
  /**
   * NTPL return data.
   * Error or filter information.
   */
#ifndef DOXYGEN_INTERNAL_ONLY
  uint32_t reserved[50];
#endif
  union NtplReturnData_u {
    struct NtNtplParserErrorData_s errorData;       //!< Error code and error text
    struct NtNtplFilterCounters_s  aFilterInfo[10]; //!< Filter counters, such as size and error counters - per adapter
  } u;
} NtNtplInfo_t;

/**
 * @brief Opens a configuration stream
 *
 * This function is called to retrieve a handle to a configuration stream
 *
 * @param[out] hStream          Reference to an NtConfigStream_t stream pointer
 * @param[in]  name             Stream friendly name - used in, for example, logging statements
 *
 * @retval  0    Success
 * @retval !=0   Error
 */
int NT_ConfigOpen(NtConfigStream_t *hStream, const char *name);

/**
 * @brief Closes a configuration stream
 *
 * This function is called to close a configuration stream
 *
 * @param[in] hStream          Reference to a NtConfigStream_t stream pointer
 *
 * @retval  0    Success
 * @retval !=0   Error
 */
int NT_ConfigClose(NtConfigStream_t hStream);

/**
 * @brief Reads data from a configuration stream
 *
 * Returns configuration data
 *
 * @param[in]      hStream   NtSystemStream_t handle
 * @param[in,out]  data      NtConfig_t structure containing configuration query and serving as output buffer for data
 *
 * @retval  0    Success
 * @retval !=0   Error
 */
int NT_ConfigRead(NtConfigStream_t hStream, NtConfig_t *data);

/**
 * @brief Writes data to a configuration stream
 *
 * Writes configuration data
 *
 * @param[in]      hStream   NtSystemStream_t handle
 * @param[in,out]  data      NtConfig_t structure containing the configuration to write
 *
 * @retval  0    Success
 * @retval !=0   Error
 */
int NT_ConfigWrite(NtConfigStream_t hStream, NtConfig_t *data);

/**
 * @brief Sends an NTPL line buffer to the parser.
 *
 * This function is used to send an NTPL line buffer to the
 * parser. The target stream is defined by the hStream stream
 * handle.
 *
 * When using validate mode no data is written to the adapter. The
 * different modes define how far down the parsing is done.
 *
 * Note: Return data is stored in the stream handle and must be
 * read by the HAL functions.
 *
 * @param[in]  hStream    Target stream for the NTPL
 * @param[in]  ntplBuffer NTPL line buffer containing NTPL code
 * @param[in]  info       NTPL Info
 * @param[in]  validate   Set parsing mode to validate
 *
 * @retval  NT_SUCCESS
 * @retval  NT_ERROR_WRONG_STREAM_TYPE
 * @retval  NT_ERROR_NT_SERVICE_NOT_STARTED
 * @retval  NT_ERROR_INVALID_STREAM_POINTER
 * @retval  NT_ERROR_INVALID_STREAM_HANDLE
 * @retval  NT_ERROR_WRONG_STREAM_TYPE
 */
int NT_NTPL(NtConfigStream_t hStream, const char *ntplBuffer, NtNtplInfo_t *info, uint32_t validate);

/** @} */

#endif // __STREAM_CONFIG_H__
