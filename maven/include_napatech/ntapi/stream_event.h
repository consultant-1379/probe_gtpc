// $Id: stream_event.h 17968 2012-03-19 15:11:29Z bk $
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
 * This header file contains the STREAMTYPE_EVENT interface
 */
#ifndef __STREAM_EVENT_H__
#define __STREAM_EVENT_H__

/** @addtogroup EventStream
 * @{
 *
 * Event streams are used to get various events from the system. The
 * event stream is a read only stream.
 *
 * To open an event stream call @ref NT_EventOpen. Once the event
 * stream is open it will receive all system events. An application
 * that requires certain events will open an event stream and
 * read the events one by one. The application can then react on the
 * events that it wants to react on and ignore the rest. Once done,
 * call @ref NT_EventClose to close the stream.
 *
 * The events types currently supported are:
 * @li <tt>Port events</tt> These events are link up and link down events.
 * @li <tt>Sensor events</tt> These events are sensor alarm state changes.
 * @li <tt>Config events</tt> These events are sent when a configuration change has been made.
 * @li <tt>Time sync events</tt> These events are time synchronization state changes.
 *
 * For an example on how to use the event stream see @ref
 * event/event.c "event/event.c".
 *
 */

/**
 * The event types supported
 * Note: MUST be bitmasks
 */
enum NtEventSource_e {
  NT_EVENT_SOURCE_PORT             = (1 << 0),    //!< Bit for port event - Data placed in @ref NtEventPort_s
  NT_EVENT_SOURCE_SENSOR           = (1 << 1),    //!< Bit for sensor change event - Data placed in @ref NtEventSensor_s
  NT_EVENT_SOURCE_CONFIG           = (1 << 2),    //!< Bit for config change made events - Data placed in @ref NtConfig_s
  NT_EVENT_SOURCE_TIMESYNC         = (1 << 3),    //!< Bit for time sync events - Data placed in @ref NtEventTimeSync_s
  NT_EVENT_SOURCE_SDRAM_FILL_LEVEL = (1 << 4),    //!< Bit for host buffer fill level warning - Data placed in @ref NtSDRAMFillLevel_s
  NT_EVENT_SOURCE_ALL              = (NT_EVENT_SOURCE_PORT |
                                      NT_EVENT_SOURCE_SENSOR |
                                      NT_EVENT_SOURCE_CONFIG |
                                      NT_EVENT_SOURCE_TIMESYNC |
                                      NT_EVENT_SOURCE_SDRAM_FILL_LEVEL) ,   //!< Bits for all events
};

/**
 * Port events
 */
enum NtEventPort_e {
  NT_EVENT_PORT_LINK_UP,      //!< Port link up event
  NT_EVENT_PORT_LINK_DOWN,    //!< Port link down event
  NT_EVENT_RXAUI_LINK_ERROR,  //!< Port RXAUI link error
};

/**
 * Sensor events
 */
enum NtEventSensor_e {
  NT_EVENT_SENSOR_ALARM_STATE_ENTRY, //!< Sensor enters alarm state
  NT_EVENT_SENSOR_ALARM_STATE_EXIT,  //!< Sensor exits alarm state
};

/**
 * Event time sync information
 */
enum NtEventTimeSync_e {
  NT_EVENT_TIMESYNC_PPS_REQUEST_TIME,   //!< Request for PPS reference time
};

/**
 * Event link up/down information
 */
struct NtEventPort_s {
  enum NtEventPort_e action;  //!< Port action
  int portNo;                 //!< Port generating the event
};

/**
 * Event SDRAM fill level information
 */
#define MAX_SDRAM_FILL_LEVEL_STREAMS 256
struct NtSDRAMFillLevel_s {
  uint32_t adapterNo;  //!< The adapter owning the host buffer
  uint32_t streamsId;  //!< Stream ID using the host buffer
  uint32_t numStreams; //!< Number of streams using the host buffers. Also indicating the use depth of @ref aStreams.
  uint64_t used;       //!< SDRAM used. This shows the amount of adapter memory used. One must pay attention to this value.
                       //!< When the value is close to used, it means that the adapter has used all the buffer memory.
                       //!< This happens if the adapter is not able to transfer the received data to the host buffers on the PC
                       //!< and is mainly caused by a slow application not being able to release the data fast enough.
                       //!< Packet loss will probably occur.
  uint64_t size;       //!< The amount of SDRAM reserved for this host buffer
  /**
   * This structure tells where the host buffer is currently used.
   */
  struct NtHostBuffer_s {
    uint64_t deQueued;          //!< Bytes available or in use by the streams.
                                //!< If all data is placed here it means that the application is too slow to handle the data.
                                //!< The application is not able to release the packets (host buffer) fast enough so the data is
                                //!< ready for the driver and adapter to fill with new data. The result is that the adapter runs
                                //!< out of data space and a packet loss occurs.
    uint64_t enQueued;          //!< Bytes available to the host buffer handler.
                                //!< If all data is placed here it means that the driver is too slow to handle the data.
                                //!< This is a driver error and should never happen.
    uint64_t enQueuedAdapter;   //!< Bytes currently in the adapter.
                                //!< Most of the time the data should be placed here.
    uint64_t size;              //!< Host buffer size
  } hb;
  /**
   * the array of streams using the host buffer
   */
  struct NtStream_s {
    int streamIndex;        //!< The index for the stream attached to the host buffer
    uint64_t enQueued;      //!< The data currently enqueued to the stream. The stream with the largest enqueued amount is the slowest stream and probably the one that causes the packet loss.
    uint64_t processID;     //!< The process owning the stream
  } aStreams[MAX_SDRAM_FILL_LEVEL_STREAMS];
};

/**
 * Event sensor change information
 */
struct NtEventSensor_s {
  enum NtSensorSource_e source;      //!< The source of the sensor (the port or adapter on which the sensor resides)
  int sourceIndex;                   //!< The source index - the adapter number or port number where the sensor resides
  int sensorIndex;                   //!< The sensor index - the index of the sensor within the group of sensors. Each adapter or port has a different number and sensor type.
                                     //!< - NT20E2 adapter sensor group - @ref NtSensorsAdapterNT20E2_e
                                     //!< - NT20E2 port sensor group - @ref NtSensorsPortNT20E2_e
                                     //!< - NT20E adapter sensor group - @ref NtSensorsAdapterNT20E_e
                                     //!< - NT20E port sensor group - @ref NtSensorsPortNT20E_e
                                     //!< - NT4E adapter sensor group - @ref NtSensorsAdapterNT4E_e
                                     //!< - NT4E port sensor group - @ref NtSensorsPortNT4E_e
  enum NtEventSensor_e action;       //!< Whether the alarm is entered or exited
  int value;                         //!< The value that triggered the event
  enum NtAdapterType_e adapterType;  //!< The adapter type triggering the event
};

/**
 * Time sync information
 */
struct NtEventTimeSync_s {
  enum NtEventTimeSync_e action;  //!< What happened
  int adapter;                    //!< Which adapter generated the event
};


/**
 * Event information
 */
typedef struct NtEvent_s {
  enum NtEventSource_e type;    //!< Event type
  /**
   * Union holding event information
  */
  union NtEvent_u {
    struct NtEventPort_s   portEvent;                         //!< Port events - @ref NT_EVENT_SOURCE_PORT
    struct NtEventSensor_s sensorEvent;                       //!< Sensor events - @ref NT_EVENT_SOURCE_SENSOR
    struct NtConfig_s configEvent;                            //!< Config events - @ref NT_EVENT_SOURCE_CONFIG
    struct NtEventTimeSync_s timeSyncEvent;                   //!< Time sync events - @ref NT_EVENT_SOURCE_TIMESYNC
    struct NtSDRAMFillLevel_s sdramFillLevelEvent;              //!< Host buffer usage event - @ref NT_EVENT_SOURCE_SDRAM_FILL_LEVEL
  } u;
} NtEvent_t;


/**
 * Event stream handle
 */
typedef struct NtEventStream_s* NtEventStream_t;

/**
 * @brief Opens an event stream and initializes event queues, etc.
 *
 * This function must be called before using the events. The necessary
 * stream, lists, mutexes and semaphores are initialized and
 * created.
 *
 * @param[in,out] hStream   Pointer to the stream handle
 * @param[in]     name      A friendly name of the stream
 * @param[in]     eventMask @ref NtEventSource_e - A bitmask defining the sources of events to receive.
 *
 * @retval  == NT_SUCCESS: SUCCESS
 * @retval  != NT_SUCCESS: Error
 */
int NT_EventOpen(NtEventStream_t *hStream, const char *name, uint32_t eventMask);

/**
 * @brief Reads an event from an event queue
 *
 * This function is called by the user to read an event.
 * The event is copied from the event queue to the
 * stream handle for the user to read using the HAL functions.
 * The event is marked as read for deletion and cannot be
 * read by the user again. The event is deleted by NT_Put.
 *
 *
 * @param[in] hStream       Stream to store the current event
 * @param[out] event        Event structure. The event information is returned in this structure.
 * @param[in] timeout       Time to wait for an event in milliseconds
 *
 * @retval  NT_SUCCESS.
 * @retval  NT_ERROR_NT_SERVICE_NOT_STARTED.
 * @retval  NT_ERROR_INVALID_STREAM_POINTER.
 * @retval  NT_ERROR_INVALID_STREAM_HANDLE.
 * @retval  NT_ERROR_INVALID_STREAM_POINTER.
 * @retval  NT_ERROR_WRONG_STREAM_TYPE.
 * @retval  NT_ERROR_UNKNOWN_ERROR.
 * @retval  NT_ERROR_FAILED_GETTING_FASTLOCK.
 */
int NT_EventRead(NtEventStream_t hStream, NtEvent_t *event, uint32_t timeout);

/**
 * @brief Releases the stream and clears event queues, etc.
 *
 * This function must be called after using the events in order
 * to release the stream and clear the allocated lists, mutexes
 * and semaphores.
 *
 * @param[in] hStream Pointer to the stream handle
 *
 * @retval  NT_SUCCESS.
 * @retval  NT_ERROR_NT_SERVICE_NOT_STARTED.
 * @retval  NT_ERROR_INVALID_STREAM_POINTER.
 * @retval  NT_ERROR_INVALID_STREAM_HANDLE.
 * @retval  NT_ERROR_INVALID_STREAM_POINTER.
 * @retval  NT_ERROR_WRONG_STREAM_TYPE.
 */
int NT_EventClose(NtEventStream_t hStream);

/** @} */

#endif /* __STREAM_EVENT_H__ */
