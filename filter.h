/*++

Copyright (c) 2001  Microsoft Corporation

Module Name:

    Filter.h

Abstract:

    This module contains all prototypes and macros for filter code.

Revision History:

    Who         When        What
    --------    --------    ----------------------------------------------

Notes:

--*/
#ifndef _FILT_H
#define _FILT_H

#define   FILTER_REQUEST_ID          'RTLF'

#define FILTER_MAJOR_NDIS_VERSION   6
#define FILTER_MINOR_NDIS_VERSION   0


#define MAX_PACKET_POOL_SIZE    0x0000FFFF
#define MIN_PACKET_POOL_SIZE    0x000000FF
#define PROTOCOL_RESERVED       4

//
// Flags for filter's state
//
#define FILTER_PAUSING          0x00000001
#define FILTER_PAUSED           0x00000002
#define FILTER_DETACHING        0x00000004
#define FILTER_ATTACHED         0x00000008
#define FILTER_RUNNING          0x00000010


#define FILTER_ALLOC_TAG                         'tliF'
#define FILTER_TAG                               'dnTF'

//
// Global variables
// 
extern NDIS_HANDLE         FilterDriverHandle; // NDIS handle for filter driver
extern NDIS_HANDLE         FilterDriverObject;
extern NDIS_HANDLE         NdisFilterDeviceHandle;
extern PDEVICE_OBJECT      DeviceObject;

extern FILTER_LOCK         FilterListLock;
extern LIST_ENTRY          FilterModuleList;
extern PWCHAR              InstanceStrings;


#if NDISLWF
#define FILTER_FRIENDLY_NAME        L"Packet11 Service Filter"
#define FILTER_UNIQUE_NAME          L"{5cbf81bd-5055-47cd-9055-a76b2b4e3697}" //unique name, quid name
#define FILTER_SERVICE_NAME         L"Packet11"
//
// The filter needs to handle IOCTRLs
//
#define LINKNAME_STRING             L"\\DosDevices\\Packet11"
#define NTDEVICE_STRING             L"\\Device\\Packet11"
#endif


#if NDISLWF1
#define FILTER_FRIENDLY_NAME        L"NDIS Sample LightWeight Filter 1"
#define FILTER_UNIQUE_NAME          L"{5cbf81be-5055-47cd-9055-a76b2b4e3697}" //unique name, quid name
#define FILTER_SERVICE_NAME         L"NDISLWF1"
//
// The filter needs to handle IOCTRLs
//
#define LINKNAME_STRING             L"\\DosDevices\\NDISLWF1"
#define NTDEVICE_STRING             L"\\Device\\NDISLWF1"
#endif

#if NDISMON
#define FILTER_FRIENDLY_NAME        L"NDIS Sample Monitor LightWeight Filter"
#define FILTER_UNIQUE_NAME          L"{5cbf81bf-5055-47cd-9055-a76b2b4e3697}" //unique name, quid name
#define FILTER_SERVICE_NAME         L"NDISMON"
//
// The filter needs to handle IOCTRLs
//
#define LINKNAME_STRING             L"\\DosDevices\\NDISMON"
#define NTDEVICE_STRING             L"\\Device\\NDISMON"
#endif

#if NDISMON1
#define FILTER_FRIENDLY_NAME        L"NDIS Sample Monitor 1 LightWeight Filter"
#define FILTER_UNIQUE_NAME          L"{5cbf81c0-5055-47cd-9055-a76b2b4e3697}" //unique name, quid name
#define FILTER_SERVICE_NAME         L"NDISMON1"
//
// The filter needs to handle IOCTRLs
//
#define LINKNAME_STRING             L"\\DosDevices\\NDISMON1"
#define NTDEVICE_STRING             L"\\Device\\NDISMON1"
#endif


//
// Types and macros to manipulate packet queue
// 
typedef struct _QUEUE_ENTRY
{
    struct _QUEUE_ENTRY * Next;
}QUEUE_ENTRY, *PQUEUE_ENTRY;

typedef struct _QUEUE_HEADER
{
    PQUEUE_ENTRY     Head;
    PQUEUE_ENTRY     Tail;
} QUEUE_HEADER, PQUEUE_HEADER;


#if TRACK_RECEIVES
UINT         filterLogReceiveRefIndex = 0;
ULONG_PTR    filterLogReceiveRef[0x10000];
#endif

#if TRACK_SENDS
UINT         filterLogSendRefIndex = 0;
ULONG_PTR    filterLogSendRef[0x10000];
#endif

#if TRACK_RECEIVES
#define   FILTER_LOG_RCV_REF(_O, _Instance, _NetBufferList, _Ref)    \
    {\
        filterLogReceiveRef[filterLogReceiveRefIndex++] = (ULONG_PTR)(_O); \
        filterLogReceiveRef[filterLogReceiveRefIndex++] = (ULONG_PTR)(_Instance); \
        filterLogReceiveRef[filterLogReceiveRefIndex++] = (ULONG_PTR)(_NetBufferList); \
        filterLogReceiveRef[filterLogReceiveRefIndex++] = (ULONG_PTR)(_Ref); \
        if (filterLogReceiveRefIndex >= (0x10000 - 5))                    \
        {                                                              \
            filterLogReceiveRefIndex = 0;                                 \
        }                                                              \
    }  
#else
#define   FILTER_LOG_RCV_REF(_O, _Instance, _NetBufferList, _Ref)
#endif

#if TRACK_SENDS
#define   FILTER_LOG_SEND_REF(_O, _Instance, _NetBufferList, _Ref)    \
    {\
        filterLogSendRef[filterLogSendRefIndex++] = (ULONG_PTR)(_O); \
        filterLogSendRef[filterLogSendRefIndex++] = (ULONG_PTR)(_Instance); \
        filterLogSendRef[filterLogSendRefIndex++] = (ULONG_PTR)(_NetBufferList); \
        filterLogSendRef[filterLogSendRefIndex++] = (ULONG_PTR)(_Ref); \
        if (filterLogSendRefIndex >= (0x10000 - 5))                    \
        {                                                              \
            filterLogSendRefIndex = 0;                                 \
        }                                                              \
    }  

#else
#define   FILTER_LOG_SEND_REF(_O, _Instance, _NetBufferList, _Ref)
#endif


//
// DEBUG related macros.
//
#if DBG
#define FILTER_ALLOC_MEM(_NdisHandle, _Size)    \
    filterAuditAllocMem(                        \
            _NdisHandle,                        \
           _Size,                               \
           __FILENUMBER,                        \
           __LINE__);  

#define FILTER_FREE_MEM(_pMem)                  \
    filterAuditFreeMem(_pMem);

#else
#define FILTER_ALLOC_MEM(_NdisHandle, _Size)     \
    NdisAllocateMemoryWithTagPriority(_NdisHandle, _Size, FILTER_ALLOC_TAG, LowPoolPriority)

#define FILTER_FREE_MEM(_pMem)    NdisFreeMemory(_pMem, 0, 0)

#endif //DBG

#if DBG_SPIN_LOCK
#define FILTER_INIT_LOCK(_pLock)                          \
    filterAllocateSpinLock(_pLock, __FILENUMBER, __LINE__)

#define FILTER_FREE_LOCK(_pLock)       filterFreeSpinLock(_pLock)


#define FILTER_ACQUIRE_LOCK(_pLock, DispatchLevel)  \
    filterAcquireSpinLock(_pLock, __FILENUMBER, __LINE__, DisaptchLevel)

#define FILTER_RELEASE_LOCK(_pLock, DispatchLevel)      \
    filterReleaseSpinLock(_pLock, __FILENUMBER, __LINE__, DispatchLevel)
    
#else
#define FILTER_INIT_LOCK(_pLock)      NdisAllocateSpinLock(_pLock)

#define FILTER_FREE_LOCK(_pLock)      NdisFreeSpinLock(_pLock)

#define FILTER_ACQUIRE_LOCK(_pLock, DispatchLevel)              \
    {                                                           \
        if (DispatchLevel)                                      \
        {                                                       \
            NdisDprAcquireSpinLock(_pLock);                     \
        }                                                       \
        else                                                    \
        {                                                       \
            NdisAcquireSpinLock(_pLock);                        \
        }                                                       \
    }
                
#define FILTER_RELEASE_LOCK(_pLock, DispatchLevel)              \
    {                                                           \
        if (DispatchLevel)                                      \
        {                                                       \
            NdisDprReleaseSpinLock(_pLock);                     \
        }                                                       \
        else                                                    \
        {                                                       \
            NdisReleaseSpinLock(_pLock);                        \
        }                                                       \
    }
#endif //DBG_SPIN_LOCK

    
#define NET_BUFFER_LIST_LINK_TO_ENTRY(_pNBL)    ((PQUEUE_ENTRY)(NET_BUFFER_LIST_NEXT_NBL(_pNBL)))
#define ENTRY_TO_NET_BUFFER_LIST(_pEnt)         (CONTAINING_RECORD((_pEnt), NET_BUFFER_LIST, Next))
    
#define InitializeQueueHeader(_QueueHeader)             \
{                                                       \
    (_QueueHeader)->Head = (_QueueHeader)->Tail = NULL; \
}

//
// Macros for queue operations
//
#define IsQueueEmpty(_QueueHeader)      ((_QueueHeader)->Head == NULL)

#define RemoveHeadQueue(_QueueHeader)                   \
    (_QueueHeader)->Head;                               \
    {                                                   \
        PQUEUE_ENTRY pNext;                             \
        ASSERT((_QueueHeader)->Head);                   \
        pNext = (_QueueHeader)->Head->Next;             \
        (_QueueHeader)->Head = pNext;                   \
        if (pNext == NULL)                              \
            (_QueueHeader)->Tail = NULL;                \
    }

#define InsertHeadQueue(_QueueHeader, _QueueEntry)                  \
    {                                                               \
        ((PQUEUE_ENTRY)(_QueueEntry))->Next = (_QueueHeader)->Head; \
        (_QueueHeader)->Head = (PQUEUE_ENTRY)(_QueueEntry);         \
        if ((_QueueHeader)->Tail == NULL)                           \
            (_QueueHeader)->Tail = (PQUEUE_ENTRY)(_QueueEntry);     \
    }

#define InsertTailQueue(_QueueHeader, _QueueEntry)                      \
    {                                                                   \
        ((PQUEUE_ENTRY)(_QueueEntry))->Next = NULL;                     \
        if ((_QueueHeader)->Tail)                                       \
            (_QueueHeader)->Tail->Next = (PQUEUE_ENTRY)(_QueueEntry);   \
        else                                                            \
            (_QueueHeader)->Head = (PQUEUE_ENTRY)(_QueueEntry);         \
        (_QueueHeader)->Tail = (PQUEUE_ENTRY)(_QueueEntry);             \
    }                                                                               


//
// Enum of filter's states
// Filter can only be in one state at one time
//
typedef enum _FILTER_STATE
{
    FilterStateUnspecified,
    FilterInitialized,
    FilterPausing,
    FilterPaused,
    FilterRunning,
    FilterRestarting,
    FilterDetaching
} FILTER_STATE;


typedef struct _FILTER_REQUEST
{
    NDIS_OID_REQUEST       Request;
    NDIS_EVENT             ReqEvent;
    NDIS_STATUS            Status;
} FILTER_REQUEST, *PFILTER_REQUEST;


typedef struct _struc1
{
  CHAR gap_0[12];
  USHORT field_C;
  CHAR gap_E[2];
  ULONG th_seq;
  CHAR gap_14[4];
  USHORT th_stream_cnt;
  CHAR gap_1A[2];
} struc1;

//
// Define the filter struct 
//
typedef struct _MS_FILTER
{
    LIST_ENTRY                     FilterModuleLink;
    //Reference to this filter
    ULONG                           RefCount;
    
    NDIS_HANDLE                     FilterHandle;
    NDIS_STRING                     FilterModuleName;
    NDIS_STRING                     MiniportFriendlyName;
    NDIS_STRING                     MiniportName;
    NET_IFINDEX                     MiniportIfIndex;

    NDIS_STATUS                     Status;
    NDIS_EVENT                      Event;
    ULONG                           BackFillSize;
    FILTER_LOCK                     Lock;    // Lock for protection of state and outstanding sends and recvs

    FILTER_STATE                    State;   // Which state the filter is in
    ULONG                           Flags;   // contains the state of the filter
    ULONG                           OutstandingSends;
    ULONG                           OutstandingRequest;
    ULONG                           OutstandingRcvs;
    FILTER_LOCK                     SendLock;
    FILTER_LOCK                     RcvLock;
    QUEUE_HEADER                    SendNBLQueue;
    QUEUE_HEADER                    RcvNBLQueue;


    NDIS_STRING                     FilterName;
    ULONG                           CallsRestart;
    BOOLEAN                         TrackReceives;
    BOOLEAN                         TrackSends;
#if DBG    
    BOOLEAN                         bIndicating;
#endif    

    PNDIS_OID_REQUEST               PendingOidRequest;
    
    NDIS_HANDLE SendNblPool;
    NDIS_HANDLE SendNbPool;
    NDIS_HANDLE pool_derived_from_nbl;
    CHAR gap_A0[36];
    NDIS_HANDLE RecvNblPool;
    NDIS_MEDIUM MiniportMediaType;
    CHAR gap_CC[4];
    ULONG MediaConnectState;
    DOT11_MAC_ADDRESS CurrentMacAddress;
    CHAR gap_DA[58];
    UCHAR field_114[6];
    CHAR gap_115[26];
    UCHAR field_134[6];
    CHAR gap_135[26];
    UCHAR field_154[4];
    CHAR field_158[4];
    USHORT IntervalStartMs;
    CHAR gap_15E[2];
    USHORT PktsSentPerInterval;
    USHORT field_162;
    USHORT field_164;
    USHORT field_166;
    USHORT tcp_stream_cnt;
    CHAR field_16A[4];
    CHAR field_16E[4];
    UCHAR field_172;
    UCHAR field_173;
    UCHAR field_174;
    CHAR gap_175[7];
    struc1 field_17C[10];
    UCHAR field_294;
    CHAR gap_295[72];
    unsigned __int8 CancelId;
    CHAR gap_2DE[22];
} MS_FILTER, * PMS_FILTER;


typedef struct _FILTER_DEVICE_EXTENSION
{
    ULONG            Signature;
    NDIS_HANDLE      Handle;
} FILTER_DEVICE_EXTENSION, *PFILTER_DEVICE_EXTENSION;


//
// Macros to set the flags and clear the flags
//
#define FILTER_SET_FLAG(_pFilter, _flag)    ((_pFilter)->Flags |= (_flag))
#define FILTER_CLEAR_FLAG(_pFilter, _flag)    ((_pFilter)->Flags &= ~(_flag))
#define FILTER_TEST_FLAG(_pFilter, _flag)    (((_pFilter)->Flags & (_flag)) != 0)


#define FILTER_READY_TO_PAUSE(_Filter)      \
    ((_Filter)->State == FilterPausing)

//
// The driver should maintain a list of NDIS filter handles
//
typedef struct _FL_NDIS_FILTER_LIST
{
    LIST_ENTRY              Link;
    NDIS_HANDLE             ContextHandle;
    NDIS_STRING             FilterInstanceName;
} FL_NDIS_FILTER_LIST, *PFL_NDIS_FILTER_LIST;

//
// The context inside a cloned request
//
typedef struct _NDIS_OID_REQUEST *FILTER_REQUEST_CONTEXT,**PFILTER_REQUEST_CONTEXT;


//
// function prototypes
//
NDIS_STATUS
DriverEntry(
        IN  PDRIVER_OBJECT      DriverObject,
        IN  PUNICODE_STRING     RegistryPath
        );

NDIS_STATUS
FilterRegisterOptions(
        IN NDIS_HANDLE      NdisFilterDriverHandle,
        IN NDIS_HANDLE      FilterDriverContext
        );

NDIS_STATUS
FilterAttach(
        IN  NDIS_HANDLE                     NdisFilterHandle,
        IN  NDIS_HANDLE                     FilterDriverContext,
        IN  PNDIS_FILTER_ATTACH_PARAMETERS  AttachParameters
        );

VOID
FilterDetach(
        IN  NDIS_HANDLE     FilterInstaceContext
        );

DRIVER_UNLOAD FilterUnload;

VOID
FilterUnload(
        IN  PDRIVER_OBJECT  DriverObject
        );

NDIS_STATUS
FilterRestart(
        IN  NDIS_HANDLE     FilterModuleContext,
        IN  PNDIS_FILTER_RESTART_PARAMETERS RestartParameters
        );

NDIS_STATUS
FilterPause(
        IN  NDIS_HANDLE     FilterModuleContext,
        IN  PNDIS_FILTER_PAUSE_PARAMETERS   PauseParameters
        );


NDIS_STATUS
FilterOidRequest(
        IN  NDIS_HANDLE        FilterModuleContext,
        IN  PNDIS_OID_REQUEST  Request
        );

VOID
FilterCancelOidRequest(
    IN  NDIS_HANDLE             FilterModuleContext,
    IN  PVOID                   RequestId
    );

VOID
FilterStatus(
    IN  NDIS_HANDLE                 FilterModuleContext,
    IN  PNDIS_STATUS_INDICATION     StatusIndication
    );

VOID
FilterDevicePnPEventNotify(
    IN  NDIS_HANDLE            FilterModuleContext,
    IN  PNET_DEVICE_PNP_EVENT  NetDevicePnPEvent
    );

NDIS_STATUS
FilterNetPnPEvent(
    IN NDIS_HANDLE              FilterModuleContext,
    IN PNET_PNP_EVENT_NOTIFICATION     NetPnPEventNotification
    );

VOID
FilterOidRequestComplete(
    IN  NDIS_HANDLE        FilterModuleContext,
    IN  PNDIS_OID_REQUEST  Request,
    IN  NDIS_STATUS        Status
    );

VOID
FilterSendNetBufferLists(
    IN  NDIS_HANDLE         FilterModuleContext,
    IN  PNET_BUFFER_LIST    NetBufferLists,
    IN  NDIS_PORT_NUMBER    PortNumber,
    IN  ULONG               SendFlags
    );

VOID
FilterReturnNetBufferLists(
    IN  NDIS_HANDLE         FilterModuleContext,
    IN  PNET_BUFFER_LIST    NetBufferLists,
    IN  ULONG               ReturnFlags
    );

VOID
FilterSendNetBufferListsComplete(
    IN  NDIS_HANDLE         FilterModuleContext,
    IN  PNET_BUFFER_LIST    NetBufferLists,
    IN  ULONG               SendCompleteFlags
    );


VOID
FilterReceiveNetBufferLists(
    IN  NDIS_HANDLE         FilterModuleContext,
    IN  PNET_BUFFER_LIST    NetBufferLists,
    IN  NDIS_PORT_NUMBER    PortNumber,
    IN  ULONG               NumberOfNetBufferLists,
    IN  ULONG               ReceiveFlags
    );

VOID
FilterCancelSendNetBufferLists(
    IN  NDIS_HANDLE         FilterModuleContext,
    IN  PVOID               CancelId
    );

NDIS_STATUS
FilterSetModuleOptions(
    IN  NDIS_HANDLE             FilterModuleContext
    );


NDIS_STATUS
FilterRegisterDevice(
    VOID
    );

VOID
FilterDeregisterDevice(
    VOID
    );

DRIVER_DISPATCH FilterDispatch;

NTSTATUS
FilterDispatch(
    IN PDEVICE_OBJECT       DeviceObjet,
    IN PIRP                 Irp
    );

DRIVER_DISPATCH FilterDeviceIoControl;

NTSTATUS
FilterDeviceIoControl(
    IN PDEVICE_OBJECT        DeviceObject,
    IN PIRP                  Irp
    );

PMS_FILTER    
filterFindFilterModule(
    IN PUCHAR                   FilterModuleName,
    IN ULONG                    BufferLength
    );

NDIS_STATUS
filterDoInternalRequest(
    IN PMS_FILTER                   FilterModuleContext,
    IN NDIS_REQUEST_TYPE            RequestType,
    IN NDIS_OID                     Oid,
    IN PVOID                        InformationBuffer,
    IN ULONG                        InformationBufferLength,
    IN ULONG                        OutputBufferLength, OPTIONAL
    IN ULONG                        MethodId, OPTIONAL
    OUT PULONG                      pBytesProcessed
    );

VOID
filterInternalRequestComplete(
    IN NDIS_HANDLE                  FilterModuleContext,
    IN PNDIS_OID_REQUEST            NdisRequest,
    IN NDIS_STATUS                  Status
    );


#endif  //_FILT_H


