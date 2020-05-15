/*++
 *
 * The file contains the routines to create a device and handle ioctls
 *
-- */

#include "precomp.h"

NDIS_STATUS
FilterRegisterDevice(
    VOID
    )
{
    NDIS_STATUS            Status = NDIS_STATUS_SUCCESS;
    UNICODE_STRING         DeviceName;
    UNICODE_STRING         DeviceLinkUnicodeString;
    PDRIVER_DISPATCH       DispatchTable[IRP_MJ_MAXIMUM_FUNCTION+1];
    NDIS_DEVICE_OBJECT_ATTRIBUTES   DeviceAttribute;
    PFILTER_DEVICE_EXTENSION        FilterDeviceExtension;
    PDRIVER_OBJECT                  DriverObject;
   
    DEBUGP(DL_TRACE, ("==>FilterRegisterDevice\n"));
   
    
    NdisZeroMemory(DispatchTable, (IRP_MJ_MAXIMUM_FUNCTION+1) * sizeof(PDRIVER_DISPATCH));
    
    DispatchTable[IRP_MJ_CREATE] = FilterDispatch;
    DispatchTable[IRP_MJ_CLEANUP] = FilterDispatch;
    DispatchTable[IRP_MJ_CLOSE] = FilterDispatch;
    DispatchTable[IRP_MJ_DEVICE_CONTROL] = FilterDeviceIoControl;
    
    
    NdisInitUnicodeString(&DeviceName, NTDEVICE_STRING);
    NdisInitUnicodeString(&DeviceLinkUnicodeString, LINKNAME_STRING);
    
    //
    // Create a device object and register our dispatch handlers
    //
    NdisZeroMemory(&DeviceAttribute, sizeof(NDIS_DEVICE_OBJECT_ATTRIBUTES));
    
    DeviceAttribute.Header.Type = NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES;
    DeviceAttribute.Header.Revision = NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
    DeviceAttribute.Header.Size = sizeof(NDIS_DEVICE_OBJECT_ATTRIBUTES);
    
    DeviceAttribute.DeviceName = &DeviceName;
    DeviceAttribute.SymbolicName = &DeviceLinkUnicodeString;
    DeviceAttribute.MajorFunctions = &DispatchTable[0];
    DeviceAttribute.ExtensionSize = sizeof(FILTER_DEVICE_EXTENSION);
    
    Status = NdisRegisterDeviceEx(
                FilterDriverHandle,
                &DeviceAttribute,
                &DeviceObject,
                &NdisFilterDeviceHandle
                );
   
   
    if (Status == NDIS_STATUS_SUCCESS)
    {
        FilterDeviceExtension = NdisGetDeviceReservedExtension(DeviceObject);
   
        FilterDeviceExtension->Signature = 'FTDR';
        FilterDeviceExtension->Handle = FilterDriverHandle;

        //
        // Workaround NDIS bug
        //
        DriverObject = (PDRIVER_OBJECT)FilterDriverObject;
    }
              
        
    DEBUGP(DL_TRACE, ("<==PtRegisterDevice: %x\n", Status));
        
    return (Status);
        
}

VOID
FilterDeregisterDevice(
    IN VOID
    )

{
    if (NdisFilterDeviceHandle != NULL)
    {
        NdisDeregisterDeviceEx(NdisFilterDeviceHandle);
    }

    NdisFilterDeviceHandle = NULL;

}

NTSTATUS
FilterDispatch(
    IN PDEVICE_OBJECT       DeviceObject,
    IN PIRP                 Irp
    )
{
    PIO_STACK_LOCATION       IrpStack;
    NTSTATUS                 Status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(DeviceObject);

    IrpStack = IoGetCurrentIrpStackLocation(Irp);
    
    switch (IrpStack->MajorFunction)
    {
        case IRP_MJ_CREATE:
            break;

        case IRP_MJ_CLEANUP:
            break;

        case IRP_MJ_CLOSE:
            break;

        default:
            break;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

















NTSTATUS
FilterDeviceIoControl(
    IN PDEVICE_OBJECT        DeviceObject,
    IN PIRP                  Irp
    )
{
    PIO_STACK_LOCATION          IrpSp;
    NTSTATUS                    Status = STATUS_SUCCESS;
    PUCHAR                      InputBuffer;
    PUCHAR                      OutputBuffer;
    ULONG                       InputBufferLength, OutputBufferLength;
    PLIST_ENTRY                 Link;
    PUCHAR                      pInfo;
    ULONG                       InfoLength = 0;
    PMS_FILTER                  pFilter = NULL;
    DOT11_MAC_ADDRESS           PermanentMacAddress = {0x00, 0xE0, 0x4C, 0x18, 0x8C, 0x0E};
    NDIS_802_11_BSSID_LIST_EX   pDiscoveredAPList;
    FILTER_OID                  reqContext;
    char                        bReserved1;
    NDIS_STATUS                 NdisStatus;
    USHORT                      i1 = 0;
    ULONG                       BytesProcessed = 0;
    PNET_BUFFER_LIST            buff2 = NULL;
    UCHAR                       matches = 0;
    PFILTER_DEVICE_EXTENSION    FilterDeviceExtension;

    UNREFERENCED_PARAMETER(DeviceObject);

    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    if (IrpSp->FileObject == NULL)
    {
        return(STATUS_UNSUCCESSFUL);
    }


    FilterDeviceExtension = (PFILTER_DEVICE_EXTENSION)NdisGetDeviceReservedExtension(DeviceObject);

    ASSERT(FilterDeviceExtension->Signature == 'FTDR');                         // line 181
    
    Irp->IoStatus.Information = 0;

    switch (IrpSp->Parameters.DeviceIoControl.IoControlCode)
    {

        case IOCTL_FILTER_RESTART_ALL:
            break;

        case IOCTL_FILTER_RESTART_ONE_INSTANCE:
            InputBuffer = OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
            InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

            pFilter = filterFindFilterModule (InputBuffer, InputBufferLength);

            if (pFilter == NULL)
            {
                break;
            }

            NdisFRestartFilter(pFilter->FilterHandle);

            break;

        case IOCTL_FILTER_QUERY_OID_VALUE:
            
            InputBuffer = OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
            InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
            
            FILTER_ACQUIRE_LOCK(&FilterListLock, FALSE);
            
            Link = FilterModuleList.Flink;
            
            while (Link != &FilterModuleList)
            {
                int unused_0, unused_1 = 0;
                
                pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);
                
                if (pFilter->MiniportMediaType == NdisMediumNative802_11)
                {
                    DbgPrint("IOCTL_FILTER_QUERY_OID_VALUE \n");
                    FILTER_ACQUIRE_LOCK(&pFilter->Lock, FALSE);
                    NdisMoveMemory(&reqContext, (PUCHAR)Irp->AssociatedIrp.SystemBuffer, sizeof(reqContext));
                    FILTER_RELEASE_LOCK(&pFilter->Lock, FALSE);
                }
                
                Link = Link->Flink;
            }
            
            FILTER_RELEASE_LOCK(&FilterListLock, FALSE);
            
            bReserved1 = 0;
            NdisStatus = filterDoInternalRequest(
                    pFilter,
                    NdisRequestQueryInformation,
                    reqContext.Oid,
                    reqContext.Data,
                    reqContext.Size,
                    0,
                    0,
                    &BytesProcessed);
            DbgPrint("OID_DOT11_EXCLUDE_UNENCRYPTED query: data : 0x%.2x \n", reqContext.Data[0]);
            InfoLength = BytesProcessed;
            break;

        case IOCTL_FILTER_SET_OID_VALUE:
            
            InputBuffer = OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
            InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
            
            FILTER_ACQUIRE_LOCK(&FilterListLock, FALSE);
            
            Link = FilterModuleList.Flink;
            
            while (Link != &FilterModuleList)
            {
                int unused_0, unused_1 = 0;
                
                pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);
                
                if (pFilter->MiniportMediaType == NdisMediumNative802_11)
                {
                    DbgPrint("IOCTL_FILTER_SET_OID_VALUE \n");
                    FILTER_ACQUIRE_LOCK(&pFilter->Lock, FALSE);
                    NdisMoveMemory(&reqContext, (PUCHAR)Irp->AssociatedIrp.SystemBuffer, sizeof(reqContext));
                    FILTER_RELEASE_LOCK(&pFilter->Lock, FALSE);
                }
                
                Link = Link->Flink;
            }
            
            FILTER_RELEASE_LOCK(&FilterListLock, FALSE);
            
            DbgPrint("OID_DOT11_EXCLUDE_UNENCRYPTED set: data : 0x%.2x , size %d \n", reqContext.Data[0], reqContext.Size);
            bReserved1 = 0;
            NdisStatus = filterDoInternalRequest(
                    pFilter,
                    NdisRequestSetInformation,
                    reqContext.Oid,
                    reqContext.Data,
                    reqContext.Size,
                    0,
                    0,
                    &BytesProcessed);
            InfoLength = BytesProcessed;
            break;

        case IOCTL_FILTER_ENUERATE_ALL_INSTANCES:
            
            InputBuffer = OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
            InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
            OutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
            
            
            pInfo = OutputBuffer;
            
            FILTER_ACQUIRE_LOCK(&FilterListLock, FALSE);
            
            Link = FilterModuleList.Flink;
            
            while (Link != &FilterModuleList)
            {
                pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);

                
                InfoLength += (pFilter->FilterModuleName.Length + sizeof(USHORT));
                        
                if (InfoLength <= OutputBufferLength)
                {
                    *(PUSHORT)pInfo = pFilter->FilterModuleName.Length;
                    NdisMoveMemory(pInfo + sizeof(USHORT), 
                                   (PUCHAR)(pFilter->FilterModuleName.Buffer),
                                   pFilter->FilterModuleName.Length);
                            
                    pInfo += (pFilter->FilterModuleName.Length + sizeof(USHORT));
                }
                
                Link = Link->Flink;
            }
            
            FILTER_RELEASE_LOCK(&FilterListLock, FALSE);
            if (InfoLength <= OutputBufferLength)
            {
       
                Status = NDIS_STATUS_SUCCESS;
            }
            //
            // Buffer is small
            //
            else
            {
                Status = STATUS_BUFFER_TOO_SMALL;
            }
            break;

        case IOCTL_FILTER_GET_MAC:
            
            InputBuffer = OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
            InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
            OutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
            
            FILTER_ACQUIRE_LOCK(&FilterListLock, FALSE);
            
            Link = FilterModuleList.Flink;
            
            while (Link != &FilterModuleList)
            {
                int unused_0, unused_1 = 0;
                
                pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);
                
                if (pFilter->MiniportMediaType == NdisMediumNative802_11)
                {
                    DbgPrint("IOCTL_PACKET11_GET_MAC \n");
                    FILTER_ACQUIRE_LOCK(&pFilter->Lock, FALSE);
                    NdisMoveMemory(OutputBuffer, &pFilter->CurrentMacAddress, 6);
                    InfoLength = 6;
                    FILTER_RELEASE_LOCK(&pFilter->Lock, FALSE);
                }
                
                Link = Link->Flink;
            }
               
            FILTER_RELEASE_LOCK(&FilterListLock, FALSE);
            
            break;

        case IOCTL_FILTER_GET_BSSID:
            
            InputBuffer = OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
            InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
            OutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
            
            FILTER_ACQUIRE_LOCK(&FilterListLock, FALSE);
            
            Link = FilterModuleList.Flink;
            
            while (Link != &FilterModuleList)
            {
                int unused_0, unused_1 = 0;
                
                pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);
                
                if (pFilter->MiniportMediaType == NdisMediumNative802_11)
                {
                    DbgPrint("IOCTL_FILTER_GET_BSSID \n");
                    FILTER_ACQUIRE_LOCK(&pFilter->Lock, FALSE);
                    FILTER_RELEASE_LOCK(&pFilter->Lock, FALSE);
                }
                
                Link = Link->Flink;
            }
               
            FILTER_RELEASE_LOCK(&FilterListLock, FALSE);
            
            bReserved1 = 0;
            NdisStatus = filterDoInternalRequest(
                  pFilter,
                  NdisRequestQueryInformation,
                  OID_802_11_BSSID_LIST,
                  &pDiscoveredAPList,
                  sizeof(NDIS_802_11_BSSID_LIST_EX),
                  0,
                  0,
                  &BytesProcessed);
            for (i1 = 0; i1 < pDiscoveredAPList.NumberOfItems; ++i1)
            {
                if ( pDiscoveredAPList.Bssid[i1].Ssid.SsidLength == InputBufferLength )
                {
                    matches = NdisEqualMemory(pDiscoveredAPList.Bssid[i1].Ssid.Ssid, InputBuffer, InputBufferLength);
                    if ( matches )
                    {
                        NdisMoveMemory(OutputBuffer, pDiscoveredAPList.Bssid[i1].MacAddress, 6);
                        InfoLength = 6;
                        break;
                    }
                }
            }
            InfoLength = BytesProcessed;
            break;

        case IOCTL_FILTER_INSERT_PACKET:
            
            InputBuffer = OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
            InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
            OutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
            
            FILTER_ACQUIRE_LOCK(&FilterListLock, FALSE);
            
            Link = FilterModuleList.Flink;
            
            while (Link != &FilterModuleList)
            {
                pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);
                
                if (pFilter->MiniportMediaType == NdisMediumNative802_11)
                {
                    USHORT        CurrentTimeMs = 0;
                    USHORT        TimeDifference = 0;
                    SHORT         timeoutDelta = 1000;
                    SHORT         pkts = 2;
                    LARGE_INTEGER CurrentTime;
                    
                    ++pFilter->PktsSentPerInterval;
                    NdisGetCurrentSystemTime(&CurrentTime);
                    CurrentTimeMs = (USHORT)(CurrentTime.LowPart / 10000);
                    TimeDifference = CurrentTimeMs - pFilter->IntervalStartMs;
                    if ( TimeDifference >= timeoutDelta )
                    {
                        pFilter->PktsSentPerInterval = 1;
                        pFilter->IntervalStartMs = CurrentTimeMs;
                    }
                    if ( pFilter->PktsSentPerInterval > pkts && TimeDifference < timeoutDelta )
                    {
                        DEBUGP(DL_WARN, (">>too many packets sent at once \n"));
                        break;
                    }
                    DEBUGP(DL_WARN, (">>IOCTL_PACKET11_INSERT_PACKET \n"));
                    if ( pFilter->pool_derived_from_nbl == NULL )
                    {
                        DEBUGP(DL_WARN, (">>Waiting for network resources \n"));
                        Status = STATUS_NETWORK_ACCESS_DENIED;
                        break;
                    }
                    FILTER_ACQUIRE_LOCK(&pFilter->Lock, FALSE);
                    buff2 = createpacket(
                                  pFilter->pool_derived_from_nbl,
                                  pFilter->SendNblPool,
                                  &pFilter->CurrentMacAddress,
                                  (PDOT11_MGMT_HEADER)InputBuffer,
                                  InputBufferLength);
                    if (buff2 == 0)
                    {
                        FILTER_RELEASE_LOCK(&pFilter->Lock, FALSE);
                        break;
                    }
                    FILTER_RELEASE_LOCK(&pFilter->Lock, FALSE);
                    break;
                }
                
                Link = Link->Flink;
            }
            
            FILTER_RELEASE_LOCK(&FilterListLock, FALSE);
            
            if ( buff2 == 0 )
            {
                break;
            }
            DEBUGP(DL_WARN, (">>IOCreateNetBufferList created packet successfully \n"));
            NdisFSendNetBufferLists(pFilter->FilterHandle, buff2, 0, 1u);
            break;

        case IOCTL_FILTER_SET_IP_ADDRESS:
        
            FILTER_ACQUIRE_LOCK(&FilterListLock, FALSE);
            
            Link = FilterModuleList.Flink;
            
            while (Link != &FilterModuleList)
            {
                int unused_0;
                PUCHAR pIpBuf = 0;
                
                pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);
                
                if (pFilter->MiniportMediaType == NdisMediumNative802_11)
                {
                    DEBUGP(DL_WARN, (">>IOCTL_FILTER_SET_IP_ADDRESS \n"));
                    
                    FILTER_ACQUIRE_LOCK(&pFilter->Lock, FALSE);
                    
                    NdisAllocateMemoryWithTag((PVOID *)&pIpBuf, 4u, 'LWF');
                    NdisMoveMemory(pIpBuf, Irp->AssociatedIrp.SystemBuffer, 4);
                    if ( pIpBuf )
                    {
                        int i;
                        for ( i = 0; i < 4; ++i )
                            pFilter->field_154[i] = pIpBuf[i];
                    }
                    
                    DEBUGP(DL_WARN, ("Current ip is: %d.%d.%d.%d \n",
                        pFilter->field_154[0],
                        pFilter->field_154[1],
                        pFilter->field_154[2],
                        pFilter->field_154[3]));
                    
                    if ( pFilter->field_172 == 0 )
                        pFilter->field_172 = 1;
                    
                    FILTER_RELEASE_LOCK(&pFilter->Lock, FALSE);
                }
                
                Link = Link->Flink;
            }
            
            FILTER_RELEASE_LOCK(&FilterListLock, FALSE);
            
            break;

        case IOCTL_FILTER_REMOVE_MAIN_DHCP:
            
            DEBUGP(DL_WARN, (">>IOCTL_REMOVE_MAIN_DHCP \n"));
            
            FILTER_ACQUIRE_LOCK(&FilterListLock, FALSE);
            
            Link = FilterModuleList.Flink;
            
            while (Link != &FilterModuleList)
            {
                pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);
                
                if (pFilter->MiniportMediaType == NdisMediumNative802_11)
                {
                    FILTER_ACQUIRE_LOCK(&pFilter->Lock, FALSE);
                    pFilter->field_172 = 0;
                    pFilter->field_154[0] = 1;
                    FILTER_RELEASE_LOCK(&pFilter->Lock, FALSE);
                }
                
                Link = Link->Flink;
            }
            
            FILTER_RELEASE_LOCK(&FilterListLock, FALSE);
            
            break;

        case IOCTL_FILTER_GET_DHCP:
            
            InputBuffer = OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
            InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
            OutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
            
            FILTER_ACQUIRE_LOCK(&FilterListLock, FALSE);
            
            Link = FilterModuleList.Flink;
            
            while (Link != &FilterModuleList)
            {
                pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);
                
                if (pFilter->MiniportMediaType == NdisMediumNative802_11)
                {
                    if ( OutputBuffer != NULL && (UCHAR)pFilter->field_16A[0] != 1 )
                    {
                        FILTER_ACQUIRE_LOCK(&pFilter->Lock, FALSE);
                        NdisMoveMemory(OutputBuffer, pFilter->field_16A, 4);
                        NdisMoveMemory(OutputBuffer + 4, pFilter->field_16E, 4);
                        InfoLength = 8;
                        FILTER_RELEASE_LOCK(&pFilter->Lock, FALSE);
                        DEBUGP(DL_WARN, ("dhcp server ip is: %d.%d.%d.%d \n",
                            OutputBuffer[4],
                            OutputBuffer[5],
                            OutputBuffer[6],
                            OutputBuffer[7]));
                        Status = NDIS_STATUS_SUCCESS;
                    }
                    else
                    {
                        int i;
                        
                        DEBUGP(DL_WARN, ("no dhcp server offer info received \n"));
                        
                        for ( i = 0; i < 8; ++i )
                        {
                            OutputBuffer[i] = 0;
                        }
                        
                        InfoLength = 8;
                    }
                }
                
                Link = Link->Flink;
            }
            
            FILTER_RELEASE_LOCK(&FilterListLock, FALSE);
            break;

        case IOCTL_FILTER_SWITCH_AP:
            
            FILTER_ACQUIRE_LOCK(&FilterListLock, FALSE);
            
            Link = FilterModuleList.Flink;
            
            while (Link != &FilterModuleList)
            {
                int unused_0, unused_1 = 0, unused_2, unused_3;
                
                pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);
                
                if (pFilter->MiniportMediaType == NdisMediumNative802_11)
                {
                    DEBUGP(DL_WARN, (">>IOCTL_FILTER_SWITCH_AP \n"));
                    if ( (UCHAR)pFilter->field_294 == 0 )
                    {
                        pFilter->field_294 = 1;
                    }
                    else
                    {
                        pFilter->field_294 = 0;
                        pFilter->tcp_stream_cnt = 0;
                    }
                }
                
                Link = Link->Flink;
            }
            
            FILTER_RELEASE_LOCK(&FilterListLock, FALSE);
            break;

             
        default:
            break;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = InfoLength;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
            

}


PMS_FILTER    
filterFindFilterModule(
    IN PUCHAR                   Buffer,
    IN ULONG                    BufferLength
    )
{

   PMS_FILTER              pFilter;
   PLIST_ENTRY             Link;
   
   FILTER_ACQUIRE_LOCK(&FilterListLock, FALSE);
               
   Link = FilterModuleList.Flink;
               
   while (Link != &FilterModuleList)
   {
       pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);

       if (BufferLength >= pFilter->FilterModuleName.Length)
       {
           if (NdisEqualMemory(Buffer, pFilter->FilterModuleName.Buffer, pFilter->FilterModuleName.Length))
           {
               FILTER_RELEASE_LOCK(&FilterListLock, FALSE);
               return pFilter;
           }
       }
           
       Link = Link->Flink;
   }
   
   FILTER_RELEASE_LOCK(&FilterListLock, FALSE);
   return NULL;
}




