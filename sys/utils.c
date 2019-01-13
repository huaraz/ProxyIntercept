/*++

Copyright (c) Microsoft Corporation. All rights reserved
Copyright (c) Markus Moeller

Abstract:

   This file implements the utility/helper functions for use by the classify
   functions and worker thread of the Transport proxy-intercept sample.

Environment:

    Kernel mode

--*/


#include <ntifs.h>
#include <ntddk.h>
#include <wdf.h>

#include <ntstrsafe.h>

#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union

#include <fwpsk.h>

#pragma warning(pop)

#include <fwpmk.h>

#include <stdlib.h>
#include "proxy-intercept.h"
#include "utils.h"


BOOLEAN IsAleReauthorize(
   _In_ const FWPS_INCOMING_VALUES* inFixedValues
   )
{
   UINT flagsIndex;

   DbgPrint("ProxyIntercept: %s\n", __FUNCTION__);

   GetFlagsIndexesForLayer(
      inFixedValues->layerId,
      &flagsIndex
      );

   if((flagsIndex != UINT_MAX) && ((inFixedValues->incomingValue\
      [flagsIndex].value.uint32 & FWP_CONDITION_FLAG_IS_REAUTHORIZE) != 0))
   {
      return TRUE;
   }

   return FALSE;
}

BOOLEAN IsSecureConnection(
   _In_ const FWPS_INCOMING_VALUES* inFixedValues
   )
{
   UINT flagsIndex;

   DbgPrint("ProxyIntercept: %s\n", __FUNCTION__);
   
   GetFlagsIndexesForLayer(
      inFixedValues->layerId,
      &flagsIndex
      );

   if ((flagsIndex != UINT_MAX) && ((inFixedValues->incomingValue\
       [flagsIndex].value.uint32 & FWP_CONDITION_FLAG_IS_IPSEC_SECURED) != 0))
   {
      return TRUE;
   }

   return FALSE;
}

BOOLEAN
IsAleClassifyRequired(
   _In_ const FWPS_INCOMING_VALUES* inFixedValues,
   _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues
   )
{
   //
   // Note that use of FWP_CONDITION_FLAG_REQUIRES_ALE_CLASSIFY has been
   // deprecated in Vista SP1 and Windows Server 2008.
   //
   UNREFERENCED_PARAMETER(inFixedValues);
   
   DbgPrint("ProxyIntercept: %s\n", __FUNCTION__);
   
   return FWPS_IS_METADATA_FIELD_PRESENT(
             inMetaValues,
             FWPS_METADATA_FIELD_ALE_CLASSIFY_REQUIRED
             );
}

BOOLEAN
IsMatchingConnectPacket(
   _In_ const FWPS_INCOMING_VALUES* inFixedValues,
   _In_ ADDRESS_FAMILY addressFamily,
   _In_ FWP_DIRECTION direction,
   _Inout_ TL_PROXY_INTERCEPT_PENDED_PACKET* pendedPacket
   )
{
   UINT localAddrIndex;
   UINT remoteAddrIndex;
   UINT localPortIndex;
   UINT remotePortIndex;
   UINT protocolIndex;
   UINT applicationIndex;
   UINT userIndex;


   NT_ASSERT(pendedPacket->type == TL_PROXY_INTERCEPT_CONNECT_PACKET);

   DbgPrint("ProxyIntercept: %s\n", __FUNCTION__);
   
   GetNetwork7TupleIndexesForLayer(
      inFixedValues->layerId,
      &localAddrIndex,
      &remoteAddrIndex,
      &localPortIndex,
      &remotePortIndex,
      &protocolIndex,
	  &applicationIndex,
      &userIndex
      );

   if(localAddrIndex == UINT_MAX)
   {
      return FALSE;
   }

   if (addressFamily != pendedPacket->addressFamily)
   {
      return FALSE;
   }

   if (direction != pendedPacket->direction)
   {
      return FALSE;
   }

   if (inFixedValues->incomingValue[protocolIndex].value.uint8 !=
       pendedPacket->protocol)
   {
      return FALSE;
   }

   if (RtlUshortByteSwap(
         inFixedValues->incomingValue[localPortIndex].value.uint16
       ) != pendedPacket->localPort)
   {
      return FALSE;
   }

   if (RtlUshortByteSwap(
         inFixedValues->incomingValue[remotePortIndex].value.uint16
         ) != pendedPacket->remotePort)
   
   {
      return FALSE;
   }

   if (addressFamily == AF_INET)
   {
      UINT32 ipv4LocalAddr =
         RtlUlongByteSwap(
            inFixedValues->incomingValue[localAddrIndex].value.uint32
            );
      UINT32 ipv4RemoteAddr =
      // Prefast thinks we are ignoring this return value.
      // If driver is unloading, we give up and ignore it on purpose.
      // Otherwise, we put the pointer onto the list, but we make it opaque
      // by casting it as a UINT64, and this tricks Prefast.
         RtlUlongByteSwap( /* host-order -> network-order conversion */
            inFixedValues->incomingValue[remoteAddrIndex].value.uint32
            );
      if (ipv4LocalAddr != pendedPacket->ipv4LocalAddr)
      {
         return FALSE;
      }

      if (ipv4RemoteAddr != pendedPacket->ipv4RemoteAddr)
      {
         return FALSE;
      }
   }
   else
   {
      if (RtlCompareMemory(
            inFixedValues->incomingValue[localAddrIndex].value.byteArray16,
            &pendedPacket->localAddr,
            sizeof(FWP_BYTE_ARRAY16)) !=  sizeof(FWP_BYTE_ARRAY16))
      {
         return FALSE;
      }

      if (RtlCompareMemory(
            inFixedValues->incomingValue[remoteAddrIndex].value.byteArray16,
            &pendedPacket->remoteAddr,
            sizeof(FWP_BYTE_ARRAY16)) !=  sizeof(FWP_BYTE_ARRAY16))
      {
         return FALSE;
      }
   }

   return TRUE;
}

void
FillNetwork7Tuple(
   _In_ const FWPS_INCOMING_VALUES* inFixedValues,
   _In_ ADDRESS_FAMILY addressFamily,
   _Inout_ TL_PROXY_INTERCEPT_PENDED_PACKET* packet
   )
{
   UINT localAddrIndex;
   UINT remoteAddrIndex;
   UINT localPortIndex;
   UINT remotePortIndex;
   UINT protocolIndex;
   UINT applicationIndex;
   UINT userIndex;

   DbgPrint("ProxyIntercept: %s\n", __FUNCTION__);
   
   GetNetwork7TupleIndexesForLayer(
      inFixedValues->layerId,
      &localAddrIndex,
      &remoteAddrIndex,
      &localPortIndex,
      &remotePortIndex,
      &protocolIndex,
	  &applicationIndex,
	  &userIndex
      );

   packet->layerId = inFixedValues->layerId;

   RtlZeroMemory(&packet->applicationPath,sizeof(UNICODE_STRING));
   if (applicationIndex != UINT_MAX) {
	   PUNICODE_STRING uString = (PUNICODE_STRING)inFixedValues->incomingValue[applicationIndex].value.unicodeString;
	   packet->applicationPath.Length = uString->Length;
	   packet->applicationPath.MaximumLength = uString->MaximumLength;
	   packet->applicationPath.Buffer = ExAllocatePoolWithTag(NonPagedPool, packet->applicationPath.MaximumLength+1, TL_PROXY_INTERCEPT_APPLICATION_PATH_POOL_TAG);

	   RtlZeroMemory(packet->applicationPath.Buffer, packet->applicationPath.MaximumLength + 1);
	   
	   RtlCopyMemory(
		   packet->applicationPath.Buffer,
		   uString->Buffer,
		   uString->Length
	   );

	   DbgPrint("ProxyIntercept: %s: Application path length %d\n", __FUNCTION__, uString->Length);
	   DbgPrint("ProxyIntercept: %s: Application copied path length %d\n", __FUNCTION__, packet->applicationPath.Length);

	   ANSI_STRING ansiApplicationPath;
   
	   if (packet->applicationPath.Length>0) {
		   RtlZeroMemory(&ansiApplicationPath, sizeof(ANSI_STRING));

		   ansiApplicationPath.Length = packet->applicationPath.MaximumLength;
		   ansiApplicationPath.MaximumLength = packet->applicationPath.MaximumLength; //ANSI should be shorter than UNICODE
		   ansiApplicationPath.Buffer = ExAllocatePoolWithTag(NonPagedPool, ansiApplicationPath.MaximumLength + 1, TL_PROXY_INTERCEPT_ANSI_PATH_POOL_TAG);

		   RtlZeroMemory(ansiApplicationPath.Buffer, ansiApplicationPath.MaximumLength + 1);

		   DbgPrint("ProxyIntercept: %s: ansiApplicationPath.Buffer %p\n", __FUNCTION__, ansiApplicationPath.Buffer);
		   
		   NTSTATUS status = RtlUnicodeStringToAnsiString(
			   &ansiApplicationPath,
			   &packet->applicationPath,
			   TRUE
		   );

		   DbgPrint("ProxyIntercept: %s: Unicode Length:  %d Ansi Length: %d\n", __FUNCTION__, packet->applicationPath.Length, ansiApplicationPath.Length);

		   if (NT_SUCCESS(status)) {
			   DbgPrint("ProxyIntercept: %s: Application path: %s\n", __FUNCTION__, ansiApplicationPath.Buffer);
			   DbgPrint("ProxyIntercept: %s: uString Buffer: %S\n", __FUNCTION__, uString->Buffer);
		   }
		   else {
			   DbgPrint("ProxyIntercept: %s: Application path failed to convert x%08x \n", __FUNCTION__, status);
		   }
		   ExFreePoolWithTag(ansiApplicationPath.Buffer, TL_PROXY_INTERCEPT_ANSI_PATH_POOL_TAG);
	   }	   
   }
   packet->userSid = NULL;
   if (userIndex != UINT_MAX) {
	   if (inFixedValues->incomingValue[userIndex].value.tokenAccessInformation) {
		   PTOKEN_ACCESS_INFORMATION tokenAccessInformation = (PTOKEN_ACCESS_INFORMATION) inFixedValues->incomingValue[userIndex].value.tokenAccessInformation->data;
		   if (tokenAccessInformation->SidHash &&
			   tokenAccessInformation->SidHash->SidAttr &&
			   RtlValidSid(tokenAccessInformation->SidHash->SidAttr->Sid)) {
//			   DbgPrint("ProxyIntercept: %s: Validated Sid, Size: %d\n", __FUNCTION__, RtlLengthSid(tokenAccessInformation->SidHash->SidAttr->Sid));
			   packet->userSid = ExAllocatePoolWithTag(NonPagedPool, RtlLengthSid(tokenAccessInformation->SidHash->SidAttr->Sid), TL_PROXY_INTERCEPT_SID_DATA_POOL_TAG);
			   NTSTATUS status = RtlCopySid(
				   RtlLengthSid(tokenAccessInformation->SidHash->SidAttr->Sid),
				   packet->userSid,
				   tokenAccessInformation->SidHash->SidAttr->Sid
				);

			   if (NT_SUCCESS(status)) {
				   DbgPrint("ProxyIntercept: %s: User SID is valid after copy\n", __FUNCTION__);
				   DbgPrint("ProxyIntercept: %s: User SID size %d\n", __FUNCTION__, RtlLengthSid(packet->userSid));
			   }
			   else {
				   DbgPrint("ProxyIntercept: %s: User SID is NOT valid after copy x%08x\n", __FUNCTION__,status);
			   }
			   DbgPrint("ProxyIntercept: %s: User SID set %p\n", __FUNCTION__, packet->userSid);

			   if (packet->userSid) {
				   DbgPrint("ProxyIntercept: %s: Valid user ID found\n", __FUNCTION__);

				   UNICODE_STRING userName;
				   UNICODE_STRING domainName;
				   ANSI_STRING ansiUserName;
				   ANSI_STRING ansiDomainName;

				   ULONG dwUserName = 1, dwDomainName = 1;
				   SID_NAME_USE eUse = SidTypeUnknown;

				   RtlZeroMemory(&userName, sizeof(UNICODE_STRING));
				   RtlZeroMemory(&domainName, sizeof(UNICODE_STRING));

				   status = SecLookupAccountSid(packet->userSid, &dwUserName, NULL, &dwDomainName, NULL, &eUse);
				   if (!NT_SUCCESS(status)) {
					   if (status == STATUS_BUFFER_TOO_SMALL) {
						   userName.Length = 0;
						   userName.MaximumLength = (USHORT)dwUserName + 1; /// for the '\0'
						   userName.Buffer = ExAllocatePoolWithTag(NonPagedPool, userName.MaximumLength, TL_PROXY_INTERCEPT_USERNAME_POOL_TAG);

						   domainName.Length = 0;
						   domainName.MaximumLength = (USHORT)dwDomainName + 1; /// for the '\0'
						   domainName.Buffer = ExAllocatePoolWithTag(NonPagedPool, domainName.MaximumLength, TL_PROXY_INTERCEPT_DOMAINNAME_POOL_TAG);

						   status = SecLookupAccountSid(packet->userSid, &dwUserName, &userName, &dwDomainName, &domainName, &eUse);
					   }
				   }
				   if (NT_SUCCESS(status)) {
					   RtlZeroMemory(&ansiUserName, sizeof(ANSI_STRING));
					   RtlZeroMemory(&ansiDomainName, sizeof(ANSI_STRING));

					   ansiUserName.Length = 0; /// for the '\0'
					   ansiUserName.MaximumLength = userName.MaximumLength; // ANSI should be same or shorter
					   ansiUserName.Buffer = ExAllocatePoolWithTag(PagedPool, ansiUserName.MaximumLength + 1, TL_PROXY_INTERCEPT_ANSI_USERNAME_POOL_TAG);

					   ansiDomainName.Length = 0; /// for the '\0'
					   ansiDomainName.MaximumLength = domainName.MaximumLength; // ANSI should be same or shorter
					   ansiDomainName.Buffer = ExAllocatePoolWithTag(PagedPool, ansiDomainName.MaximumLength + 1, TL_PROXY_INTERCEPT_ANSI_DOMAINNAME_POOL_TAG);

					   status = RtlUnicodeStringToAnsiString(
						   &ansiUserName,
						   &userName,
						   TRUE
					   );
					   status = RtlUnicodeStringToAnsiString(
						   &ansiDomainName,
						   &domainName,
						   TRUE
					   );
					   ExFreePoolWithTag(userName.Buffer, TL_PROXY_INTERCEPT_USERNAME_POOL_TAG);
					   ExFreePoolWithTag(domainName.Buffer, TL_PROXY_INTERCEPT_DOMAINNAME_POOL_TAG);

					   if (NT_SUCCESS(status)) {
						   DbgPrint("ProxyIntercept: %s: User name length: %d\n", __FUNCTION__, ansiDomainName.Length + ansiUserName.Length + 1);
						   DbgPrint("ProxyIntercept: %s: User name: %s\\%s\n", __FUNCTION__, ansiDomainName.Buffer, ansiUserName.Buffer);
					   }
					   ExFreePoolWithTag(ansiUserName.Buffer, TL_PROXY_INTERCEPT_ANSI_USERNAME_POOL_TAG);
					   ExFreePoolWithTag(ansiDomainName.Buffer, TL_PROXY_INTERCEPT_ANSI_DOMAINNAME_POOL_TAG);
				   }
				   else {
					   DbgPrint("ProxyIntercept: %s: User name failed to convert\n", __FUNCTION__);
				   }
			   }

		   }
	   }
   }

   if (addressFamily == AF_INET)
   {
      packet->ipv4LocalAddr =
         RtlUlongByteSwap( /* host-order -> network-order conversion */
            inFixedValues->incomingValue[localAddrIndex].value.uint32
            );
      packet->ipv4RemoteAddr =
         RtlUlongByteSwap( /* host-order -> network-order conversion */
            inFixedValues->incomingValue[remoteAddrIndex].value.uint32
            );
   }
   else
   {
      RtlCopyMemory(
         (UINT8*)&packet->localAddr,
         inFixedValues->incomingValue[localAddrIndex].value.byteArray16,
         sizeof(FWP_BYTE_ARRAY16)
         );
      RtlCopyMemory(
         (UINT8*)&packet->remoteAddr,
         inFixedValues->incomingValue[remoteAddrIndex].value.byteArray16,
         sizeof(FWP_BYTE_ARRAY16)
         );
   }

   packet->localPort =
	   RtlUshortByteSwap(
	   inFixedValues->incomingValue[localPortIndex].value.uint16
	        );
   packet->remotePort =
	   RtlUshortByteSwap(
	   inFixedValues->incomingValue[remotePortIndex].value.uint16
         );

   packet->protocol = inFixedValues->incomingValue[protocolIndex].value.uint8;

   return;
}

void
FreePendedPacket(
   _Inout_ __drv_freesMem(Mem) TL_PROXY_INTERCEPT_PENDED_PACKET* packet
   )
{
	DbgPrint("ProxyIntercept: %s\n", __FUNCTION__);
	
	if (packet->netBufferList != NULL)
   {
      FwpsDereferenceNetBufferList(packet->netBufferList, FALSE);
   }
   if (packet->controlData != NULL)
   {
      ExFreePoolWithTag(packet->controlData, TL_PROXY_INTERCEPT_CONTROL_DATA_POOL_TAG);
   }
   if (packet->completionContext != NULL)
   {
      NT_ASSERT(packet->type == TL_PROXY_INTERCEPT_CONNECT_PACKET);
      NT_ASSERT(packet->direction == FWP_DIRECTION_INBOUND); // complete for ALE connect
                                                          // is done prior to freeing
                                                          // of the packet.
      FwpsCompleteOperation(packet->completionContext, NULL);
   }
   if (packet->userSid != NULL)
   {
	   ExFreePoolWithTag(packet->userSid, TL_PROXY_INTERCEPT_SID_DATA_POOL_TAG);
	   packet->userSid = NULL;
   }
   if (packet->applicationPath.Buffer != NULL)
   {
	   ExFreePoolWithTag(packet->applicationPath.Buffer, TL_PROXY_INTERCEPT_APPLICATION_PATH_POOL_TAG);
	   packet->applicationPath.Buffer = NULL;
	   packet->applicationPath.Length = 0;
	   packet->applicationPath.MaximumLength = 0;
   }
   ExFreePoolWithTag(packet, TL_PROXY_INTERCEPT_PENDED_PACKET_POOL_TAG);
}

__drv_allocatesMem(Mem)
TL_PROXY_INTERCEPT_PENDED_PACKET*
AllocateAndInitializePendedPacket(
   _In_ const FWPS_INCOMING_VALUES* inFixedValues,
   _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
   _In_ ADDRESS_FAMILY addressFamily,
   _Inout_opt_ void* layerData,
   _In_ TL_PROXY_INTERCEPT_PACKET_TYPE packetType,
   _In_ FWP_DIRECTION packetDirection
   )
{
   TL_PROXY_INTERCEPT_PENDED_PACKET* pendedPacket;

   DbgPrint("ProxyIntercept: %s\n", __FUNCTION__);
   
   pendedPacket = ExAllocatePoolWithTag(
                        NonPagedPool,
                        sizeof(TL_PROXY_INTERCEPT_PENDED_PACKET),
                        TL_PROXY_INTERCEPT_PENDED_PACKET_POOL_TAG
                        );

   if (pendedPacket == NULL)
   {
      return NULL;
   }

   RtlZeroMemory(pendedPacket, sizeof(TL_PROXY_INTERCEPT_PENDED_PACKET));

   pendedPacket->type = packetType;
   pendedPacket->direction = packetDirection;

   pendedPacket->addressFamily = addressFamily;

   FillNetwork7Tuple(
      inFixedValues,
      addressFamily,
      pendedPacket
      );

   if (layerData != NULL)
   {
      pendedPacket->netBufferList = layerData;

      //
      // Reference the net buffer list to make it accessible outside of
      // classifyFn.
      //
      FwpsReferenceNetBufferList(pendedPacket->netBufferList, TRUE);
   }

   NT_ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues,
                                         FWPS_METADATA_FIELD_COMPARTMENT_ID));
   pendedPacket->compartmentId = inMetaValues->compartmentId;

   if ((pendedPacket->direction == FWP_DIRECTION_OUTBOUND) &&
       (layerData != NULL))
   {
      NT_ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(
                  inMetaValues,
                  FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE));
      pendedPacket->endpointHandle = inMetaValues->transportEndpointHandle;

      pendedPacket->remoteScopeId = inMetaValues->remoteScopeId;

      if (FWPS_IS_METADATA_FIELD_PRESENT(
            inMetaValues,
            FWPS_METADATA_FIELD_TRANSPORT_CONTROL_DATA))
      {
         NT_ASSERT(inMetaValues->controlDataLength > 0);

         pendedPacket->controlData = ExAllocatePoolWithTag(
                                       NonPagedPool,
                                       inMetaValues->controlDataLength,
                                       TL_PROXY_INTERCEPT_CONTROL_DATA_POOL_TAG
                                       );
         if (pendedPacket->controlData == NULL)
         {
            goto Exit;
         }

         RtlCopyMemory(
            pendedPacket->controlData,
            inMetaValues->controlData,
            inMetaValues->controlDataLength
            );

         pendedPacket->controlDataLength =  inMetaValues->controlDataLength;
      }
   }
   else if (pendedPacket->direction == FWP_DIRECTION_INBOUND)
   {
      UINT interfaceIndexIndex = 0;
      UINT subInterfaceIndexIndex = 0;

      GetDeliveryInterfaceIndexesForLayer(
         inFixedValues->layerId,
         &interfaceIndexIndex,
         &subInterfaceIndexIndex
         );

      pendedPacket->interfaceIndex =
         inFixedValues->incomingValue[interfaceIndexIndex].value.uint32;
      pendedPacket->subInterfaceIndex =
         inFixedValues->incomingValue[subInterfaceIndexIndex].value.uint32;

      NT_ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(
               inMetaValues,
               FWPS_METADATA_FIELD_IP_HEADER_SIZE));
      NT_ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(
               inMetaValues,
               FWPS_METADATA_FIELD_TRANSPORT_HEADER_SIZE));
      pendedPacket->ipHeaderSize = inMetaValues->ipHeaderSize;
      pendedPacket->transportHeaderSize = inMetaValues->transportHeaderSize;

      if (pendedPacket->netBufferList != NULL)
      {
         FWPS_PACKET_LIST_INFORMATION packetInfo = {0};
         FwpsGetPacketListSecurityInformation(
            pendedPacket->netBufferList,
            FWPS_PACKET_LIST_INFORMATION_QUERY_IPSEC |
            FWPS_PACKET_LIST_INFORMATION_QUERY_INBOUND,
            &packetInfo
            );

         pendedPacket->ipSecProtected =
            (BOOLEAN)packetInfo.ipsecInformation.inbound.isSecure;

         pendedPacket->nblOffset =
            NET_BUFFER_DATA_OFFSET(\
               NET_BUFFER_LIST_FIRST_NB(pendedPacket->netBufferList));
      }
   }

   return pendedPacket;

Exit:

   if (pendedPacket != NULL)
   {
      FreePendedPacket(pendedPacket);
   }

   return NULL;
}

extern WDFKEY gParametersKey;

BOOLEAN
IsTrafficPermitted(void)
{
   NTSTATUS status;
   BOOLEAN permitTraffic = TRUE;
   DECLARE_CONST_UNICODE_STRING(valueName, L"BlockTraffic");
   ULONG result;

   DbgPrint("ProxyIntercept: %s\n", __FUNCTION__);
   
   status = WdfRegistryQueryULong(
               gParametersKey,
               &valueName,
               &result
               );

   if (NT_SUCCESS(status) && result != 0)
   {
      permitTraffic = FALSE;
   }

   return permitTraffic;
}


