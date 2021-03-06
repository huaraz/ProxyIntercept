/*++

Copyright (c) Microsoft Corporation. All rights reserved
Copyright (c) Markus Moeller

Abstract:

   This file declares the utility/helper functions for use by the classify
   functions and worker thread of the Transport proxy-intercept sample.

Environment:

    Kernel mode

--*/

#include <limits.h>

#ifndef _TL_PROXY_INTERCEPT_UTILS_H_
#define _TL_PROXY_INTERCEPT_UTILS_H_

__inline
ADDRESS_FAMILY GetAddressFamilyForLayer(
   _In_ UINT16 layerId
   )
{
   ADDRESS_FAMILY addressFamily;

   switch (layerId)
   {
   case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
   case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
   case FWPS_LAYER_OUTBOUND_TRANSPORT_V4:
   case FWPS_LAYER_INBOUND_TRANSPORT_V4:
   case FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V4:
   case	FWPS_LAYER_ALE_AUTH_LISTEN_V4:
      addressFamily = AF_INET;
      break;
   case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
   case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
   case FWPS_LAYER_OUTBOUND_TRANSPORT_V6:
   case FWPS_LAYER_INBOUND_TRANSPORT_V6:
   case FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V6:
   case	FWPS_LAYER_ALE_AUTH_LISTEN_V6:
      addressFamily = AF_INET6;
      break;
   default:
      addressFamily = AF_UNSPEC;
      NT_ASSERT(0);
   }

   return addressFamily;
}

__inline
FWP_DIRECTION GetPacketDirectionForLayer(
   _In_ UINT16 layerId
   )
{
   FWP_DIRECTION direction;

   switch (layerId)
   {
   case FWPS_LAYER_OUTBOUND_TRANSPORT_V4:
   case FWPS_LAYER_OUTBOUND_TRANSPORT_V6:
      direction = FWP_DIRECTION_OUTBOUND;
      break;
   case FWPS_LAYER_INBOUND_TRANSPORT_V4:
   case FWPS_LAYER_INBOUND_TRANSPORT_V6:
      direction = FWP_DIRECTION_INBOUND;
      break;
   default:
      direction = FWP_DIRECTION_MAX;
      NT_ASSERT(0);
   }

   return direction;
}

__inline
void
GetFlagsIndexesForLayer(
   _In_ UINT16 layerId,
   _Out_ UINT* flagsIndex
   )
{
   switch (layerId)
   {
   case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
      *flagsIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_FLAGS;
      break;
   case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
      *flagsIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_FLAGS;
      break;
   case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
      *flagsIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_FLAGS;
      break;
   case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
      *flagsIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_FLAGS;
      break;
   case FWPS_LAYER_OUTBOUND_TRANSPORT_V4:
      *flagsIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V4_FLAGS;
      break;
   case FWPS_LAYER_OUTBOUND_TRANSPORT_V6:
      *flagsIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V6_FLAGS;
      break;
   case FWPS_LAYER_INBOUND_TRANSPORT_V4:
      *flagsIndex = FWPS_FIELD_INBOUND_TRANSPORT_V4_FLAGS;
      break;
   case FWPS_LAYER_INBOUND_TRANSPORT_V6:
      *flagsIndex = FWPS_FIELD_INBOUND_TRANSPORT_V6_FLAGS;
      break;
   case FWPS_LAYER_ALE_AUTH_LISTEN_V4:
	   *flagsIndex = FWPS_FIELD_ALE_AUTH_LISTEN_V4_FLAGS;
	   break;
   case FWPS_LAYER_ALE_AUTH_LISTEN_V6:
	   *flagsIndex = FWPS_FIELD_ALE_AUTH_LISTEN_V6_FLAGS;
       break;
   case FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V4:
	   *flagsIndex = FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_FLAGS;
	   break;
   case FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V6:
	   *flagsIndex = FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_FLAGS;
       break;
   default:
      *flagsIndex = UINT_MAX;
      NT_ASSERT(0);
      break;
   }
}

__inline
void
GetDeliveryInterfaceIndexesForLayer(
   _In_ UINT16 layerId,
   _Out_ UINT* interfaceIndexIndex,
   _Out_ UINT* subInterfaceIndexIndex
   )
{
   *interfaceIndexIndex = 0;

   *subInterfaceIndexIndex = 0;

   switch (layerId)
   {
   case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
      *interfaceIndexIndex = 
         FWPS_FIELD_ALE_AUTH_CONNECT_V4_INTERFACE_INDEX;
      *subInterfaceIndexIndex = 
         FWPS_FIELD_ALE_AUTH_CONNECT_V4_SUB_INTERFACE_INDEX;
      break;
   case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
      *interfaceIndexIndex = 
         FWPS_FIELD_ALE_AUTH_CONNECT_V6_INTERFACE_INDEX;
      *subInterfaceIndexIndex = 
         FWPS_FIELD_ALE_AUTH_CONNECT_V6_SUB_INTERFACE_INDEX;
      break;
   case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
      *interfaceIndexIndex = 
         FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_INTERFACE_INDEX;
      *subInterfaceIndexIndex = 
         FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_SUB_INTERFACE_INDEX;
      break;
   case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
      *interfaceIndexIndex = 
         FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_INTERFACE_INDEX;
      *subInterfaceIndexIndex = 
         FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_SUB_INTERFACE_INDEX;
      break;
   case FWPS_LAYER_INBOUND_TRANSPORT_V4:
      *interfaceIndexIndex = 
         FWPS_FIELD_INBOUND_TRANSPORT_V4_INTERFACE_INDEX;
      *subInterfaceIndexIndex = 
         FWPS_FIELD_INBOUND_TRANSPORT_V4_SUB_INTERFACE_INDEX;
      break;
   case FWPS_LAYER_INBOUND_TRANSPORT_V6:
      *interfaceIndexIndex = 
         FWPS_FIELD_INBOUND_TRANSPORT_V6_INTERFACE_INDEX;
      *subInterfaceIndexIndex = 
         FWPS_FIELD_INBOUND_TRANSPORT_V6_SUB_INTERFACE_INDEX;
      break;
   default:
      NT_ASSERT(0);
      break;
   }
}

__inline
void
GetNetwork7TupleIndexesForLayer(
   _In_ UINT16 layerId,
   _Out_ UINT* localAddressIndex,
   _Out_ UINT* remoteAddressIndex,
   _Out_ UINT* localPortIndex,
   _Out_ UINT* remotePortIndex,
   _Out_ UINT* protocolIndex,
   _Out_ UINT* applicationIndex,
   _Out_ UINT* userIndex
)
{
   switch (layerId)
   {
   case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
      *localAddressIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS;
      *remoteAddressIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS;
      *localPortIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT;
      *remotePortIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT;
      *protocolIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL;
	  *applicationIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID;
	  *userIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_USER_ID;
	  break;
   case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
      *localAddressIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS;
      *remoteAddressIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS;
      *localPortIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT;
      *remotePortIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT;
      *protocolIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL;
	  *applicationIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_APP_ID;
	  *userIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_USER_ID;
	  break;
   case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
      *localAddressIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS;
      *remoteAddressIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS;
      *localPortIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT;
      *remotePortIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT;
      *protocolIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL;
	  *applicationIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ALE_APP_ID;
	  *userIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ALE_USER_ID;
	  break;
   case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
      *localAddressIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS;
      *remoteAddressIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS;
      *localPortIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT;
      *remotePortIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT;
      *protocolIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL;
	  *applicationIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_ALE_APP_ID;
	  *userIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_ALE_USER_ID;
	  break;
   case FWPS_LAYER_OUTBOUND_TRANSPORT_V4:
      *localAddressIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS;
      *remoteAddressIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS;
      *localPortIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT;
      *remotePortIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT;
      *protocolIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_PROTOCOL;
	  *applicationIndex = UINT_MAX;
	  *userIndex = UINT_MAX;
	  break;
   case FWPS_LAYER_OUTBOUND_TRANSPORT_V6:
      *localAddressIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_ADDRESS;
      *remoteAddressIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_REMOTE_ADDRESS;
      *localPortIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_PORT;
      *remotePortIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_REMOTE_PORT;
      *protocolIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_PROTOCOL;
	  *applicationIndex = UINT_MAX;
	  *userIndex = UINT_MAX;
	  break;
   case FWPS_LAYER_INBOUND_TRANSPORT_V4:
      *localAddressIndex = FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS;
      *remoteAddressIndex = FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS;
      *localPortIndex = FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_PORT;
      *remotePortIndex = FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_PORT;
      *protocolIndex = FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_PROTOCOL;
	  *applicationIndex = UINT_MAX;
	  *userIndex = UINT_MAX;
	  break;
   case FWPS_LAYER_INBOUND_TRANSPORT_V6:
      *localAddressIndex = FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_LOCAL_ADDRESS;
      *remoteAddressIndex = FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_REMOTE_ADDRESS;
      *localPortIndex = FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_LOCAL_PORT;
      *remotePortIndex = FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_REMOTE_PORT;
      *protocolIndex = FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_PROTOCOL;
	  *applicationIndex = UINT_MAX;
	  *userIndex = UINT_MAX;
	  break;
   case FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V4:
	   *localAddressIndex = FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_ADDRESS;
	   *remoteAddressIndex = UINT_MAX;
	   *localPortIndex = FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_PORT;
	   *remotePortIndex = UINT_MAX;
	   *protocolIndex = FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_PROTOCOL;
	   *applicationIndex = FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_ALE_APP_ID;
	   *userIndex = FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_ALE_USER_ID;
	   break;
   case FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V6:
	   *localAddressIndex = FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_IP_LOCAL_ADDRESS;
	   *remoteAddressIndex = UINT_MAX;
	   *localPortIndex = FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_IP_LOCAL_PORT;
	   *remotePortIndex = UINT_MAX;
	   *protocolIndex = FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_IP_PROTOCOL;
	   *applicationIndex = FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_ALE_APP_ID;
	   *userIndex = FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_ALE_USER_ID;
	   break;
   case FWPS_LAYER_ALE_AUTH_LISTEN_V4:
	   *localAddressIndex = FWPS_FIELD_ALE_AUTH_LISTEN_V4_IP_LOCAL_ADDRESS;
	   *remoteAddressIndex = UINT_MAX;
	   *localPortIndex = FWPS_FIELD_ALE_AUTH_LISTEN_V4_IP_LOCAL_PORT;
	   *remotePortIndex = UINT_MAX;
	   *protocolIndex = UINT_MAX;
	   *applicationIndex = FWPS_FIELD_ALE_AUTH_LISTEN_V4_ALE_APP_ID;
	   *userIndex = FWPS_FIELD_ALE_AUTH_LISTEN_V4_ALE_USER_ID;
	   break;
   case FWPS_LAYER_ALE_AUTH_LISTEN_V6:
	   *localAddressIndex = FWPS_FIELD_ALE_AUTH_LISTEN_V6_IP_LOCAL_ADDRESS;
	   *remoteAddressIndex = UINT_MAX;
	   *localPortIndex = FWPS_FIELD_ALE_AUTH_LISTEN_V6_IP_LOCAL_PORT;
	   *remotePortIndex = UINT_MAX;
	   *protocolIndex = UINT_MAX;
	   *applicationIndex = FWPS_FIELD_ALE_AUTH_LISTEN_V6_ALE_APP_ID;
	   *userIndex = FWPS_FIELD_ALE_AUTH_LISTEN_V6_ALE_USER_ID;
       break; 
   default:
      *localAddressIndex = UINT_MAX;
      *remoteAddressIndex = UINT_MAX;
      *localPortIndex = UINT_MAX;
      *remotePortIndex = UINT_MAX;
      *protocolIndex = UINT_MAX;      
	  *applicationIndex = UINT_MAX;
	  *userIndex = UINT_MAX;
	  NT_ASSERT(0);
   }
 }

BOOLEAN IsAleReauthorize(
   _In_ const FWPS_INCOMING_VALUES* inFixedValues
   );

BOOLEAN IsSecureConnection(
   _In_ const FWPS_INCOMING_VALUES* inFixedValues
   );

BOOLEAN
IsAleClassifyRequired(
   _In_ const FWPS_INCOMING_VALUES* inFixedValues,
   _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues
   );

void
FillNetwork7Tuple(
   _In_ const FWPS_INCOMING_VALUES* inFixedValues,
   _In_ ADDRESS_FAMILY addressFamily,
   _Inout_ TL_PROXY_INTERCEPT_PENDED_PACKET* packet
   );

BOOLEAN
IsMatchingConnectPacket(
   _In_ const FWPS_INCOMING_VALUES* inFixedValues,
   _In_ ADDRESS_FAMILY addressFamily,
   _In_ FWP_DIRECTION direction,
   _Inout_ TL_PROXY_INTERCEPT_PENDED_PACKET* pendedPacket
   );

__drv_allocatesMem(Mem)
TL_PROXY_INTERCEPT_PENDED_PACKET*
AllocateAndInitializePendedPacket(
   _In_ const FWPS_INCOMING_VALUES* inFixedValues,
   _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
   _In_ ADDRESS_FAMILY addressFamily,
   _Inout_opt_ void* layerData,
   _In_ TL_PROXY_INTERCEPT_PACKET_TYPE packetType,
   _In_ FWP_DIRECTION packetDirection
   );

void
FreePendedPacket(
   _Inout_ __drv_freesMem(Mem) TL_PROXY_INTERCEPT_PENDED_PACKET* packet
   );

BOOLEAN
IsTrafficPermitted(void);

#endif // _TL_PROXY_INTERCEPT_UTILS_H_
