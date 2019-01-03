/*++

Copyright (c) Microsoft Corporation. All rights reserved
Copyright (c) Markus Moeller

Abstract:

   Transport proxy-intercept Proxy Callout Driver Sample.

   This sample callout driver intercepts all transport layer traffic (e.g. 
   TCP, UDP, and non-error ICMP) sent to or receive from a (configurable) 
   remote peer and queue them to a worker thread for out-of-band processing. 
   The sample performs proxy-interception of inbound and outbound connections as 
   well as all packets belong to those connections.  In addition the sample 
   demonstrates special considerations required to be compatible with Windows 
   Vista and Windows Server 2008�s IpSec implementation.

   proxy-interception parameters are configurable via the following registry 
   values --

   HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\proxy-intercept\Parameters
      
    o  BlockTraffic (REG_DWORD) : 0 (permit, default); 1 (block)
    o  RemoteAddressToproxy-intercept (REG_SZ) : literal IPv4/IPv6 string 
                                                (e.g. �10.0.0.1�)
   The sample is IP version agnostic. It performs proxy-interception for 
   both IPv4 and IPv6 traffic.

Environment:

    Kernel mode

--*/

#include <ntddk.h>
#include <wdf.h>

#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union

#include <fwpsk.h>

#pragma warning(pop)

#include <fwpmk.h>

#include <ws2ipdef.h>
#include <in6addr.h>
#include <ip2string.h>

#include "proxy-intercept.h"

#define INITGUID
#include <guiddef.h>


// 
// Configurable parameters (addresses and ports are in host order)
//

BOOLEAN configPermitTraffic = TRUE;

UINT8*   configProxyInterceptRemoteAddrV4 = NULL;
UINT8*   configProxyInterceptRemoteAddrV6 = NULL;

IN_ADDR  remoteAddrStorageV4;
IN6_ADDR remoteAddrStorageV6;

// 
// Callout and sublayer GUIDs
//

// {345875CE-1CDF-4896-8F8A-D7F9C6EDE5F5}
DEFINE_GUID(
	TL_PROXY_INTERCEPT_OUTBOUND_TRANSPORT_CALLOUT_V4,
	0x345875ce, 
	0x1cdf, 
	0x4896, 
	0x8f, 0x8a, 0xd7, 0xf9, 0xc6, 0xed, 0xe5, 0xf5);

// {8A653566-A067-489B-A93E-8370D0AD7AD3}
DEFINE_GUID(
	TL_PROXY_INTERCEPT_OUTBOUND_TRANSPORT_CALLOUT_V6,
	0x8a653566, 
	0xa067, 
	0x489b, 
	0xa9, 0x3e, 0x83, 0x70, 0xd0, 0xad, 0x7a, 0xd3);

// {EAD798C4-D151-463F-8753-79C02B12D9C2}
DEFINE_GUID(
	TL_PROXY_INTERCEPT_INBOUND_TRANSPORT_CALLOUT_V4,
	0xead798c4, 
	0xd151, 
	0x463f, 
	0x87, 0x53, 0x79, 0xc0, 0x2b, 0x12, 0xd9, 0xc2);

// {BAC0D40D-A473-4834-9547-20B34BB93682}
DEFINE_GUID(
	TL_PROXY_INTERCEPT_INBOUND_TRANSPORT_CALLOUT_V6,
	0xbac0d40d, 
	0xa473, 
	0x4834, 
	0x95, 0x47, 0x20, 0xb3, 0x4b, 0xb9, 0x36, 0x82);

// {7BEB8006-52EF-48F8-8E01-FC954F983629}
DEFINE_GUID(
	TL_PROXY_INTERCEPT_ALE_CONNECT_CALLOUT_V4,
	0x7beb8006, 
	0x52ef, 
	0x48f8, 
	0x8e, 0x1, 0xfc, 0x95, 0x4f, 0x98, 0x36, 0x29);

// {341D2527-8624-4E2F-AD0F-7B8FE266AC9E}
DEFINE_GUID(
	TL_PROXY_INTERCEPT_ALE_CONNECT_CALLOUT_V6,
	0x341d2527, 
	0x8624, 
	0x4e2f, 
	0xad, 0xf, 0x7b, 0x8f, 0xe2, 0x66, 0xac, 0x9e);

// {3296B589-7EEF-4703-84AA-56396B178AB8}
DEFINE_GUID(
	TL_PROXY_INTERCEPT_ALE_RECV_ACCEPT_CALLOUT_V4,
	0x3296b589, 
	0x7eef, 
	0x4703, 
	0x84, 0xaa, 0x56, 0x39, 0x6b, 0x17, 0x8a, 0xb8);

// {097E4E69-96CD-4E93-872E-7D9F1B494A9E}
DEFINE_GUID(
	TL_PROXY_INTERCEPT_ALE_RECV_ACCEPT_CALLOUT_V6,
	0x97e4e69, 
	0x96cd, 
	0x4e93, 
	0x87, 0x2e, 0x7d, 0x9f, 0x1b, 0x49, 0x4a, 0x9e);

// {65979E55-0551-4D67-AC6E-74B835173FFD}
DEFINE_GUID(
	TL_PROXY_INTERCEPT_SUBLAYER,
	0x65979e55, 
	0x551, 
	0x4d67, 
	0xac, 0x6e, 0x74, 0xb8, 0x35, 0x17, 0x3f, 0xfd);

// 
// Callout driver global variables
//

DEVICE_OBJECT* gWdmDevice;
WDFKEY gParametersKey;

HANDLE gEngineHandle;
UINT32 gAleConnectCalloutIdV4, gOutboundTlCalloutIdV4;
UINT32 gAleRecvAcceptCalloutIdV4, gInboundTlCalloutIdV4;
UINT32 gAleConnectCalloutIdV6, gOutboundTlCalloutIdV6;
UINT32 gAleRecvAcceptCalloutIdV6, gInboundTlCalloutIdV6;

HANDLE gInjectionHandle;

LIST_ENTRY gConnList;
KSPIN_LOCK gConnListLock;
LIST_ENTRY gPacketQueue;
KSPIN_LOCK gPacketQueueLock;

KEVENT gWorkerEvent;

BOOLEAN gDriverUnloading = FALSE;
void* gThreadObj;

// 
// Callout driver implementation
//

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD TLProxyInterceptEvtDriverUnload;

NTSTATUS
TLProxyInterceptLoadConfig(
   _In_ const WDFKEY key
   )
{
   NTSTATUS status;
   DECLARE_CONST_UNICODE_STRING(valueName, L"RemoteAddressToProxyIntercept");
   DECLARE_UNICODE_STRING_SIZE(value, INET6_ADDRSTRLEN);
   
   status = WdfRegistryQueryUnicodeString(key, &valueName, NULL, &value);

   if (NT_SUCCESS(status))
   {
      PWSTR terminator;
      // Defensively null-terminate the string
      value.Length = min(value.Length, value.MaximumLength - sizeof(WCHAR));
      value.Buffer[value.Length/sizeof(WCHAR)] = UNICODE_NULL;

      status = RtlIpv4StringToAddressW(
                  value.Buffer,
                  TRUE,
                  &terminator,
                  &remoteAddrStorageV4
                  );

      if (NT_SUCCESS(status))
      {
         remoteAddrStorageV4.S_un.S_addr = 
            RtlUlongByteSwap(remoteAddrStorageV4.S_un.S_addr);
         configProxyInterceptRemoteAddrV4 = &remoteAddrStorageV4.S_un.S_un_b.s_b1;
      }
      else
      {
         status = RtlIpv6StringToAddressW(
                     value.Buffer,
                     &terminator,
                     &remoteAddrStorageV6
                     );

         if (NT_SUCCESS(status))
         {
            configProxyInterceptRemoteAddrV6 = (UINT8*)(&remoteAddrStorageV6.u.Byte[0]);
         }
      }
   }

   return status;
}

NTSTATUS
TLProxyInterceptAddFilter(
   _In_ const wchar_t* filterName,
   _In_ const wchar_t* filterDesc,
   _In_reads_opt_(16) const UINT8* remoteAddr,
   _In_ UINT64 context,
   _In_ const GUID* layerKey,
   _In_ const GUID* calloutKey
   )
{
   NTSTATUS status = STATUS_SUCCESS;

   FWPM_FILTER filter = {0};
   FWPM_FILTER_CONDITION filterConditions[3] = {0}; 
   UINT conditionIndex;

   filter.layerKey = *layerKey;
   filter.displayData.name = (wchar_t*)filterName;
   filter.displayData.description = (wchar_t*)filterDesc;

   filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
   filter.action.calloutKey = *calloutKey;
   filter.filterCondition = filterConditions;
   filter.subLayerKey = TL_PROXY_INTERCEPT_SUBLAYER;
   filter.weight.type = FWP_EMPTY; // auto-weight.
   filter.rawContext = context;

   conditionIndex = 0;

   if (remoteAddr != NULL)
   {
      filterConditions[conditionIndex].fieldKey = 
         FWPM_CONDITION_IP_REMOTE_ADDRESS;
      filterConditions[conditionIndex].matchType = FWP_MATCH_EQUAL;

      if (IsEqualGUID(layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V4) ||
          IsEqualGUID(layerKey, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4) ||
          IsEqualGUID(layerKey, &FWPM_LAYER_INBOUND_TRANSPORT_V4) ||
          IsEqualGUID(layerKey, &FWPM_LAYER_OUTBOUND_TRANSPORT_V4))
      {
         filterConditions[conditionIndex].conditionValue.type = FWP_UINT32;
         filterConditions[conditionIndex].conditionValue.uint32 = 
            *(UINT32*)remoteAddr;
      }
      else
      {
         filterConditions[conditionIndex].conditionValue.type = 
            FWP_BYTE_ARRAY16_TYPE;
         filterConditions[conditionIndex].conditionValue.byteArray16 = 
            (FWP_BYTE_ARRAY16*)remoteAddr;
      }

      conditionIndex++;
   }

   filter.numFilterConditions = conditionIndex;

   status = FwpmFilterAdd(
               gEngineHandle,
               &filter,
               NULL,
               NULL);

   return status;
}

NTSTATUS
TLProxyInterceptRegisterALEClassifyCallouts(
   _In_ const GUID* layerKey,
   _In_ const GUID* calloutKey,
   _Inout_ void* deviceObject,
   _Out_ UINT32* calloutId
   )
/* ++

   This function registers callouts and filters at the following layers 
   to intercept inbound or outbound connect attempts.
   
      FWPM_LAYER_ALE_AUTH_CONNECT_V4
      FWPM_LAYER_ALE_AUTH_CONNECT_V6
      FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
      FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

-- */
{
   NTSTATUS status = STATUS_SUCCESS;

   FWPS_CALLOUT sCallout = {0};
   FWPM_CALLOUT mCallout = {0};

   FWPM_DISPLAY_DATA displayData = {0};

   BOOLEAN calloutRegistered = FALSE;

   sCallout.calloutKey = *calloutKey;

   if (IsEqualGUID(layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V4) ||
       IsEqualGUID(layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V6))
   {
      sCallout.classifyFn = TLProxyInterceptALEConnectClassify;
      sCallout.notifyFn = TLProxyInterceptALEConnectNotify;
   }
   else
   {
      sCallout.classifyFn = TLProxyInterceptALERecvAcceptClassify;
      sCallout.notifyFn = TLProxyInterceptALERecvAcceptNotify;
   }

   status = FwpsCalloutRegister(
               deviceObject,
               &sCallout,
               calloutId
               );
   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }
   calloutRegistered = TRUE;

   displayData.name = L"Transport proxy-intercept ALE Classify Callout";
   displayData.description = 
      L"Intercepts inbound or outbound connect attempts";

   mCallout.calloutKey = *calloutKey;
   mCallout.displayData = displayData;
   mCallout.applicableLayer = *layerKey;

   status = FwpmCalloutAdd(
               gEngineHandle,
               &mCallout,
               NULL,
               NULL
               );

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   status = TLProxyInterceptAddFilter(
               L"Transport proxy-intercept ALE Classify",
               L"Intercepts inbound or outbound connect attempts",
               (IsEqualGUID(layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V4) ||
                IsEqualGUID(layerKey, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4)) ? 
                  configProxyInterceptRemoteAddrV4 : configProxyInterceptRemoteAddrV6,
               0,
               layerKey,
               calloutKey
               );

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

Exit:

   if (!NT_SUCCESS(status))
   {
      if (calloutRegistered)
      {
         FwpsCalloutUnregisterById(*calloutId);
         *calloutId = 0;
      }
   }

   return status;
}

NTSTATUS
TLProxyInterceptRegisterTransportCallouts(
   _In_ const GUID* layerKey,
   _In_ const GUID* calloutKey,
   _Inout_ void* deviceObject,
   _Out_ UINT32* calloutId
   )
/* ++

   This function registers callouts and filters that intercept transport 
   traffic at the following layers --

      FWPM_LAYER_OUTBOUND_TRANSPORT_V4
      FWPM_LAYER_OUTBOUND_TRANSPORT_V6
      FWPM_LAYER_INBOUND_TRANSPORT_V4
      FWPM_LAYER_INBOUND_TRANSPORT_V6

-- */
{
   NTSTATUS status = STATUS_SUCCESS;

   FWPS_CALLOUT sCallout = {0};
   FWPM_CALLOUT mCallout = {0};

   FWPM_DISPLAY_DATA displayData = {0};

   BOOLEAN calloutRegistered = FALSE;

   sCallout.calloutKey = *calloutKey;
   sCallout.classifyFn = TLProxyInterceptTransportClassify;
   sCallout.notifyFn = TLProxyInterceptTransportNotify;

   status = FwpsCalloutRegister(
               deviceObject,
               &sCallout,
               calloutId
               );
   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }
   calloutRegistered = TRUE;

   displayData.name = L"Transport proxy-intercept Callout";
   displayData.description = L"proxy-intercept inbound/outbound transport traffic";

   mCallout.calloutKey = *calloutKey;
   mCallout.displayData = displayData;
   mCallout.applicableLayer = *layerKey;

   status = FwpmCalloutAdd(
               gEngineHandle,
               &mCallout,
               NULL,
               NULL
               );

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   status = TLProxyInterceptAddFilter(
               L"Transport proxy-intercept Filter (Outbound)",
               L"proxy-intercept inbound/outbound transport traffic",
               (IsEqualGUID(layerKey, &FWPM_LAYER_OUTBOUND_TRANSPORT_V4) ||
                IsEqualGUID(layerKey, &FWPM_LAYER_INBOUND_TRANSPORT_V4))? 
                  configProxyInterceptRemoteAddrV4 : configProxyInterceptRemoteAddrV6,
               0,
               layerKey,
               calloutKey
               );

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

Exit:

   if (!NT_SUCCESS(status))
   {
      if (calloutRegistered)
      {
         FwpsCalloutUnregisterById(*calloutId);
         *calloutId = 0;
      }
   }

   return status;
}

NTSTATUS
TLProxyInterceptRegisterCallouts(
   _Inout_ void* deviceObject
   )
/* ++

   This function registers dynamic callouts and filters that intercept 
   transport traffic at ALE AUTH_CONNECT/AUTH_RECV_ACCEPT and 
   INBOUND/OUTBOUND transport layers.

   Callouts and filters will be removed during DriverUnload.

-- */
{
   NTSTATUS status = STATUS_SUCCESS;
   FWPM_SUBLAYER TLProxyInterceptSubLayer;

   BOOLEAN engineOpened = FALSE;
   BOOLEAN inTransaction = FALSE;

   FWPM_SESSION session = {0};

   session.flags = FWPM_SESSION_FLAG_DYNAMIC;

   status = FwpmEngineOpen(
                NULL,
                RPC_C_AUTHN_WINNT,
                NULL,
                &session,
                &gEngineHandle
                );
   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }
   engineOpened = TRUE;

   status = FwpmTransactionBegin(gEngineHandle, 0);
   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }
   inTransaction = TRUE;

   RtlZeroMemory(&TLProxyInterceptSubLayer, sizeof(FWPM_SUBLAYER)); 

   TLProxyInterceptSubLayer.subLayerKey = TL_PROXY_INTERCEPT_SUBLAYER;
   TLProxyInterceptSubLayer.displayData.name = L"Transport proxy-intercept Sub-Layer";
   TLProxyInterceptSubLayer.displayData.description = 
      L"Sub-Layer for use by Transport proxy-intercept callouts";
   TLProxyInterceptSubLayer.flags = 0;
   TLProxyInterceptSubLayer.weight = 0; // must be less than the weight of 
                                 // FWPM_SUBLAYER_UNIVERSAL to be
                                 // compatible with Vista's IpSec
                                 // implementation.

   status = FwpmSubLayerAdd(gEngineHandle, &TLProxyInterceptSubLayer, NULL);
   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   if (configProxyInterceptRemoteAddrV4 != NULL)
   {
      status = TLProxyInterceptRegisterALEClassifyCallouts(
                  &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                  &TL_PROXY_INTERCEPT_ALE_CONNECT_CALLOUT_V4,
                  deviceObject,
                  &gAleConnectCalloutIdV4
                  );
      if (!NT_SUCCESS(status))
      {
         goto Exit;
      }

      status = TLProxyInterceptRegisterALEClassifyCallouts(
                  &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                  &TL_PROXY_INTERCEPT_ALE_RECV_ACCEPT_CALLOUT_V4,
                  deviceObject,
                  &gAleRecvAcceptCalloutIdV4
                  );
      if (!NT_SUCCESS(status))
      {
         goto Exit;
      }

      status = TLProxyInterceptRegisterTransportCallouts(
                  &FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
                  &TL_PROXY_INTERCEPT_OUTBOUND_TRANSPORT_CALLOUT_V4,
                  deviceObject,
                  &gOutboundTlCalloutIdV4
                  );
      if (!NT_SUCCESS(status))
      {
         goto Exit;
      }

      status = TLProxyInterceptRegisterTransportCallouts(
                  &FWPM_LAYER_INBOUND_TRANSPORT_V4,
                  &TL_PROXY_INTERCEPT_INBOUND_TRANSPORT_CALLOUT_V4,
                  deviceObject,
                  &gInboundTlCalloutIdV4
                  );
      if (!NT_SUCCESS(status))
      {
         goto Exit;
      }
   }

   if (configProxyInterceptRemoteAddrV6 != NULL)
   {
      status = TLProxyInterceptRegisterALEClassifyCallouts(
                  &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                  &TL_PROXY_INTERCEPT_ALE_CONNECT_CALLOUT_V6,
                  deviceObject,
                  &gAleConnectCalloutIdV6
                  );
      if (!NT_SUCCESS(status))
      {
         goto Exit;
      }

      status = TLProxyInterceptRegisterALEClassifyCallouts(
                  &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                  &TL_PROXY_INTERCEPT_ALE_RECV_ACCEPT_CALLOUT_V6,
                  deviceObject,
                  &gAleRecvAcceptCalloutIdV6
                  );
      if (!NT_SUCCESS(status))
      {
         goto Exit;
      }

      status = TLProxyInterceptRegisterTransportCallouts(
                  &FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
                  &TL_PROXY_INTERCEPT_OUTBOUND_TRANSPORT_CALLOUT_V6,
                  deviceObject,
                  &gOutboundTlCalloutIdV6
                  );
      if (!NT_SUCCESS(status))
      {
         goto Exit;
      }

      status = TLProxyInterceptRegisterTransportCallouts(
                  &FWPM_LAYER_INBOUND_TRANSPORT_V6,
                  &TL_PROXY_INTERCEPT_INBOUND_TRANSPORT_CALLOUT_V6,
                  deviceObject,
                  &gInboundTlCalloutIdV6
                  );
      if (!NT_SUCCESS(status))
      {
         goto Exit;
      }
   }

   status = FwpmTransactionCommit(gEngineHandle);
   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }
   inTransaction = FALSE;

Exit:

   if (!NT_SUCCESS(status))
   {
      if (inTransaction)
      {
         FwpmTransactionAbort(gEngineHandle);
         _Analysis_assume_lock_not_held_(gEngineHandle); // Potential leak if "FwpmTransactionAbort" fails
      }
      if (engineOpened)
      {
         FwpmEngineClose(gEngineHandle);
         gEngineHandle = NULL;
      }
   }

   return status;
}

void
TLProxyInterceptUnregisterCallouts(void)
{
   FwpmEngineClose(gEngineHandle);
   gEngineHandle = NULL;

   FwpsCalloutUnregisterById(gOutboundTlCalloutIdV6);
   FwpsCalloutUnregisterById(gOutboundTlCalloutIdV4);
   FwpsCalloutUnregisterById(gInboundTlCalloutIdV6);
   FwpsCalloutUnregisterById(gInboundTlCalloutIdV4);

   FwpsCalloutUnregisterById(gAleConnectCalloutIdV6);
   FwpsCalloutUnregisterById(gAleConnectCalloutIdV4);
   FwpsCalloutUnregisterById(gAleRecvAcceptCalloutIdV6);
   FwpsCalloutUnregisterById(gAleRecvAcceptCalloutIdV4);
}

_Function_class_(EVT_WDF_DRIVER_UNLOAD)
_IRQL_requires_same_
_IRQL_requires_max_(PASSIVE_LEVEL)
void
TLProxyInterceptEvtDriverUnload(
   _In_ WDFDRIVER driverObject
   )
{

   KLOCK_QUEUE_HANDLE connListLockHandle;
   KLOCK_QUEUE_HANDLE packetQueueLockHandle;

   UNREFERENCED_PARAMETER(driverObject);

   KeAcquireInStackQueuedSpinLock(
      &gConnListLock,
      &connListLockHandle
      );
   KeAcquireInStackQueuedSpinLock(
      &gPacketQueueLock,
      &packetQueueLockHandle
      );

   gDriverUnloading = TRUE;

   KeReleaseInStackQueuedSpinLock(&packetQueueLockHandle);
   KeReleaseInStackQueuedSpinLock(&connListLockHandle);

   if (IsListEmpty(&gConnList) && IsListEmpty(&gPacketQueue))
   {
      KeSetEvent(
         &gWorkerEvent,
         IO_NO_INCREMENT, 
         FALSE
         );
   }

   NT_ASSERT(gThreadObj != NULL);

   KeWaitForSingleObject(
      gThreadObj,
      Executive,
      KernelMode,
      FALSE,
      NULL
      );

   ObDereferenceObject(gThreadObj);

   TLProxyInterceptUnregisterCallouts();

   FwpsInjectionHandleDestroy(gInjectionHandle);
}

NTSTATUS
TLProxyInterceptInitDriverObjects(
   _Inout_ DRIVER_OBJECT* driverObject,
   _In_ const UNICODE_STRING* registryPath,
   _Out_ WDFDRIVER* pDriver,
   _Out_ WDFDEVICE* pDevice
   )
{
   NTSTATUS status;
   WDF_DRIVER_CONFIG config;
   PWDFDEVICE_INIT pInit = NULL;

   WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);

   config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
   config.EvtDriverUnload = TLProxyInterceptEvtDriverUnload;

   status = WdfDriverCreate(
               driverObject,
               registryPath,
               WDF_NO_OBJECT_ATTRIBUTES,
               &config,
               pDriver
               );

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   pInit = WdfControlDeviceInitAllocate(*pDriver, &SDDL_DEVOBJ_KERNEL_ONLY);

   if (!pInit)
   {
      status = STATUS_INSUFFICIENT_RESOURCES;
      goto Exit;
   }

   WdfDeviceInitSetDeviceType(pInit, FILE_DEVICE_NETWORK);
   WdfDeviceInitSetCharacteristics(pInit, FILE_DEVICE_SECURE_OPEN, FALSE);
   WdfDeviceInitSetCharacteristics(pInit, FILE_AUTOGENERATED_DEVICE_NAME, TRUE);

   status = WdfDeviceCreate(&pInit, WDF_NO_OBJECT_ATTRIBUTES, pDevice);
   if (!NT_SUCCESS(status))
   {
      WdfDeviceInitFree(pInit);
      goto Exit;
   }

   WdfControlFinishInitializing(*pDevice);

Exit:
   return status;
}

NTSTATUS
DriverEntry(
   DRIVER_OBJECT* driverObject,
   UNICODE_STRING* registryPath
   )
{
   NTSTATUS status;
   WDFDRIVER driver;
   WDFDEVICE device;
   HANDLE threadHandle;

   // Request NX Non-Paged Pool when available
   ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

   status = TLProxyInterceptInitDriverObjects(
               driverObject,
               registryPath,
               &driver,
               &device
               );

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   status = WdfDriverOpenParametersRegistryKey(
               driver,
               KEY_READ,
               WDF_NO_OBJECT_ATTRIBUTES,
               &gParametersKey
               );

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   status = TLProxyInterceptLoadConfig(gParametersKey);

   if (!NT_SUCCESS(status))
   {
      status = STATUS_DEVICE_CONFIGURATION_ERROR;
      goto Exit;
   }

   if ((configProxyInterceptRemoteAddrV4 == NULL) && 
       (configProxyInterceptRemoteAddrV6 == NULL))
   {
      status = STATUS_DEVICE_CONFIGURATION_ERROR;
      goto Exit;
   }

   status = FwpsInjectionHandleCreate(
               AF_UNSPEC,
               FWPS_INJECTION_TYPE_TRANSPORT,
               &gInjectionHandle
               );

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   InitializeListHead(&gConnList);
   KeInitializeSpinLock(&gConnListLock);   

   InitializeListHead(&gPacketQueue);
   KeInitializeSpinLock(&gPacketQueueLock);  

   KeInitializeEvent(
      &gWorkerEvent,
      NotificationEvent,
      FALSE
      );

   gWdmDevice = WdfDeviceWdmGetDeviceObject(device);

   status = TLProxyInterceptRegisterCallouts(gWdmDevice);

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   status = PsCreateSystemThread(
               &threadHandle,
               THREAD_ALL_ACCESS,
               NULL,
               NULL,
               NULL,
               TLProxyInterceptWorker,
               NULL
               );

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   status = ObReferenceObjectByHandle(
               threadHandle,
               0,
               NULL,
               KernelMode,
               &gThreadObj,
               NULL
               );
   NT_ASSERT(NT_SUCCESS(status));

   ZwClose(threadHandle);

Exit:
   
   if (!NT_SUCCESS(status))
   {
      if (gEngineHandle != NULL)
      {
         TLProxyInterceptUnregisterCallouts();
      }
      if (gInjectionHandle != NULL)
      {
         FwpsInjectionHandleDestroy(gInjectionHandle);
      }
   }

   return status;
};

