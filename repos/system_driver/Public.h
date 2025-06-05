/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_systemdriver,
    0xfbce2ab0,0x3b6f,0x429c,0x9a,0xfd,0xb1,0xea,0x22,0xa2,0x27,0xb5);
// {fbce2ab0-3b6f-429c-9afd-b1ea22a227b5}
