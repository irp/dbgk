/*++ NDK Version: 0098

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    potypes.h

Abstract:

    Type definitions for the Power Subystem

Author:

    Alex Ionescu (alexi@tinykrnl.org) - Updated - 27-Feb-2006

--*/

#ifndef _POTYPES_H
#define _POTYPES_H

//
// Dependencies
//
#include <umtypes.h>
#ifndef NTOS_MODE_USER
#include <ntpoapi.h>
#endif

//
// Docking states
//
typedef enum _SYSTEM_DOCK_STATE
{
    SystemDockStateUnknown,
    SystemUndocked,
    SystemDocked
} SYSTEM_DOCK_STATE, *PSYSTEM_DOCK_STATE;

#ifndef NTOS_MODE_USER

//
// Processor Power State Data
//
struct _PROCESSOR_POWER_STATE;

typedef
VOID
(FASTCALL *PPROCESSOR_IDLE_FUNCTION)(
    struct _PROCESSOR_POWER_STATE *PState);

typedef struct _PPM_IDLE_STATES
{
     ULONG Type;
     ULONG Count;
     union
     {
         ULONG AsULONG;
         struct
         {
             ULONG AllowScaling:1;
             ULONG Disabled:1;
             ULONG Reserved:30;
         };
     }Flags;
     ULONG TargetState;
     ULONG ActualState;
     ULONG OldState;
     ULONG TargetProcessors;
     struct _PPM_IDLE_STATES *State;
} PPM_IDLE_STATES, *PPPM_IDLE_STATES;

typedef struct _PPM_IDLE_ACCOUNTING
{
     ULONG StateCount;
     ULONG TotalTransitions;
     ULONG ResetCount;
     UINT64 StartTime;
     struct _PPM_IDLE_ACCOUNTING *State;
} PPM_IDLE_ACCOUNTING, *PPPM_IDLE_ACCOUNTING;

typedef struct _PPM_PERF_STATES
{
     ULONG Count;
     ULONG MaxFrequency;
     ULONG MaxPerfState;
     ULONG MinPerfState;
     ULONG LowestPState;
     ULONG IncreaseTime;
     ULONG DecreaseTime;
     UCHAR BusyAdjThreshold;
     UCHAR Reserved;
     UCHAR ThrottleStatesOnly;
     UCHAR PolicyType;
     ULONG TimerInterval;
     union
     {
         ULONG AsULONG;
         struct
         {
             ULONG UsingHypervisor:1;
             ULONG NoDomainAccounting:1;
             ULONG IncreasePolicy:2;
             ULONG DecreasePolicy:2;
             ULONG Reserved: 26;
         };
     }Flags;
     ULONG TargetProcessors;
     LONG * PStateHandler;
     ULONG PStateContext;
     LONG * TStateHandler;
     ULONG TStateContext;
     ULONG * FeedbackHandler;
     struct _PPM_PERF_STATES *State;
} PPM_PERF_STATES, *PPPM_PERF_STATES;

typedef struct _PROCESSOR_POWER_STATE
{
    PPROCESSOR_IDLE_FUNCTION IdleFunction;
    PPM_IDLE_STATES IdleStates;
    UINT64 LastTimeCheck;
    UINT64 LastIdleTime;
    PROCESSOR_IDLE_TIMES IdleTimes;
    PPM_IDLE_ACCOUNTING IdleAccounting;
    PPM_PERF_STATES PerfStates;
    ULONG LastKernelUserTime;
    ULONG LastIdleThreadKTime;
    UINT64 LastGlobalTimeHv;
    UINT64 LastProcessorTimeHv;
    UCHAR ThermalConstraint;
    UCHAR LastBusyPercentage;
    union
    {
        USHORT AsUSHORT;
        struct
        {
            USHORT PStateDoimain:1;
            USHORT PStateDomainIdleAccounting:1;
            USHORT Reserved:14;
        };
    }Flags;
    KTIMER PerfTimer;
    KDPC PerfDpc;
    struct _KPRCB *PStateMaster;
    ULONG PStateSet;
    ULONG CurrentPState;
    ULONG Reserved0;
    ULONG DesiredPState;
    ULONG Reserved1;
    ULONG PStateIdleStartTime;
    ULONG PStateIdleTime;
    ULONG LastPStateIdleTime;
    ULONG PStateStartTIme;
    ULONG WmiDispatchPtr;
    LONG WmiInterfaceEnabled;
} PROCESSOR_POWER_STATE, *PPROCESSOR_POWER_STATE;

//
// Device Notification Structure
//
typedef struct _PO_DEVICE_NOTIFY
{
    LIST_ENTRY Link;
    PDEVICE_OBJECT TargetDevice;
    UCHAR OrderLevel;
    PDEVICE_OBJECT DeviceObject;
    PUSHORT DeviceName;
    PUSHORT DriverName;
    ULONG ChildCount;
    ULONG ActiveChild;
} PO_DEVICE_NOTIFY, *PPO_DEVICE_NOTIFY;

//
// Power IRP Queue
//
typedef struct _PO_IRP_QUEUE
{
    PIRP CurrentIrp;
    PIRP PendingIrpList;
} PO_IRP_QUEUE, *PPO_IRP_QUEUE;

// Power IRP Manager
typedef struct _PO_IRP_MANAGER
{
    PO_IRP_QUEUE DeviceIrpQueue;
    PO_IRP_QUEUE SystemIrpQueue;
} PO_IRP_MANAGER, *PPO_IRP_MANAGER;

#endif // !NTOS_MODE_USER

#endif // _POTYPES_H
