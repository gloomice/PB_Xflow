/*
#==============================================================#
# File       :   PB X-Flow V1.0 RC1 (Release Candidate)
# Ctime      :   2025-10-16
# Mtime      :   2026-10-19
# Version    :   V124 (advice1 P0-P2: MFT stream, FileBasicInfo, IOCP/pool/LRU, BlockClone cache, WaitOnAddress)
# Author     :   www.linkleading.com
# Copyright (C) 2025-2026
#==============================================================#
 * fast_copy_universal_v123.c - 企业级 PB 级海量文件高速复制引擎 (V122 "Ultimate Edition R2")
 *
 * X-Flow 技术迭代（基于 PB 数据复制调研）：
 * - P1 大文件预分配：SetFileInformationByHandle(FileAllocationInfo)，本地路径 SSD/RAID 可提升 20-30%
 * - P2 Same HDD 模式：同盘 HDD 时 actualQD 降至 4，减少磁头寻道竞争
 * - P3 CPU 亲和性：-W 绑定工作线程到核心，减少缓存竞争
 *
 * V122 极端场景专项修复（基于 V121 深度走查）：
 * - BUG-01：DLQ 并发重试——主流水线结束后用 numCopiers 线程池并发重试死信队列，
 *           g_NoDLQ 防止重入，彻底消除串行 Sleep(5/10/20s) 导致的程序"假死"数小时
 * - OPT-01：MirrorDelete 哈希化——用 XXH3_64bits uint64_t 数组替代离散 malloc 字符串
 *           指针数组，100 万文件内存从 ~200MB 降至 8MB，qsort/bsearch 速度提升百倍
 * - OPT-02：CopyBigFileDelta NO_BUFFERING——hSrc 加 FILE_FLAG_NO_BUFFERING + VirtualAlloc
 *           对齐缓冲区，防止 TB 级顺序读把系统 Standby List 清空（缓存海啸）
 * - OPT-03：令牌退还——新增 RefundBandwidthTokens，读写失败时归还已扣令牌，
 *           防止低速网络高频失败导致限速器长时间饥饿阻塞后续任务
 * - 顺序修复：DirMeta 恢复移至 Verify+DLQ 之后（确保目录时间戳在所有文件 I/O 完成后写入）
 *
 * 编译：gcc -o fast_copy_universal_v122.exe fast_copy_universal_v122.c -O3
 * -municode -lcrypt32 -lpdh -lshell32 -lshlwapi -lVssApi -lole32
 
 
 大文件复制推荐参数
fast_copy_universal_v122.exe -s E:\1_Source_100M -d D:\1_Source_100M -B 64 -q 8 -t 64 -F -W 这个最好

大文件 + 小文件混合场景
fast_copy_universal_v122.exe -s E:\1_Source_100M -d D:\1_Source_100M -J -j 256 -B 32 -q 8 -t 64 -F

小文件复制推荐参数
fast_copy_universal_v122.exe -s E:\1_Source_15K -d D:\1_Source_15K -J -D -F -t 24 -j 512 -W 这个最好
 */

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define _WIN32_WINNT 0x0602
#define _CRT_SECURE_NO_WARNINGS 1  /* MSVC: 抑制 sprintf/wcscat/_wfopen 等 C4996 */

#include <stdint.h>  /* MinGW: uint32_t/uint16_t/uint8_t 用于 MFT 结构体 */
#include <pdh.h>
#include <pdhmsg.h>
#include <process.h>
#include <intrin.h>
#include <xmmintrin.h>  /* Phase 14: _mm_prefetch T0/NTA */
#include <emmintrin.h>  /* P4: IsUncPathEx SSE2 向量化，x64 恒可用 */
#if defined(__AVX2__) || defined(_M_AVX2)
#include <immintrin.h>
#define USE_AVX2_ZERO_CHECK 1
#endif
#if defined(__AVX512F__) || defined(_M_AVX512F)
#define USE_AVX512_ZERO_CHECK 1  /* 64B 步长零块检测，需 -mavx512f /arch:AVX512 */
#endif
#include <shellapi.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <errno.h>
#include <limits.h>  /* LLONG_MAX for ParseSizeFilter overflow check */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <wchar.h>
#include <stdint.h>
#include <fcntl.h>
#include <io.h>
#include <wincrypt.h>
#include <windows.h>

#ifndef FILE_ATTRIBUTE_VALID_FLAGS
#define FILE_ATTRIBUTE_VALID_FLAGS 0x00007FB7
#endif
#ifndef MFT_ATTR_DATA
#define MFT_ATTR_DATA 0x80
#endif
#include <tlhelp32.h>   /* QueryParentProcessId：-P 启动提示（CMD 勿粘贴 GUI 的 -P） */
#include <winioctl.h>   /* USN_RECORD_*；与 FSCTL 枚举一致 */
#include <memoryapi.h>  /* PrefetchVirtualMemory, WIN32_MEMORY_RANGE_ENTRY */
#include <timeapi.h>
#pragma comment(lib, "winmm.lib")

BOOL EnablePrivilege(LPCWSTR lpszPrivilege); // 增加这行前置声明
/* =========================================================================
   [迭代一 NTAPI] 绕过 VFS 路径解析，RootDirectory 相对路径 O(1) 创建
   ========================================================================= */
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#ifndef _NTDEF_
typedef LONG NTSTATUS;
#endif
typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES {
  ULONG Length;
  HANDLE RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG Attributes;
  PVOID SecurityDescriptor;
  PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
typedef struct _IO_STATUS_BLOCK {
  union { NTSTATUS Status; PVOID Pointer; } DUMMYUNIONNAME;
  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
#define InitializeObjectAttributes(p, n, a, r, s) do { \
  (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
  (p)->RootDirectory = (r); \
  (p)->Attributes = (a); \
  (p)->ObjectName = (n); \
  (p)->SecurityDescriptor = (s); \
  (p)->SecurityQualityOfService = NULL; \
} while(0)
#define OBJ_CASE_INSENSITIVE 0x00000040L

typedef NTSTATUS (NTAPI *PNT_CREATE_FILE)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize,
  ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
  PVOID EaBuffer, ULONG EaLength);
typedef ULONG (NTAPI *PRTL_NTSTATUS_TO_DOS_ERROR)(NTSTATUS Status);

static PNT_CREATE_FILE g_NtCreateFile = NULL;
static PRTL_NTSTATUS_TO_DOS_ERROR g_RtlNtStatusToDosError = NULL;

static void InitNtApi(void) {
  HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
  if (hNtdll) {
    g_NtCreateFile = (PNT_CREATE_FILE)GetProcAddress(hNtdll, "NtCreateFile");
    g_RtlNtStatusToDosError = (PRTL_NTSTATUS_TO_DOS_ERROR)GetProcAddress(hNtdll, "RtlNtStatusToDosError");
  }
}

/* MSVC: 包含 SDK winioctl.h（提供 FSCTL_*、USN_RECORD_V2、DUPLICATE_EXTENTS_DATA 等）
 * GCC/MinGW: 跳过，由下方手动补全缺失定义 */
#ifndef __GNUC__
#  include <winioctl.h>
#endif

/* IO 优先级类型：MSVC SDK 用户模式头文件未导出，GCC/MinGW 亦未提供，两个编译器都需要 */
#ifndef THREAD_IO_PRIORITY_DESCRIPTOR
typedef enum { IoPriorityVeryLow=0, IoPriorityLow, IoPriorityNormal,
               IoPriorityHigh, IoPriorityCritical } IO_PRIORITY_HINT;
typedef struct { IO_PRIORITY_HINT Priority; } THREAD_IO_PRIORITY_DESCRIPTOR;
#endif
#ifndef THREAD_IO_PRIORITY_CLASS
#define THREAD_IO_PRIORITY_CLASS 3
#endif

/* FSCTL 常量：MSVC SDK winioctl.h 已提供，#ifndef 防止重定义；MinGW 缺失则补全 */
#ifndef FSCTL_QUERY_ALLOCATED_RANGES
#define FSCTL_QUERY_ALLOCATED_RANGES                                           \
  CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 51, METHOD_NEITHER, FILE_READ_DATA)
#endif
#ifndef FSCTL_SET_SPARSE
#define FSCTL_SET_SPARSE                                                       \
  CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 49, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#ifndef FSCTL_SET_ZERO_DATA
#define FSCTL_SET_ZERO_DATA                                                    \
  CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 50, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#endif
#ifndef FSCTL_ENUM_USN_DATA
#define FSCTL_ENUM_USN_DATA CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 44, METHOD_NEITHER, FILE_ANY_ACCESS)
#endif
#ifndef FSCTL_GET_VOLUME_BITMAP
#define FSCTL_GET_VOLUME_BITMAP CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 27, METHOD_NEITHER, FILE_READ_DATA)
#endif
#ifndef FSCTL_DUPLICATE_EXTENTS_TO_FILE
/* ReFS/NTFS 块克隆：Win10 1803+ NTFS、WinServer2016+ ReFS，零拷贝秒传 */
#define FSCTL_DUPLICATE_EXTENTS_TO_FILE CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 131, METHOD_BUFFERED, FILE_WRITE_DATA)
#endif
/* Phase 17 BypassIO：Win11+ 剥离 Filter Driver 栈，NVMe 直通物理队列，非缓存读零内核切换 */
#ifndef FSCTL_MANAGE_BYPASS_IO
#define FSCTL_MANAGE_BYPASS_IO CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 240, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
/* 自定义精简 BPIO_INPUT/OUTPUT（与 SDK 的 FS_BPIO_* 名字不同，不冲突） */
#ifndef _BPIO_PHASE17_DEFINED
#define _BPIO_PHASE17_DEFINED
typedef struct { ULONG Operation; ULONG InFlags; ULONGLONG Reserved1; ULONGLONG Reserved2; } BPIO_INPUT;
typedef struct { ULONG Operation; ULONG OutFlags; ULONGLONG R1; ULONGLONG R2; } BPIO_OUTPUT;
#endif
#ifndef FSCTL_GET_NTFS_VOLUME_DATA
#define FSCTL_GET_NTFS_VOLUME_DATA CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 25, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#ifndef FSCTL_GET_RETRIEVAL_POINTERS
#define FSCTL_GET_RETRIEVAL_POINTERS CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 28, METHOD_NEITHER, FILE_ANY_ACCESS)
#endif
/* MFT raw-read 自定义类型：MSVC SDK 和 MinGW 均无此私有接口结构，两个编译器都需要 */
#ifndef _NTFS_VOLUME_DATA_RAW_DEFINED
#define _NTFS_VOLUME_DATA_RAW_DEFINED
typedef struct {
  LARGE_INTEGER VolumeSerialNumber, NumberSectors, TotalClusters, FreeClusters, TotalReserved;
  DWORD BytesPerSector, BytesPerCluster, BytesPerFileRecordSegment, ClustersPerFileRecordSegment;
  LARGE_INTEGER MftValidDataLength, MftStartLcn, Mft2StartLcn, MftZoneStart, MftZoneEnd;
} MFT_NTFS_VOLUME_DATA;
#endif
typedef struct { LARGE_INTEGER StartingVcn; } MFT_VCN_INPUT;
typedef struct { DWORD ExtentCount; LARGE_INTEGER StartingVcn; struct { LARGE_INTEGER NextVcn, Lcn; } Extents[1]; } MFT_RETRIEVAL_BUF;
/* MFT 记录头 (FILE 魔数 0x454C4946) */
#pragma pack(push, 1)
typedef struct { uint32_t Magic; uint16_t UsaOffset, UsaCount; uint64_t Lsn; uint16_t SeqNum, LinkCount;
  uint16_t AttrOffset; uint16_t Flags; uint32_t BytesInUse, BytesAllocated; uint64_t BaseFileRecord;
  uint16_t NextAttrNum; } MFT_RECORD_HEADER;
typedef struct { uint32_t TypeCode; uint32_t RecordLength; uint8_t NonResident; uint8_t NameLength;
  uint16_t NameOffset; uint16_t Flags; uint16_t AttributeId; } MFT_ATTR_HEADER;
#pragma pack(pop)
#define MFT_MAGIC_FILE 0x454C4946
#define MFT_ATTR_END 0xFFFFFFFF
#define MFT_ATTR_FILE_NAME 0x30
#define MFT_FLAG_IN_USE 0x01
/* DUPLICATE_EXTENTS_DATA：SDK 在 _WIN32_WINNT >= 0x0603 时才暴露；
 * 为兼容 _WIN32_WINNT=0x0602 编译且保证 MinGW 可用，统一以 #ifndef 守卫补全 */
#ifndef _DUPLICATE_EXTENTS_DATA_DEFINED
typedef struct _DUPLICATE_EXTENTS_DATA {
  HANDLE FileHandle;
  LARGE_INTEGER SourceFileOffset;
  LARGE_INTEGER TargetFileOffset;
  LARGE_INTEGER ByteCount;
} DUPLICATE_EXTENTS_DATA, *PDUPLICATE_EXTENTS_DATA;
#  define _DUPLICATE_EXTENTS_DATA_DEFINED
#endif
/* 以下标准类型 MSVC SDK winioctl.h 已提供（不受 _WIN32_WINNT 版本门槛限制）；
 * GCC/MinGW winioctl.h 缺失，仅在 __GNUC__ 路径下补全 */
#ifdef __GNUC__
typedef struct _FILE_ZERO_DATA_INFORMATION {
  LARGE_INTEGER FileOffset;
  LARGE_INTEGER BeyondFinalZero;
} FILE_ZERO_DATA_INFORMATION;
typedef struct _FILE_ALLOCATED_RANGE_BUFFER {
  LARGE_INTEGER FileOffset;
  LARGE_INTEGER Length;
} FILE_ALLOCATED_RANGE_BUFFER;
typedef LONGLONG USN;
typedef struct {
  DWORDLONG StartFileReferenceNumber;
  USN LowUsn;
  USN HighUsn;
} MFT_ENUM_DATA_V0, *PMFT_ENUM_DATA_V0;
typedef struct {
  DWORD RecordLength;
  WORD MajorVersion;
  WORD MinorVersion;
  DWORDLONG FileReferenceNumber;
  DWORDLONG ParentFileReferenceNumber;
  USN Usn;
  LARGE_INTEGER TimeStamp;
  DWORD Reason;
  DWORD SourceInfo;
  DWORD SecurityId;
  DWORD FileAttributes;
  WORD FileNameLength;
  WORD FileNameOffset;
  WCHAR FileName[1];
} USN_RECORD_V2, *PUSN_RECORD_V2;
#endif /* __GNUC__ */

/* USN V3：ReFS / 部分卷返回 128 位 FileId；布局与 Win32 USN_RECORD_V3 一致（独立命名避免与 SDK 宏冲突） */
typedef struct _XFLOW_USN_RECORD_V3 {
  DWORD RecordLength;
  WORD MajorVersion;
  WORD MinorVersion;
  BYTE FileReferenceNumber[16];
  BYTE ParentFileReferenceNumber[16];
  LONGLONG Usn;
  LARGE_INTEGER TimeStamp;
  DWORD Reason;
  DWORD SourceInfo;
  DWORD SecurityId;
  DWORD FileAttributes;
  WORD FileNameLength;
  WORD FileNameOffset;
} XFLOW_USN_RECORD_V3;

#define STRSAFE_NO_DEPRECATE
#include <strsafe.h>
#include "ipc_telemetry.h"
#ifndef ERROR_DEVICE_NOT_CONNECTED
#define ERROR_DEVICE_NOT_CONNECTED 1167  /* MinGW 部分版本缺失 */
#endif
#ifndef ERROR_DIR_NOT_EMPTY
#define ERROR_DIR_NOT_EMPTY 145  /* 目录非空，Windows 异步删除时常见 */
#endif
#ifndef FILE_SUPPORTS_BLOCK_REFCOUNTING
#define FILE_SUPPORTS_BLOCK_REFCOUNTING 0x08000000u /* Win10 1803+ Duplicate Extents 能力位 */
#endif

/* PB 级稳定性：统一释放宏，强制 _aligned_malloc/_aligned_free 配对，消除堆损坏风险
 * 使用临时变量避免多次求值副作用：PB_ALIGNED_FREE(ptrArray[i++]) 不会导致 i 递增 3 次 */
#define PB_ALIGNED_FREE(p) do { void *_pb_tmp = (p); (p) = NULL; if (_pb_tmp) _aligned_free(_pb_tmp); } while (0)
#define PB_FREE(p)         do { void *_pb_tmp = (p); (p) = NULL; if (_pb_tmp) free(_pb_tmp); } while (0)

#ifndef FileAllocationInfo
#define FileAllocationInfo ((FILE_INFO_BY_HANDLE_CLASS)5)
#endif
/* MSVC SDK 10.0.26100+ winbase.h 已定义 _FILE_ALLOCATION_INFO；MinGW 头文件缺失，仍需手动定义 */
#if defined(__GNUC__) && !defined(_FILE_ALLOCATION_INFO_DEFINED)
typedef struct _FILE_ALLOCATION_INFO {
  LARGE_INTEGER AllocationSize;
} FILE_ALLOCATION_INFO;
#define _FILE_ALLOCATION_INFO_DEFINED
#endif

#ifndef HAS_VSS
#define HAS_VSS 0  /* 编译时 -DHAS_VSS=1 -lVssApi -lole32 启用 VSS */
#endif
#if defined(HAS_VSS) && (HAS_VSS) != 0
#include <Vss.h>
#include <VsBackup.h>
#pragma comment(lib, "VssApi.lib")
#pragma comment(lib, "ole32.lib")
#endif

#define XXH_INLINE_ALL
#include "xxhash.h"

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")

// 修复 1: 定义内存对齐与缓存行对齐宏
#ifndef MEMORY_ALLOCATION_ALIGNMENT
#define MEMORY_ALLOCATION_ALIGNMENT 16
#endif
#define PHYSICAL_SECTOR_ALIGN 4096  /* NO_BUFFERING 与 Large Pages 最小对齐 */

#ifdef __GNUC__
#define CACHE_ALIGN __attribute__((aligned(64)))
#else
#define CACHE_ALIGN __declspec(align(64))
#endif

/* Phase 13 分支预测：Happy Path 保持 I-Cache 紧凑，冷代码分离至函数尾 */
#if defined(__GNUC__) || defined(__clang__)
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define LIKELY(x)   (x)
#define UNLIKELY(x) (x)
#endif

/* Phase 13 Weak Fencing：x64 对齐读取天生原子，统计/取消标志只读无需 LOCK
 * ptr 为指向 volatile 变量的指针；变量用 &g_xxx，成员用 &s->hash */
#define READ_VOLATILE_64(ptr) (*(volatile const LONG64 *)(ptr))
#define READ_VOLATILE_32(ptr) (*(volatile const LONG *)(ptr))

/* Phase 16 TSO：x64 强内存序，仅需编译器屏障，0 时钟周期；ARM64 等弱序架构保留全屏障 */
#if defined(_M_X64) || defined(_M_IX86) || defined(__x86_64__) || defined(__i386__)
#define LIGHT_BARRIER() do { _ReadWriteBarrier(); } while(0)
#else
#define LIGHT_BARRIER() do { MemoryBarrier(); } while(0)
#endif

/* Phase 14 BMI2：PEXT 折叠多标志位判断，消除分支，单周期完成 */
#if defined(__BMI2__) || defined(_M_BMI2)
#include <immintrin.h>
#define PHASE14_IS_JUNCTION_DIR(attr) (_pext_u64((uint64_t)(attr), (uint64_t)(FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 3)
#else
#define PHASE14_IS_JUNCTION_DIR(attr) (((attr) & FILE_ATTRIBUTE_DIRECTORY) && ((attr) & FILE_ATTRIBUTE_REPARSE_POINT))
#endif

// 长路径支持缓冲区
#define MAX_PATH_EXT 32768

/* 稀疏空洞哈希：只读零缓冲，L3 共享缓存，零 memset 写压力 */
static const BYTE g_ZeroBuffer[1024 * 1024] = {0};
static BOOL g_HasAVX2 = FALSE;   /* SIMD 零块检测：CPUID 探测，-zero-skip 时 AVX2 加速 */
#if defined(USE_AVX512_ZERO_CHECK)
static BOOL g_HasAVX512 = FALSE; /* AVX-512F：64B 步长，单周期检测，稀疏文件零块极致加速 */
#endif
/* P/E-Core 亲和性：12 代+ 异构核，IOCP 工作线程绑定 P-Core，Win10 20H1+ EfficiencyClass */
#define MAX_PCORE_MASKS 64
static DWORD_PTR g_PCoreMasks[MAX_PCORE_MASKS];
static int g_NumPCores = 0;
#define SCAN_BUFFER_SIZE (1024 * 1024) /* 1MB 线程本地，覆盖 99% 目录，扫描零分配 */
#define LONG_PATH_THRESHOLD 240
//增加一个计数器
static volatile LONG g_CtrlCCount = 0;

typedef enum { LOG_ERROR = 0, LOG_WARNING, LOG_INFO, LOG_DEBUG } LogLevel;

typedef struct _AppConfig {
  wchar_t SrcPath[MAX_PATH_EXT];
  wchar_t DstPath[MAX_PATH_EXT];
  int ThreadCountNormal;
  int ThreadCountIdle;
  int StartHour;
  int EndHour;
  BOOL RunHoursStrict;  /* -rh_strict: 时间窗口外完全暂停（Sleep 60s），非仅降线程 */
  wchar_t FileFilter[MAX_PATH];
  wchar_t FileFilterLower[MAX_PATH];
  BOOL HasFilter; /* 启动时一次性判定，扫描循环零 wcslen 开销 */
  BOOL RealTimeStats;
  LogLevel LogVerbosity;
  BOOL IsSSD;
  BOOL CopyAcl;
  BOOL CopyAllSecurity; /* -copyall: DACL+SACL+Owner+Group，需 SE_SECURITY_NAME+SE_TAKE_OWNERSHIP_NAME */
  BOOL FastMode;
  BOOL SkipAds; /* -no_ads: 跳过 ADS（Zone.Identifier 等），PB 小文件减 FindFirstStream 税 */
  BOOL HighPriority;
  int BigBufferSizeMB;
  int MaxQueueDepth;
  int BigFileQD; /* 大文件 Ring Buffer 队列深度，0=智能自适应 */
  BOOL CompareMTime;
  BOOL CompareSize;
  BOOL CompareContent;
  BOOL UseXxh3; /* -X: 用 XXH3 替代 MD5 做内容校验，吞吐 ~10GB/s */
  BOOL FlattenDir;
  BOOL CaseInsensitive;
  BOOL UseIoRing; /* -J: 小文件 IoRing 批处理 (Win11/Server2022+) */
  BOOL MetadataOnly; /* -M: 仅复制 ACL/时间戳/属性，不碰数据 */
  BOOL IsFtpSource;
  BOOL IsFtpDest;
  wchar_t LogPath[MAX_PATH];
  wchar_t NormalLogName[MAX_PATH];
  wchar_t ErrorLogName[MAX_PATH];
  int RefreshInterval; // 建议 10: 可配置刷新间隔
  int SpeedLimitMB;    /* -L: 限速 MB/s，0=不限，令牌桶 QoS */
  int IpGapMs;         /* -ipg:n: 每 64KB 块后休眠 n 毫秒，企业 WAN 微秒流控，0=禁用 */
  BOOL SampleLargeFiles; /* -S: >5GB 文件头/中/尾各 100MB 抽样 Hash，增量盘点秒级 */
  BOOL HostAware;       /* Phase 20: -host_aware 系统负载高时主动降速，运维友好 */
  int SampleThresholdGB; /* Phase 20: -sample_threshold=N 抽样阈值 GB，0=默认 5GB */
  int SampleRandomBlocks; /* Phase 20: 中间随机块数，0=默认 6，首尾各 10MB + 中间 N×10MB */
  BOOL UseVss;           /* -V: VSS 存储快照，复制被独占锁定的 SQL .mdf 等 */
  BOOL AuditOnly;        /* 任意审计模式时为 TRUE */
  int AuditMode;         /* 0=无, 1=src 基准, 2=dst 基准, 3=full 双向(浅扫 Extra) */
  BOOL AuditPrecount;    /* -precount: 启动时同步递归数文件（海量树极慢）；默认关，以流式 g_TotalFound 为准 */
  BOOL MirrorDelete;     /* -K: 镜像模式，目标端孤儿文件/目录清理，与源端完全一致 */
  BOOL UseDeltaTransfer; /* -Y: 大文件差异块传输，仅覆写哈希不同的 1MB 块，省带宽 */
  BOOL OrderByPhysical;  /* -O: 按 FileId 物理顺序排序任务，减少 HDD 寻道 */
  BOOL BfsScan;          /* Phase 10: -bfs 广度优先扫描，HDD 同级目录批量预热 MFT，减少寻道 */
  BOOL CpuAffinity;      /* -W: 工作线程绑定 CPU 核心，减少缓存竞争 */
  BOOL HardWorkingSet;   /* -H: Phase 18 强物理页面保留，1GB 硬下限防 Working Set Trimmer */
  int SrcDriveIndex;     /* 物理磁盘索引：-1=未知/UNC, >=0=PhysicalDriveX */
  int DstDriveIndex;
  BOOL IsSamePhysicalHDD; /* 源/目在同一块物理 HDD 上 */
  wchar_t ListFilePath[MAX_PATH_EXT]; /* -l: 失败项清单，仅复制列表中的路径，跳过全盘扫描 */
  BOOL Quiet; /* -z: GUI 模式下关闭常规逐行打印，防管道反向阻塞 */
  DWORD ParentPid; /* -P: 父进程 PID，用于检测 GUI 崩溃时优雅退出，0=不监控 */
  BOOL Preflight;  /* -preflight: 仅扫盘汇总字节，不拷数据，供 GUI 预检 */
  BOOL SkipSpacePreflight; /* -no_space_preflight: 禁用目标盘容量预检（稀疏卷/确信有足够空间时慎用） */
  BOOL LowIoPriority; /* -U: Vista+ 低 I/O 优先级，优先让出资源给其他应用 */
  int TimeAllowMs;    /* -G: 时间戳容差 ms，NAS/FAT 等精度不足时视为相同 */
  LONGLONG FromDateFilter;  /* -from_date: 仅复制比此时间新的文件，0=禁用 */
  LONGLONG ToDateFilter;   /* -to_date: 仅复制比此时间早的文件，0=禁用 */
  LONGLONG MinSizeFilter;  /* -min_size: 仅复制大于此尺寸的文件，-1=禁用 */
  LONGLONG MaxSizeFilter;  /* -max_size: 仅复制小于此尺寸的文件，-1=禁用 */
  BOOL PerfectVerify;      /* -U2: 完美校验，Src+Dest 双读，检测临时错误 */
  BOOL VerifyErrRename;    /* 校验错误时重命名为 .fc_verify_err */
  wchar_t JobName[MAX_PATH]; /* -job: 任务模板名，从 ini 加载 */
  BOOL AddVerifyInfo;      /* -verifyinfo: 校验成功后写入 :fc_verify 交换数据流 */
  int DirectIoThresholdMB; /* 直接 I/O 阈值 MB，0=1MB 起全用 NO_BUFFERING，100=仅 100MB+ 用 */
  BOOL UseZeroSkip;       /* -zero-skip: 全零块打空洞，精简配置优化 */
  BOOL UseMftScan;        /* -A: MFT/USN 极速扫描，需 NTFS+管理员，秒级千万文件 */
  BOOL UseMftRawScan;     /* -mft_raw: Raw $MFT 裸盘直读，剥离 VFS 秒级千万文件 */
  int CheckpointIntervalSec;   /* 断点间隔秒，0=禁用 */
  LONGLONG CheckpointIntervalGB; /* 断点间隔 GB，0=禁用 */
  BOOL ResumeMode;        /* -resume: 从 pb_xflow_resume.dat 恢复 */
  BOOL IsMoveMode;        /* -move: 移动模式，同卷 O(1) MoveFileEx，跨卷 Copy+Delete */
  BOOL IsDeleteMode;      /* -delete: 极速删除模式，仅 -s 路径，自底向上并发删除 */
  /* Round4 P2 架构3：SetFileValidData 合规开关
   * 默认 FALSE（关闭）：断电/BSOD 后目标文件含旧磁盘数据（Data Leakage），金融/医疗合规不可接受。
   * 显式 -unsafe_fast_alloc 方可启用，并在审计日志中写入合规警告行。 */
  BOOL UnsafeFastAlloc;
  /* 大文件 NO_BUFFERING 路径：显式 -write_through 才对目标启用 FILE_FLAG_WRITE_THROUGH；
   * 默认关（吞吐优先），收尾依赖 FlushFileBuffers，见 CopyBigFileHighSpeed。 */
  BOOL WriteThroughBigFiles;
} AppConfig;

AppConfig g_Config = {0};
static wchar_t *StrDupTransient(const wchar_t *str, size_t charLen);

static volatile LONG g_AuditChecked = 0;
static volatile LONG g_AuditMissing = 0;
static volatile LONG g_AuditSizeMismatch = 0;
static volatile LONG g_AuditHashMismatch = 0;
static volatile LONG g_AuditHashError = 0;
static volatile LONG g_AuditTimeMismatch = 0;
static volatile LONG g_AuditDestFileCount = 0;
static volatile LONG g_AuditExtra = 0;
static CRITICAL_SECTION g_AuditReportCs;
static BOOL g_AuditReportCsInited = FALSE;
static FILE *g_AuditReport = NULL;

#define AUDIT_MODE_NONE 0
#define AUDIT_MODE_SRC  1 /* 以源为基准：缺/错在目标；默认不扫 Extra */
#define AUDIT_MODE_DST  2 /* 以目标为基准：缺/错在源 */
#define AUDIT_MODE_FULL 3 /* 源向深度校验 + 目标浅扫 Extra */

static wchar_t g_AuditBaselineRoot[MAX_PATH_EXT];
static wchar_t g_AuditPeerRoot[MAX_PATH_EXT];

/* 审计路径索引：XXH3_64(规范化相对路径) + 链地址法，替代千万级 O(n) 链表。
 * 桶数 2^24：64 位下指针表约 128MB，压低装载因子。
 * 节点与宽字符串同块分配（FAM）；256 路锁分片 (shard = bucket & 255) 降低全局锁竞争。 */
#define AUDIT_HASH_BUCKETS (1u << 24)
#define AUDIT_HASH_SHARDS 256
typedef struct _AuditHashEntry {
  struct _AuditHashEntry *next;
  UINT64 h;
  wchar_t relPath[1]; /* MSVC：FAM 惯用法；分配 offsetof + (len+1)*sizeof(wchar_t) */
} AuditHashEntry;
static AuditHashEntry **g_AuditPathHash = NULL;
static CRITICAL_SECTION g_AuditBucketCs[AUDIT_HASH_SHARDS];
static BOOL g_AuditBucketCsInited = FALSE;
static volatile LONG g_AuditPhase = 1;       /* 1=基准校验+建表；2=仅 Extra（MFT 对端枚举） */
static volatile LONG g_AuditHashFrozen = 0;  /* Phase1 排空后为 1：仅读路径查表 */
static volatile LONG g_AuditPhase2MftOk = 0; /* Phase2 MFT Extra 已成功投递（可跳过末尾递归） */
static LONG g_AuditPeerCountInit = 0; /* 启动时 peer 侧常规文件数（对账展示） */

static void AuditInitBaselinePeerRoots(void);
static void PathForDisplayW(const wchar_t *path, wchar_t *out, size_t outCch);

static void AuditReportLine(const wchar_t *fmt, ...) {
  if (!g_AuditReport || !g_AuditReportCsInited) return;
  EnterCriticalSection(&g_AuditReportCs);
  va_list ap;
  va_start(ap, fmt);
  vfwprintf(g_AuditReport, fmt, ap);
  va_end(ap);
  fflush(g_AuditReport);
  LeaveCriticalSection(&g_AuditReportCs);
}

static void AuditReportInit(void) {
  if (!g_Config.AuditOnly || g_AuditReportCsInited) return;
  InitializeCriticalSection(&g_AuditReportCs);
  g_AuditReportCsInited = TRUE;
  AuditInitBaselinePeerRoots();
  static const wchar_t kAuditReportName[] = L"PBXFlow_Audit_Report.txt";
  BOOL append = (GetFileAttributesW(kAuditReportName) != INVALID_FILE_ATTRIBUTES);
  g_AuditReport = _wfopen(kAuditReportName, append ? L"a, ccs=UTF-8" : L"w, ccs=UTF-8");
  if (!g_AuditReport) return;
  SYSTEMTIME st;
  GetLocalTime(&st);
  if (append) {
    fwprintf(g_AuditReport, L"\n\n");
    fwprintf(g_AuditReport,
        L"--------------------------------------------------------------------------------\n");
    fwprintf(g_AuditReport, L"PB X-Flow Audit Report (appended session)\n");
  } else {
    fwprintf(g_AuditReport, L"PB X-Flow Audit Report\n");
  }
  fwprintf(g_AuditReport, L"Time: %04d-%02d-%02d %02d:%02d:%02d\n",
      st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
  if (g_Config.AuditMode == AUDIT_MODE_SRC)
    fwprintf(g_AuditReport, L"Mode: src (baseline=source, peer=target; no Extra pass)\n");
  else if (g_Config.AuditMode == AUDIT_MODE_DST)
    fwprintf(g_AuditReport, L"Mode: dst (baseline=target, peer=source)\n");
  else if (g_Config.AuditMode == AUDIT_MODE_FULL)
    fwprintf(g_AuditReport, L"Mode: full (baseline=source deep verify + target Extra pass)\n");
  {
    wchar_t dispSrc[MAX_PATH_EXT], dispDst[MAX_PATH_EXT];
    PathForDisplayW(g_Config.SrcPath, dispSrc, MAX_PATH_EXT);
    PathForDisplayW(g_Config.DstPath, dispDst, MAX_PATH_EXT);
    fwprintf(g_AuditReport, L"Source: %ls\n", dispSrc);
    fwprintf(g_AuditReport, L"Target: %ls\n", dispDst);
  }
  fwprintf(g_AuditReport, L"Baseline root: %ls\n", g_AuditBaselineRoot);
  fwprintf(g_AuditReport, L"Peer root: %ls\n\n", g_AuditPeerRoot);
  fwprintf(g_AuditReport, L"[DETAILS]\n");
  fflush(g_AuditReport);
}

static void AuditReportClose(void) {
  if (g_AuditReport) {
    fclose(g_AuditReport);
    g_AuditReport = NULL;
  }
  if (g_AuditReportCsInited) {
    DeleteCriticalSection(&g_AuditReportCs);
    g_AuditReportCsInited = FALSE;
  }
}

static void AuditSrcPathInit(void) {
  if (g_AuditBucketCsInited) return;
  for (int i = 0; i < AUDIT_HASH_SHARDS; i++)
    InitializeCriticalSection(&g_AuditBucketCs[i]);
  g_AuditBucketCsInited = TRUE;
}

static void AuditInitBaselinePeerRoots(void) {
  g_AuditBaselineRoot[0] = g_AuditPeerRoot[0] = L'\0';
  if (g_Config.AuditMode == AUDIT_MODE_DST) {
    StringCchCopyW(g_AuditBaselineRoot, MAX_PATH_EXT, g_Config.DstPath);
    StringCchCopyW(g_AuditPeerRoot, MAX_PATH_EXT, g_Config.SrcPath);
  } else {
    StringCchCopyW(g_AuditBaselineRoot, MAX_PATH_EXT, g_Config.SrcPath);
    StringCchCopyW(g_AuditPeerRoot, MAX_PATH_EXT, g_Config.DstPath);
  }
}

/* 相对路径规范化：统一 \\、小写，便于哈希与比对（自包含，不依赖后文 SIMD 宏） */
static void AuditNormalizeRelPath(wchar_t *out, size_t outCch, const wchar_t *rel) {
  if (!out || outCch < 2) return;
  StringCchCopyW(out, outCch, rel ? rel : L"");
  for (wchar_t *p = out; *p; p++) {
    if (*p == L'/') *p = L'\\';
  }
  _wcslwr(out);
}

/* Phase2 Extra：对端盘上绝对路径 → 与 Phase1 基准索引一致的规范化相对路径（与 AuditScanTargetExtraRecursive 一致） */
static BOOL AuditPeerAbsToNormRel(const wchar_t *absOnPeer, wchar_t *normOut, size_t normCch) {
  if (!absOnPeer || !normOut || normCch < 2) return FALSE;
  size_t peerLen = wcslen(g_AuditPeerRoot);
  if (peerLen == 0) return FALSE;
  if (_wcsnicmp(absOnPeer, g_AuditPeerRoot, peerLen) != 0) return FALSE;
  const wchar_t *rel = absOnPeer + peerLen;
  if (*rel == L'\\') rel++;
  if (*rel == L'\0') return FALSE;
  AuditNormalizeRelPath(normOut, normCch, rel);
  return TRUE;
}

static BOOL AuditPathHashInsert(const wchar_t *normRel) {
  if (!normRel || !*normRel) return FALSE;
  if (READ_VOLATILE_32(&g_AuditHashFrozen)) return FALSE;
  AuditSrcPathInit();
  if (!g_AuditPathHash) {
    g_AuditPathHash = (AuditHashEntry **)calloc(AUDIT_HASH_BUCKETS, sizeof(AuditHashEntry *));
    if (!g_AuditPathHash) return FALSE;
  }
  size_t blen = wcslen(normRel) * sizeof(wchar_t);
  UINT64 h = XXH3_64bits(normRel, blen);
  UINT32 bucket = (UINT32)(h & (AUDIT_HASH_BUCKETS - 1));
  UINT32 shard = bucket & (AUDIT_HASH_SHARDS - 1);
  EnterCriticalSection(&g_AuditBucketCs[shard]);
  for (AuditHashEntry *e = g_AuditPathHash[bucket]; e; e = e->next) {
    if (e->h == h && !_wcsicmp(e->relPath, normRel)) {
      LeaveCriticalSection(&g_AuditBucketCs[shard]);
      return TRUE;
    }
  }
  size_t pathCch = wcslen(normRel) + 1;
  size_t allocSz = offsetof(AuditHashEntry, relPath) + pathCch * sizeof(wchar_t);
  AuditHashEntry *ne = (AuditHashEntry *)malloc(allocSz);
  if (!ne) {
    LeaveCriticalSection(&g_AuditBucketCs[shard]);
    return FALSE;
  }
  ne->h = h;
  memcpy(ne->relPath, normRel, pathCch * sizeof(wchar_t));
  ne->next = g_AuditPathHash[bucket];
  g_AuditPathHash[bucket] = ne;
  LeaveCriticalSection(&g_AuditBucketCs[shard]);
  return TRUE;
}

static BOOL AuditPathHashExists(const wchar_t *normRel) {
  if (!g_AuditPathHash || !normRel || !*normRel) return FALSE;
  size_t blen = wcslen(normRel) * sizeof(wchar_t);
  UINT64 h = XXH3_64bits(normRel, blen);
  UINT32 bucket = (UINT32)(h & (AUDIT_HASH_BUCKETS - 1));
  UINT32 shard = bucket & (AUDIT_HASH_SHARDS - 1);
  BOOL found = FALSE;
  EnterCriticalSection(&g_AuditBucketCs[shard]);
  for (AuditHashEntry *e = g_AuditPathHash[bucket]; e; e = e->next) {
    if (e->h == h && !_wcsicmp(e->relPath, normRel)) {
      found = TRUE;
      break;
    }
  }
  LeaveCriticalSection(&g_AuditBucketCs[shard]);
  return found;
}

static void AuditSrcPathFreeAll(void) {
  if (g_AuditPathHash && g_AuditBucketCsInited) {
    for (int shard = 0; shard < AUDIT_HASH_SHARDS; shard++) {
      EnterCriticalSection(&g_AuditBucketCs[shard]);
      for (UINT32 b = (UINT32)shard; b < AUDIT_HASH_BUCKETS; b += AUDIT_HASH_SHARDS) {
        AuditHashEntry *e = g_AuditPathHash[b];
        while (e) {
          AuditHashEntry *next = e->next;
          free(e);
          e = next;
        }
        g_AuditPathHash[b] = NULL;
      }
      LeaveCriticalSection(&g_AuditBucketCs[shard]);
    }
    free(g_AuditPathHash);
    g_AuditPathHash = NULL;
  }
  if (g_AuditBucketCsInited) {
    for (int i = 0; i < AUDIT_HASH_SHARDS; i++)
      DeleteCriticalSection(&g_AuditBucketCs[i]);
    g_AuditBucketCsInited = FALSE;
  }
  InterlockedExchange(&g_AuditHashFrozen, 0);
  InterlockedExchange(&g_AuditPhase, 1);
  InterlockedExchange(&g_AuditPhase2MftOk, 0);
}

/* 记录基准侧已枚举文件的规范化相对路径（供 Extra 浅扫） */
static void AuditCollectBaselinePath(const wchar_t *absBaselinePath) {
  if (!g_Config.AuditOnly || !absBaselinePath || !*absBaselinePath || !g_AuditBaselineRoot[0])
    return;
  size_t blen = wcslen(g_AuditBaselineRoot);
  if (blen > 0 && g_AuditBaselineRoot[blen - 1] == L'\\')
    blen--;
  if (_wcsnicmp(absBaselinePath, g_AuditBaselineRoot, blen) != 0) return;
  const wchar_t *rel = absBaselinePath + blen;
  if (*rel == L'\\') rel++;
  if (*rel == L'\0') return;
  wchar_t norm[MAX_PATH_EXT];
  AuditNormalizeRelPath(norm, MAX_PATH_EXT, rel);
  AuditPathHashInsert(norm);
}

/* 审计：源任务时间 vs 目标盘 GetFileAttributesEx；与 CheckIncrementalSync 一致支持 -G 容差 */
static BOOL AuditLastWriteTimeMatches(const FILETIME *src, const FILETIME *dst) {
  int cmp = CompareFileTime(src, dst);
  if (cmp == 0)
    return TRUE;
  if (g_Config.TimeAllowMs > 0) {
    ULARGE_INTEGER u1, u2;
    u1.LowPart = src->dwLowDateTime;
    u1.HighPart = src->dwHighDateTime;
    u2.LowPart = dst->dwLowDateTime;
    u2.HighPart = dst->dwHighDateTime;
    LONGLONG diff = (LONGLONG)(u1.QuadPart - u2.QuadPart);
    if (diff < 0)
      diff = -diff;
    if (diff <= (LONGLONG)g_Config.TimeAllowMs * 10000)
      return TRUE;
  }
  return FALSE;
}

static void AuditFormatFileTimeLocal(const FILETIME *ft, wchar_t *buf, size_t cchBuf) {
  FILETIME ftLoc;
  SYSTEMTIME st;
  if (!ft || !buf || cchBuf < 24) {
    if (buf && cchBuf)
      buf[0] = L'\0';
    return;
  }
  if (!FileTimeToLocalFileTime(ft, &ftLoc) || !FileTimeToSystemTime(&ftLoc, &st)) {
    StringCchCopyW(buf, cchBuf, L"?");
    return;
  }
  StringCchPrintfW(buf, cchBuf, L"%04u-%02u-%02u %02u:%02u:%02u",
      st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

static void AuditScanTargetExtraRecursive(const wchar_t *dstRoot, const wchar_t *curPath) {
  HANDLE hDir = CreateFileW(curPath, GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
  if (hDir == INVALID_HANDLE_VALUE) return;
  DWORD bufSize = 1024 * 1024;
  BYTE *buffer = (BYTE *)malloc(bufSize);
  if (!buffer) { CloseHandle(hDir); return; }
  /* FileIdBothDirectoryInfo：缓冲区内由 NextEntryOffset 链成一批；单批可能装不下超大目录，
   * 须同一句柄循环调用直至 ERROR_NO_MORE_FILES。ERROR_MORE_DATA 表示缓冲区不足需扩容。 */
  for (;;) {
    if (!GetFileInformationByHandleEx(hDir, FileIdBothDirectoryInfo, buffer, bufSize)) {
      DWORD err = GetLastError();
      if (err == ERROR_MORE_DATA && bufSize < 32 * 1024 * 1024) {
        DWORD newSize = bufSize * 2;
        BYTE *nb = (BYTE *)realloc(buffer, newSize);
        if (!nb)
          break;
        buffer = nb;
        bufSize = newSize;
        continue;
      }
      if (err == ERROR_NO_MORE_FILES) {
        break;
      }
      break;
    }
    FILE_ID_BOTH_DIR_INFO *p = (FILE_ID_BOTH_DIR_INFO *)buffer;
    while (1) {
      DWORD nameLen = p->FileNameLength / sizeof(wchar_t);
      wchar_t name[MAX_PATH];
      if (nameLen >= MAX_PATH) nameLen = MAX_PATH - 1;
      StringCchCopyNW(name, MAX_PATH, p->FileName, nameLen);
      name[nameLen] = L'\0';
      if (wcscmp(name, L".") != 0 && wcscmp(name, L"..") != 0) {
        wchar_t child[MAX_PATH_EXT];
        StringCchPrintfW(child, MAX_PATH_EXT, L"%ls\\%ls", curPath, name);
        const wchar_t *rel = child + wcslen(dstRoot);
        if (*rel == L'\\') rel++;
        if (p->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
          AuditScanTargetExtraRecursive(dstRoot, child);
        } else if (rel[0]) {
          wchar_t norm[MAX_PATH_EXT];
          AuditNormalizeRelPath(norm, MAX_PATH_EXT, rel);
          if (!AuditPathHashExists(norm)) {
            InterlockedIncrement(&g_AuditExtra);
            AuditReportLine(
                L"[Extra on destination] File exists on target only (not in baseline index): %ls\n",
                child);
          }
        }
      }
      if (p->NextEntryOffset == 0) break;
      p = (FILE_ID_BOTH_DIR_INFO *)((BYTE *)p + p->NextEntryOffset);
    }
  }
  free(buffer);
  CloseHandle(hDir);
}

/* Phase 10 SIMD：无分支 / -> \\ 替换，AVX2 一次 16 个 wchar_t，千万路径压 CPU 分支 */
#if defined(USE_AVX2_ZERO_CHECK) && USE_AVX2_ZERO_CHECK
static void PathReplaceForwardSlashSimd(wchar_t *path, size_t len) {
  if (!path || len == 0) return;
  const __m256i slash = _mm256_set1_epi16((short)L'/');
  size_t i = 0;
  for (; i + 16 <= len; i += 16) {
    __m256i v = _mm256_loadu_si256((const __m256i *)(path + i));
    __m256i eq = _mm256_cmpeq_epi16(v, slash);
    int mask = _mm256_movemask_epi8(eq);
    if (mask) {
      __m256i bslash = _mm256_set1_epi16((short)L'\\');
      v = _mm256_blendv_epi8(v, bslash, eq);
      _mm256_storeu_si256((__m256i *)(path + i), v);
    }
  }
  for (; i < len; i++)
    if (path[i] == L'/') path[i] = L'\\';
}
#else
#define PathReplaceForwardSlashSimd(p, n) do { \
  for (size_t _i = 0; _i < (n); _i++) if ((p)[_i] == L'/') (p)[_i] = L'\\'; \
} while(0)
#endif

/* Phase 16 SIMD wcslwr：AVX2 批量 A-Z 转小写，消除千万级扩展名过滤的 Locale 分支 */
#if defined(USE_AVX2_ZERO_CHECK) && USE_AVX2_ZERO_CHECK
static void ToLowerASCII_AVX2(wchar_t *str, size_t len) {
  if (!str || len == 0) return;
  const __m256i v_A = _mm256_set1_epi16(0x0041);
  const __m256i v_Z = _mm256_set1_epi16(0x005A);
  const __m256i v_32 = _mm256_set1_epi16(0x0020);
  const __m256i v_40 = _mm256_set1_epi16(0x0040);  /* A-1 */
  const __m256i v_5B = _mm256_set1_epi16(0x005B);  /* Z+1 */
  size_t i = 0;
  for (; i + 16 <= len; i += 16) {
    __m256i v = _mm256_loadu_si256((const __m256i *)(str + i));
    __m256i ge_A = _mm256_cmpgt_epi16(v, v_40);
    __m256i le_Z = _mm256_cmpgt_epi16(v_5B, v);
    __m256i mask = _mm256_and_si256(ge_A, le_Z);
    __m256i add_val = _mm256_and_si256(mask, v_32);
    v = _mm256_add_epi16(v, add_val);
    _mm256_storeu_si256((__m256i *)(str + i), v);
  }
  for (; i < len; i++) {
    wchar_t c = str[i];
    if (c >= L'A' && c <= L'Z') str[i] = (wchar_t)(c + 0x20);
  }
}
#else
#define ToLowerASCII_AVX2(str, len) do { _wcslwr(str); (void)(len); } while(0)
#endif

/* 启动时：将 -s/-d 根路径转为 \\?\ 绝对路径，避免传统扫描在 >260 字符树上 CreateFile 失败导致子树被截断。
 * 严禁对已带长路径/NT 对象前缀的路径再次拼接 \\?\：
 * - VSS 卷影常为 \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\...，再包一层会得到 \\?\\\\?\... 非法路径；
 * - 内核对象路径 \??\... 同理。已带 \\?\ 或 \??\ 时必须直接跳过。 */
static BOOL ApplyLongPathRootToConfig(wchar_t *path, size_t cch) {
  if (!path || !path[0] || cch < 8) return TRUE;
  if (wcsncmp(path, L"sftp://", 7) == 0 || wcsncmp(path, L"ftp://", 6) == 0 ||
      wcsncmp(path, L"SFTP://", 7) == 0 || wcsncmp(path, L"FTP://", 6) == 0)
    return TRUE;
  if (wcsncmp(path, L"\\\\?\\", 4) == 0)
    return TRUE;
  if (wcsncmp(path, L"\\??\\", 4) == 0)
    return TRUE;
  wchar_t absBuf[MAX_PATH_EXT];
  DWORD n = GetFullPathNameW(path, MAX_PATH_EXT, absBuf, NULL);
  if (n == 0 || n >= MAX_PATH_EXT)
    return FALSE;
  HRESULT hr;
  if (absBuf[0] && absBuf[1] == L':' &&
      (absBuf[2] == L'\\' || absBuf[2] == L'/' || absBuf[2] == L'\0')) {
    hr = StringCchPrintfW(path, cch, L"\\\\?\\%c:\\%ls", absBuf[0],
                          absBuf[2] ? absBuf + 3 : L"");
  } else if (absBuf[0] == L'\\' && absBuf[1] == L'\\') {
    hr = StringCchPrintfW(path, cch, L"\\\\?\\UNC\\%ls", absBuf + 2);
  } else {
    hr = StringCchPrintfW(path, cch, L"\\\\?\\%ls", absBuf);
  }
  return SUCCEEDED(hr) ? TRUE : FALSE;
}

/* 自动长路径前缀补全，盘符路径需 E:\\ 格式 */
void NormalizePath(const wchar_t *src, wchar_t *dest, size_t destLen) {
  if (!src || !dest || destLen == 0) return;
  BOOL isUri = (wcsncmp(src, L"sftp://", 7) == 0 || wcsncmp(src, L"ftp://", 6) == 0 ||
                wcsncmp(src, L"SFTP://", 7) == 0 || wcsncmp(src, L"FTP://", 6) == 0);
  if (!isUri && wcslen(src) >= LONG_PATH_THRESHOLD && wcsncmp(src, L"\\\\?\\", 4) != 0) {
    if (src[0] && src[1] == L':' &&
        (src[2] == L'\\' || src[2] == L'/' || !src[2]))
      StringCchPrintfW(dest, destLen, L"\\\\?\\%c:\\%ls", src[0],
                       src[2] ? src + 3 : L"");
    else if (src[0] == L'\\' && src[1] == L'\\')
      StringCchPrintfW(dest, destLen, L"\\\\?\\UNC\\%ls", src + 2);
    else
      StringCchPrintfW(dest, destLen, L"\\\\?\\%ls", src);
  } else {
    StringCchCopyW(dest, destLen, src);
  }
  PathReplaceForwardSlashSimd(dest, wcslen(dest));
}

/* 日志/UI 显示：剥掉 \\?\ 、\\?\UNC\ 、\\??\ 等扩展前缀；内部仍用完整前缀做 I/O */
static void PathForDisplayW(const wchar_t *path, wchar_t *out, size_t outCch) {
  if (!out || outCch == 0)
    return;
  if (!path || !path[0]) {
    out[0] = L'\0';
    return;
  }
  if (wcsncmp(path, L"\\\\?\\UNC\\", 8) == 0) {
    if (FAILED(StringCchPrintfW(out, outCch, L"\\\\%ls", path + 8)))
      StringCchCopyW(out, outCch, path);
    return;
  }
  if (wcsncmp(path, L"\\\\?\\", 4) == 0) {
    StringCchCopyW(out, outCch, path + 4);
    return;
  }
  /* NT 对象命名空间别名（卷影、部分 API 返回） */
  if (wcsncmp(path, L"\\??\\UNC\\", 8) == 0) {
    if (FAILED(StringCchPrintfW(out, outCch, L"\\\\%ls", path + 8)))
      StringCchCopyW(out, outCch, path);
    return;
  }
  if (wcsncmp(path, L"\\??\\", 4) == 0) {
    StringCchCopyW(out, outCch, path + 4);
    return;
  }
  StringCchCopyW(out, outCch, path);
}

FILE *g_fNormalLog = NULL;
FILE *g_fErrorLog = NULL;
CRITICAL_SECTION g_LogCs;

/* 无等待二进制日志：POD 结构，热路径仅 memcpy 压队，LogThread 负责 vswprintf */
typedef struct {
  SLIST_ENTRY ItemEntry;
  int isRaw;  /* 0=fmt, 1=raw, 2=stats(来自 g_StatsEntryPool) */
  union {
    struct { LogLevel level; wchar_t msg[1024]; } fmt;
    struct {
      uint32_t timestamp;
      int level;
      DWORD errCode;
      uint64_t fileSize;
      /* Round4 P1 Bug1：改为堆指针，支持 MAX_PATH_EXT (32768) 超长路径。
       * 写入方：LogMessageRaw 用 _wcsdup 分配，OOM 时回退到截断+标注长度的备用缓冲区。
       * 消费方：LogThread 消费后必须 free(entry->u.raw.path)，再归还条目到池。
       * 结构体从 ~540B 缩减至 ~50B，内存池效率同步提升。*/
      wchar_t *path;
      int rawType;  /* 0=FAILED, 1=DLQ slow, 2=DLQ concurrent, 3=IoRing fallback */
    } raw;
  } u;
} LogEntry;

PSLIST_HEADER g_LogQueue = NULL;
PSLIST_HEADER g_LogEntryPool = NULL;
PSLIST_HEADER g_StatsEntryPool = NULL;  /* V8：PrintStats 专用 4 Slot，与 LogEntry 池解耦 */
HANDLE g_hLogEvent = NULL;
HANDLE g_hLogThread = NULL;
volatile BOOL g_LogThreadRunning = TRUE;

PDH_HQUERY g_PdhQuery = NULL;
PDH_HCOUNTER g_PdhDiskQueue = NULL;
PDH_HCOUNTER g_PdhCpuUsage = NULL;  /* Phase 20: Host-Aware QoS CPU 负载 */

/* P3 OsTelemetryThread：单一 PDH 采样，TokenBucketThread/PrintStats/自适应 I/O 只读缓存 */
static volatile DWORD g_CachedCpuLoad = 0;
static volatile DWORD g_CachedDiskQueue = 0;
static HANDLE g_hOsTelemetryThread = NULL;
static HANDLE g_hOsTelemetryStopEvent = NULL;  /* N8：事件等待替代 10×Sleep(100) */

void LogMessage(LogLevel level, const wchar_t *format, ...);
void LogMessageAsync(LogLevel level, const wchar_t *format, va_list args);
/* 无等待二进制日志：热路径零 vswprintf，仅 memcpy 压队 */
void LogMessageRaw(LogLevel level, DWORD errCode, const wchar_t *path, uint64_t fileSize, int rawType);
void FreeAllPools(void);

extern volatile LONG g_IsCanceling;
extern volatile LONG g_PipelineStarted; /* 流水线已投递根任务后才响应 Ctrl+C */
extern DWORD g_PipelineStartTick;       /* 流水线启动时刻，用于启动后数秒内忽略虚假 Ctrl+C */
/* Weak Fencing：只读取消标志，volatile 足够，避免 LOCK 前缀 */
#define IsCanceling() ((BOOL)READ_VOLATILE_32(&g_IsCanceling) != 0)
extern volatile LONGLONG g_AvailableTokens;
extern volatile LONGLONG g_SpeedLimitBps; /* QoS 令牌桶发牌速率 */
extern DWORD g_BigBufferSize;             /* 大文件缓冲区尺寸 */
extern DWORD g_SectorSize;
extern BOOL g_BigFileUseDirectIo; /* FALSE：大文件走缓冲复制，避免 NO_BUFFERING 在几何未证实 */

#define TOKEN_CHUNK_SIZE (16 * 1024 * 1024)  /* OPT-05: 16MB 批发，消除 64 线程 CAS 伪共享 */
static DWORD g_TlsTokenSlot = TLS_OUT_OF_INDEXES;
static DWORD g_TlsCopierParamSlot = TLS_OUT_OF_INDEXES;  /* Phase 19：发牌人模式，工作线程绑定 param */

/* D7 修复：WaitOnAddress / WakeByAddressAll 通过 GetProcAddress 动态加载，
 * 避免 MinGW 老版本缺少 -lsynchronization 导致链接失败。
 * Windows 8+ 可用；Win7 下函数指针为 NULL，退回 SwitchToThread。 */
typedef BOOL  (WINAPI *PFN_WaitOnAddress)(volatile void *, void *, SIZE_T, DWORD);
typedef void  (WINAPI *PFN_WakeByAddressAll)(void *);
static PFN_WaitOnAddress    g_pfnWaitOnAddress    = NULL;
static PFN_WakeByAddressAll g_pfnWakeByAddressAll = NULL;
static void InitSyncFunctions(void) {
  HMODULE h = GetModuleHandleW(L"api-ms-win-core-synch-l1-2-0.dll");
  if (!h) h = GetModuleHandleW(L"KernelBase.dll");
  if (!h) h = GetModuleHandleW(L"kernel32.dll");
  if (h) {
    g_pfnWaitOnAddress    = (PFN_WaitOnAddress)   GetProcAddress(h, "WaitOnAddress");
    g_pfnWakeByAddressAll = (PFN_WakeByAddressAll)GetProcAddress(h, "WakeByAddressAll");
  }
}

struct _CopierParam;
typedef struct _CopierParam CopierParam;  /* MinGW 前向声明：AcquireBandwidthTokens 等早于完整定义 */
struct _CopyTask;
typedef struct _CopyTask CopyTask;  /* MinGW 前向声明：TryBlockCloneCopy 等早于完整定义 */
static CopierParam **g_CopierParams = NULL;
/* MinGW 前向声明：定义晚于首次调用 */
static unsigned __stdcall TokenBucketThread(void *pParam);
static unsigned __stdcall OverflowConsumerThread(void *p);
static BOOL TryBlockCloneCopy(const wchar_t *src, const wchar_t *dst, LONGLONG fileSize, const CopyTask *task);
static BOOL PassesDateSizeFilter(LONGLONG fileSize, const void *lastWrite);
static int g_NumCopierParams = 0;
static void ApplyIpGap(LONGLONG bytesWritten);  /* -ipg:n 前向声明 */
static void AcquireBandwidthTokens(LONGLONG n);  /* 定义在 CopierParam 之后 */
static void RefundBandwidthTokens(LONGLONG n);

/* -ipg:n: 每 64KB 块后休眠 n 毫秒，企业 WAN 微秒流控（Robocopy /IPG 风格） */
static void ApplyIpGap(LONGLONG bytesWritten) {
  if (g_Config.IpGapMs <= 0 || bytesWritten <= 0) return;
  int chunks = (int)((bytesWritten + 65535) / 65536);
  for (int i = 0; i < chunks && !IsCanceling(); i++)
    Sleep(g_Config.IpGapMs);
}


HANDLE g_hTokenThread = NULL;
volatile LONG g_TokenThreadRunning = 0; /* BUG-04: 独立退出标志，不依赖 g_LogThreadRunning */
HANDLE g_hParentWatcherThread = NULL;

/* 调试文件路径：%TEMP%\\pb_xflow_exit_debug.txt，确保任意工作目录下可写 */
static wchar_t g_ExitDebugPath[MAX_PATH] = L"";

static void WriteExitDebug(const char *msg) {
  if (!g_ExitDebugPath[0]) {
    wchar_t tmp[MAX_PATH];
    if (GetTempPathW(MAX_PATH, tmp) > 0) {
      StringCchCatW(tmp, MAX_PATH, L"pb_xflow_exit_debug.txt");
      StringCchCopyW(g_ExitDebugPath, MAX_PATH, tmp);
    } else
      StringCchCopyW(g_ExitDebugPath, MAX_PATH, L"pb_xflow_exit_debug.txt");
  }
  HANDLE h = CreateFileW(g_ExitDebugPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h != INVALID_HANDLE_VALUE) {
    SetFilePointer(h, 0, NULL, FILE_END);
    DWORD wr;
    WriteFile(h, msg, (DWORD)strlen(msg), &wr, NULL);
    FlushFileBuffers(h);
    CloseHandle(h);
  }
}

/* 未处理异常过滤器：主循环内崩溃时写入诊断，便于定位（勿与 WinAPI UnhandledExceptionFilter 同名） */
static LONG WINAPI CrashExceptionFilter(EXCEPTION_POINTERS *p) {
  char buf[192];
  DWORD code = p && p->ExceptionRecord ? p->ExceptionRecord->ExceptionCode : 0;
  void *addr = p && p->ExceptionRecord ? (void *)p->ExceptionRecord->ExceptionAddress : NULL;
  int n = snprintf(buf, sizeof(buf),
      "CRASH: ExceptionCode=0x%lX ExceptionAddress=%p\n",
      (unsigned long)code, addr);
  return EXCEPTION_CONTINUE_SEARCH;  /* 继续默认处理，进程终止 */
}

/* Ctrl+C 安全刹车：设置标志，各线程完成当前 I/O 后退出，避免 0 字节残次文件
 * 仅当流水线已启动后才响应，避免控制台/脚本在启动时产生的虚假 CTRL_C 导致未复制即退出 */
/* Ctrl+C 安全刹车：首次尝试优雅退出，再次按下暴力退出 */
static BOOL WINAPI CtrlHandler(DWORD ctrlType) {
  if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT) {
	/* 这四行防误触保护，允许随时响应取消！ */
    if (!READ_VOLATILE_32(&g_PipelineStarted)) 
      return TRUE;
    // 保护期稍微缩短一点，3秒足够了
    if (GetTickCount() - g_PipelineStartTick < 3000) 
      return TRUE;

    // 原子递增按下的次数
    LONG count = InterlockedIncrement(&g_CtrlCCount);

    if (count == 1) {
      InterlockedExchange(&g_IsCanceling, 1);
      wprintf(L"\n[WARN] Ctrl+C received, safely shutting down IO... (Press Ctrl+C again to force quit)\n");
      
    } 
    else if (count >= 2) {
      wprintf(L"\n[FATAL] Force terminating process by user request!\n");
      ExitProcess(1); // 第二次按下，无条件暴力结束进程
    }
    return TRUE;
  }
  return FALSE;
}

void InitPerformanceCounters() {
  if (PdhOpenQuery(NULL, 0, &g_PdhQuery) == ERROR_SUCCESS) {
    if (PdhAddEnglishCounterW(
            g_PdhQuery, L"\\PhysicalDisk(_Total)\\Current Disk Queue Length", 0,
            &g_PdhDiskQueue) != ERROR_SUCCESS) {
      PdhCloseQuery(g_PdhQuery);
      g_PdhQuery = NULL;
      return;
    }
    /* Phase 20: CPU 负载，Host-Aware QoS 用 */
    if (PdhAddEnglishCounterW(
            g_PdhQuery, L"\\Processor(_Total)\\% Processor Time", 0,
            &g_PdhCpuUsage) != ERROR_SUCCESS)
      g_PdhCpuUsage = NULL;
  }
}

static DWORD GetDiskQueue(void) {
  if (!g_PdhQuery || !g_PdhDiskQueue)
    return 0;
  if (PdhCollectQueryData(g_PdhQuery) == ERROR_SUCCESS) {
    PDH_FMT_COUNTERVALUE cv;
    if (PdhGetFormattedCounterValue(g_PdhDiskQueue, PDH_FMT_LONG, NULL, &cv) ==
        ERROR_SUCCESS)
      return (DWORD)cv.longValue;
  }
  return 0;
}

/* Phase 20: Host-Aware QoS，返回 0~100 CPU 使用率。P3：仅 OsTelemetryThread 调用，其他线程读 g_CachedCpuLoad */
static DWORD GetCPULoad() {
  if (!g_PdhQuery || !g_PdhCpuUsage)
    return 0;
  if (PdhCollectQueryData(g_PdhQuery) == ERROR_SUCCESS) {
    PDH_FMT_COUNTERVALUE cv;
    if (PdhGetFormattedCounterValue(g_PdhCpuUsage, PDH_FMT_DOUBLE, NULL, &cv) ==
        ERROR_SUCCESS && cv.CStatus == PDH_CSTATUS_VALID_DATA)
      return (DWORD)(cv.doubleValue + 0.5);
  }
  return 0;
}

/* P3 OsTelemetryThread：1s 周期 PDH 采样，写入 g_CachedCpuLoad/g_CachedDiskQueue，消除多线程 PDH 争用 */
static unsigned __stdcall OsTelemetryThread(void *p) {
  (void)p;
  while (g_LogThreadRunning) {
    if (g_PdhQuery) {
      if (PdhCollectQueryData(g_PdhQuery) == ERROR_SUCCESS) {
        if (g_PdhDiskQueue) {
          PDH_FMT_COUNTERVALUE cv;
          if (PdhGetFormattedCounterValue(g_PdhDiskQueue, PDH_FMT_LONG, NULL, &cv) == ERROR_SUCCESS)
            g_CachedDiskQueue = (DWORD)cv.longValue;
        }
        if (g_PdhCpuUsage) {
          PDH_FMT_COUNTERVALUE cv;
          if (PdhGetFormattedCounterValue(g_PdhCpuUsage, PDH_FMT_DOUBLE, NULL, &cv) == ERROR_SUCCESS &&
              cv.CStatus == PDH_CSTATUS_VALID_DATA)
            g_CachedCpuLoad = (DWORD)(cv.doubleValue + 0.5);
        }
      }
    }
    /* N8 优化：单次 1s 事件等待替代 10×Sleep(100)，减少 9 次无意义内核唤醒；
     * g_hOsTelemetryStopEvent 在关闭时 SetEvent，实现即时退出。 */
    if (g_hOsTelemetryStopEvent)
      WaitForSingleObject(g_hOsTelemetryStopEvent, 1000);
    else
      Sleep(1000);
  }
  return 0;
}

/* Large Pages 可选：管理员权限 + 策略时使用，减少 TLB 缺失。失败时静默降级 */
static BOOL g_LargePagesAvailable = FALSE;
static void *AllocBufferWithLargePagesFallback(SIZE_T size) {
  typedef SIZE_T (WINAPI * GetLargePageMinimumProc)(void);
  static GetLargePageMinimumProc pGetLargePageMinimum = NULL;
  if (!pGetLargePageMinimum)
    pGetLargePageMinimum = (GetLargePageMinimumProc)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetLargePageMinimum");
  if (pGetLargePageMinimum && g_LargePagesAvailable) {
    SIZE_T pgMin = pGetLargePageMinimum();
    if (pgMin > 0 && size >= pgMin) {
      SIZE_T aligned = (size + pgMin - 1) & ~(pgMin - 1);
      void *p = VirtualAlloc(NULL, aligned, MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES, PAGE_READWRITE);
      if (p) return p;
      g_LargePagesAvailable = FALSE; /* 失败则后续不再尝试 */
    }
  }
  return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

/* 绝对可靠的 UNC 探针，PathIsUNCW 对 \\?\UNC\ 返回 FALSE，必须手写
 * P4：SSE2 向量化前 8 字符判定，消除 EnsureParentDirExistsEx 热路径分支预测失误 */
static BOOL IsUncPathEx(const wchar_t *path) {
  if (!path) return FALSE;
  if (path[0] != L'\\' || path[1] != L'\\') return FALSE;
  if (!path[2]) return FALSE;
  if (!path[3] || !path[4] || !path[5] || !path[6] || !path[7])
    return (path[2] != L'?' && path[2] != L'.');  /* 不足 8 字符用标量，避免 SIMD 越界 */
  /* 一次加载前 8 个 wchar_t，向量化判定 \\?\UNC\ 与经典 UNC */
  __m128i u16 = _mm_loadu_si128((const __m128i *)path);
  __m128i unc_prefix = _mm_set_epi16((short)L'\\', (short)L'c', (short)L'n', (short)L'u',
                                     (short)L'\\', (short)L'?', (short)L'\\', (short)L'\\');
  __m128i mask_lower = _mm_set_epi16(0, 0x20, 0x20, 0x20, 0, 0, 0, 0);  /* 仅 U/N/C 转小写 */
  __m128i u16_lower = _mm_or_si128(u16, mask_lower);
  __m128i eq = _mm_cmpeq_epi16(u16_lower, unc_prefix);
  if (_mm_movemask_epi8(eq) == (int)0xFFFF)  /* 全匹配 => \\?\UNC\ */
    return TRUE;
  if (path[2] != L'?' && path[2] != L'.')  /* 经典 UNC \\server\share */
    return TRUE;
  return FALSE;
}
#define IsUncPath(path) IsUncPathEx(path)

/* GetVolumePathNameW 卷根 → CreateFile/DeviceIoControl 用的设备路径（\\.\X: 或 \\.\Volume{GUID}）。
 * 禁止再用 volumePath[0] 当盘符：\\?\ 前缀时 [0] 为反斜杠，会拼成 \\.\:
 * 注意：IOCTL 打开卷设备时路径末尾不得带 \（否则易成目录句柄或 ACCESS_DENIED）；Volume{GUID} 须去掉全部尾 \。 */
static BOOL VolumeRootToDosDevicePath(const wchar_t *volumeRoot, wchar_t *out, size_t outCch) {
  if (!volumeRoot || !out || outCch < 16)
    return FALSE;
  out[0] = L'\0';
  if (((volumeRoot[0] >= L'A' && volumeRoot[0] <= L'Z') ||
        (volumeRoot[0] >= L'a' && volumeRoot[0] <= L'z')) &&
      volumeRoot[1] == L':') {
    StringCchPrintfW(out, outCch, L"\\\\.\\%c:", volumeRoot[0]);
    return TRUE;
  }
  if (wcsncmp(volumeRoot, L"\\\\?\\", 4) == 0) {
    if (((volumeRoot[4] >= L'A' && volumeRoot[4] <= L'Z') ||
         (volumeRoot[4] >= L'a' && volumeRoot[4] <= L'z')) &&
        volumeRoot[5] == L':') {
      StringCchPrintfW(out, outCch, L"\\\\.\\%c:", volumeRoot[4]);
      return TRUE;
    }
    if (wcsncmp(volumeRoot, L"\\\\?\\Volume{", 11) == 0) {
      wchar_t tmp[MAX_PATH_EXT];
      if (FAILED(StringCchCopyW(tmp, MAX_PATH_EXT, volumeRoot)))
        return FALSE;
      size_t len = wcslen(tmp);
      while (len > 0 && tmp[len - 1] == L'\\')
        tmp[--len] = L'\0';
      if (FAILED(StringCchPrintfW(out, outCch, L"\\\\.\\%s", tmp + 4)))
        return FALSE;
      return TRUE;
    }
  }
  return FALSE;
}

/* GetVolumeInformationW / GetDiskFreeSpaceW：卷根 lpRootPathName 应以反斜杠结尾（MSDN）。 */
static void PbEnsureTrailingBackslashForVolumeQuery(wchar_t *path, size_t cch) {
  if (!path || cch < 4)
    return;
  size_t n = wcslen(path);
  if (n > 0 && n + 1 < cch && path[n - 1] != L'\\') {
    path[n] = L'\\';
    path[n + 1] = L'\0';
  }
}

/* IsSSD：UNC 路径返回 FALSE，盘符路径才探测；支持长路径 */
BOOL IsSSD(const wchar_t *path) {
  wchar_t volumePath[MAX_PATH_EXT];
  if (!GetVolumePathNameW(path, volumePath, MAX_PATH_EXT))
    return FALSE;
  if (IsUncPath(volumePath))
    return FALSE;
  wchar_t driveName[128];
  if (!VolumeRootToDosDevicePath(volumePath, driveName, 128))
    return FALSE;
  HANDLE hDrive = CreateFileW(driveName, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              NULL, OPEN_EXISTING, 0, NULL);
  if (hDrive == INVALID_HANDLE_VALUE) {
    if (g_fErrorLog)
      LogMessage(LOG_WARNING, L"[IsSSD] Failed to open drive %s, err=%lu\n",
                 driveName, GetLastError());
    else
      wprintf(L"[IsSSD] Failed to open drive %s, err=%lu\n", driveName,
              GetLastError());
    return FALSE;
  }
  STORAGE_PROPERTY_QUERY query = {StorageDeviceSeekPenaltyProperty,
                                  PropertyStandardQuery};
  DEVICE_SEEK_PENALTY_DESCRIPTOR descriptor = {0};
  DWORD bytesReturned = 0;
  BOOL success = DeviceIoControl(hDrive, IOCTL_STORAGE_QUERY_PROPERTY, &query,
                                 sizeof(query), &descriptor, sizeof(descriptor),
                                 &bytesReturned, NULL);
  if (!success && g_fErrorLog)
    LogMessage(LOG_WARNING, L"[IsSSD] DeviceIoControl failed for %s, err=%lu\n",
               driveName, GetLastError());
  CloseHandle(hDrive);
  return success && !descriptor.IncursSeekPenalty;
}

/* 探测卷宗逻辑扇区大小；GetVolumePathNameW 穿透挂载点直达物理卷，支持 UNC/长路径 */
static DWORD ProbeSectorSizeEx(const wchar_t *path) {
  wchar_t volumePath[MAX_PATH_EXT];
  if (!GetVolumePathNameW(path, volumePath, MAX_PATH_EXT))
    return 4096;
  PbEnsureTrailingBackslashForVolumeQuery(volumePath, MAX_PATH_EXT);
  DWORD sectorsPerCluster, bytesPerSector, freeClusters, totalClusters;
  if (GetDiskFreeSpaceW(volumePath, &sectorsPerCluster, &bytesPerSector,
                        &freeClusters, &totalClusters))
    return bytesPerSector;
  return 4096;
}

/* 探测簇大小（sectorsPerCluster * bytesPerSector），块克隆需簇对齐 */
static DWORD ProbeClusterSizeEx(const wchar_t *path) {
  wchar_t volumePath[MAX_PATH_EXT];
  if (!GetVolumePathNameW(path, volumePath, MAX_PATH_EXT))
    return 4096;
  PbEnsureTrailingBackslashForVolumeQuery(volumePath, MAX_PATH_EXT);
  DWORD sectorsPerCluster, bytesPerSector, freeClusters, totalClusters;
  if (GetDiskFreeSpaceW(volumePath, &sectorsPerCluster, &bytesPerSector,
                        &freeClusters, &totalClusters))
    return sectorsPerCluster * bytesPerSector;
  return 4096;
}

/* 卷序列号：与 GetVolumePathNameW 同卷判定互补，防路径规范化边缘情况 */
static BOOL GetVolumeSerialNumberFromPath(const wchar_t *path, DWORD *outSerial) {
  wchar_t root[8] = {0};
  if (path && path[0] && path[1] == L':' && (path[2] == L'\\' || path[2] == L'/')) {
    root[0] = path[0];
    root[1] = L':';
    root[2] = L'\\';
    root[3] = L'\0';
  } else if (path && wcsncmp(path, L"\\\\?\\", 4) == 0 && path[4] && path[5] == L':') {
    root[0] = path[4];
    root[1] = L':';
    root[2] = L'\\';
    root[3] = L'\0';
  } else {
    wchar_t vol[MAX_PATH_EXT];
    if (!path || !GetVolumePathNameW(path, vol, MAX_PATH_EXT))
      return FALSE;
    if (wcslen(vol) < 3)
      return FALSE;
    if (wcsncmp(vol, L"\\\\?\\", 4) == 0 &&
        ((vol[4] >= L'A' && vol[4] <= L'Z') || (vol[4] >= L'a' && vol[4] <= L'z')) &&
        vol[5] == L':') {
      root[0] = vol[4];
      root[1] = L':';
      root[2] = L'\\';
      root[3] = L'\0';
    } else if (((vol[0] >= L'A' && vol[0] <= L'Z') || (vol[0] >= L'a' && vol[0] <= L'z')) &&
               vol[1] == L':' && (vol[2] == L'\\' || vol[2] == L'/')) {
      root[0] = vol[0];
      root[1] = L':';
      root[2] = L'\\';
      root[3] = L'\0';
    } else if (wcsncmp(vol, L"\\\\?\\Volume{", 11) == 0) {
      wchar_t volRoot[MAX_PATH_EXT];
      if (FAILED(StringCchCopyW(volRoot, MAX_PATH_EXT, vol)))
        return FALSE;
      PbEnsureTrailingBackslashForVolumeQuery(volRoot, MAX_PATH_EXT);
      return GetVolumeInformationW(volRoot, NULL, 0, outSerial, NULL, NULL, NULL, 0);
    } else
      return FALSE;
  }
  return GetVolumeInformationW(root, NULL, 0, outSerial, NULL, NULL, NULL, 0);
}

/* 动态物理扇区对齐：企业级 512B/4K/8K/16K 扇区阵列兼容
 * FILE_FLAG_NO_BUFFERING 必须按物理扇区对齐，硬编码 4096 在非 4K 设备上会 ERROR_INVALID_PARAMETER(87)
 * 逻辑扇区与 IOCTL 物理扇区不一致时（512e/4Kn）取二者较大值作对齐粒度。
 * *outIoctlTrusted：仅在 STORAGE_ACCESS_ALIGNMENT 成功时 TRUE，供 g_BigFileUseDirectIo 判定。 */
static DWORD ProbePhysicalSectorSizeTrusted(const wchar_t *path, BOOL *outIoctlTrusted) {
  *outIoctlTrusted = FALSE;
  DWORD logical = ProbeSectorSizeEx(path);
  if (logical < 512)
    logical = 512;
  wchar_t volumePath[MAX_PATH_EXT];
  if (!GetVolumePathNameW(path, volumePath, MAX_PATH_EXT))
    return logical;
  if (IsUncPath(volumePath))
    return logical; /* UNC：无法可靠 IOCTL，几何未证实 → 不信任 Direct I/O */
  wchar_t drivePrefix[128];
  if (!VolumeRootToDosDevicePath(volumePath, drivePrefix, 128))
    return logical;
  HANDLE hVol = CreateFileW(drivePrefix, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
  if (hVol == INVALID_HANDLE_VALUE)
    return logical;
  STORAGE_PROPERTY_QUERY query = {StorageAccessAlignmentProperty, PropertyStandardQuery};
  STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR align = {0};
  DWORD bytesReturned = 0;
  BOOL ok = DeviceIoControl(hVol, IOCTL_STORAGE_QUERY_PROPERTY, &query,
                            sizeof(query), &align, sizeof(align), &bytesReturned, NULL);
  CloseHandle(hVol);
  if (ok && bytesReturned >= sizeof(align) && align.BytesPerPhysicalSector > 0) {
    *outIoctlTrusted = TRUE;
    DWORD phys = align.BytesPerPhysicalSector;
    if (phys < 512)
      phys = 512;
    return (logical >= phys) ? logical : phys;
  }
  return logical;
}

static DWORD ProbePhysicalSectorSizeEx(const wchar_t *path) {
  BOOL dummy;
  return ProbePhysicalSectorSizeTrusted(path, &dummy);
}

/* 获取物理磁盘索引 (PhysicalDriveX) */
static int GetPhysicalDiskIndex(const wchar_t *path) {
  wchar_t volumePath[MAX_PATH_EXT];
  if (!GetVolumePathNameW(path, volumePath, MAX_PATH_EXT))
    return -1;
  if (IsUncPath(volumePath))
    return -1;
  wchar_t drivePrefix[128];
  if (!VolumeRootToDosDevicePath(volumePath, drivePrefix, 128))
    return -1;
  HANDLE hDrive = CreateFileW(drivePrefix, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              NULL, OPEN_EXISTING, 0, NULL);
  if (hDrive == INVALID_HANDLE_VALUE)
    return -1;

  STORAGE_DEVICE_NUMBER sdn;
  DWORD bytesReturned;
  int index = -1;
  if (DeviceIoControl(hDrive, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &sdn,
                      sizeof(sdn), &bytesReturned, NULL)) {
    index = (int)sdn.DeviceNumber;
  }
  CloseHandle(hDrive);
  return index;
}

// 建议 5: 优化 DirCache 大小，64 位 XXH3 防生日悖论（百万目录碰撞概率 < 百亿分之一）
#define DIR_CACHE_SIZE 16777213
volatile LONG64 g_DirCache[DIR_CACHE_SIZE] = {0};

#define DST_DIR_CACHE_SIZE 16777216   /* Phase 18：32 对齐，Swiss Table 探测 */
#define DST_DIR_CTRL_EMPTY 0x80
#define DST_DIR_GROUP_SIZE 32
/* Phase 22 AoS：Ctrl 与 Hash 同 Cache Line，命中时 L1 无延迟。16B/slot，4 槽/64B */
struct DstDirSlot {
  uint8_t ctrl;
  uint8_t _pad[7];
  volatile LONG64 hash;
};
static struct DstDirSlot g_DstDirSlots[DST_DIR_CACHE_SIZE];
/* Round4 P3 Bug2：用 InitOnceExecuteOnce 替代自制三态自旋锁。
 * 原三态自旋锁隐患：若线程 A 被外部 SuspendThread（调试器/EDR）或 SEH 异常阻断，
 * flag 永久停在 1，等待线程 B/C/D 陷入无法自愈的活锁。
 * InitOnceExecuteOnce 由 Windows 内核安全接管等待队列：
 *   - 回调抛出异常时，等待线程收到失败通知而非永久阻塞；
 *   - 天然支持 SuspendThread 场景的恢复；
 *   - 比自旋等待更节能（等待线程进入内核等待，不占 CPU）。*/
static INIT_ONCE g_DstDirCacheInitOnce = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK DstDirCacheInitCallback(INIT_ONCE *once, void *param, void **ctx) {
  (void)once; (void)param; (void)ctx;
  /* Round6 P2：memset 替代 16 字节步长循环，消除 Cache Thrashing，256MB 初始化 <1ms */
  memset(g_DstDirSlots, DST_DIR_CTRL_EMPTY, sizeof(g_DstDirSlots));
  return TRUE;  /* 返回 FALSE 则通知等待线程初始化失败 */
}

static void DstDirCacheInit(void) {
  /* InitOnceExecuteOnce 保证回调仅执行一次，内核级等待安全，无活锁风险 */
  InitOnceExecuteOnce(&g_DstDirCacheInitOnce, DstDirCacheInitCallback, NULL, NULL);
}

/* Phase 22：AoS 布局，Ctrl+Hash 同 Cache Line，消除 L1d Miss。统一标量探测，顺序访问友好 */
static BOOL CheckDstDirCacheEx(const wchar_t *dir, size_t len) {
  DstDirCacheInit();
  if (len == 0) len = wcslen(dir);
  ULONG64 uHash = (ULONG64)XXH3_64bits(dir, len * sizeof(wchar_t));
  if (uHash == 0) uHash = 1;
  uint8_t targetCtrl = (uint8_t)((uHash >> 8) & 0x7F);
  if (targetCtrl == DST_DIR_CTRL_EMPTY) targetCtrl = 0x7F;
  LONG64 atomicHash = (LONG64)uHash;
  /* Phase 25：numGroups=524288 为 2^19，用 &mask 替代 % 消灭 DIV 指令（30 周期→1 周期） */
  DWORD numGroups = DST_DIR_CACHE_SIZE / DST_DIR_GROUP_SIZE;
  DWORD mask = numGroups - 1;
  DWORD groupIdx = (DWORD)(uHash & mask);
  for (DWORD step = 0; step < numGroups && step < 1024; step++) {
    DWORD base = ((groupIdx + step) & mask) * DST_DIR_GROUP_SIZE;
    for (int i = 0; i < DST_DIR_GROUP_SIZE; i++) {
      struct DstDirSlot *s = &g_DstDirSlots[base + i];
      if (s->ctrl == DST_DIR_CTRL_EMPTY) return FALSE;
      if ((s->ctrl & 0x7F) == targetCtrl && s->hash == atomicHash)
        return TRUE;
    }
  }
  return FALSE;
}

/* 自动把路径加入 Windows Defender 排除项，减少复制过程中的锁冲突。
 * 使用 CreateProcessW 继承当前进程 token（不触发 UAC）：
 *   - 以管理员运行本程序 → PowerShell 继承管理员 token → Add-MpPreference 成功
 *   - 非管理员运行 → PowerShell 继承普通 token → Add-MpPreference 静默失败，不影响主流程
 * tag: L"src" / L"dst"，用于日志区分；失败时输出可操作的诊断信息 */
static BOOL AddDefenderExclusion(const wchar_t *path, const wchar_t *tag) {
  if (!path || !path[0]) {
    wprintf(L"[WARN] Defender exclusion (%ls): empty path\n", tag);
    return FALSE;
  }
  /* 仅 \\server\share 与 \\?\UNC\... 为网络路径；\\?\E:\ 等为本地长路径前缀，勿误判为 UNC */
  if (wcsncmp(path, L"\\\\?\\UNC\\", 8) == 0) {
    wprintf(L"[WARN] Defender exclusion (%ls): skipped — UNC/network path "
            L"(use mapped drive or add exclusion manually in Windows Security)\n", tag);
    return FALSE;
  }
  if (path[0] == L'\\' && path[1] == L'\\' && path[2] != L'?') {
    wprintf(L"[WARN] Defender exclusion (%ls): skipped — UNC/network path "
            L"(use mapped drive or add exclusion manually in Windows Security)\n", tag);
    return FALSE;
  }

  /* 供 Defender/PowerShell：剥掉 \\?\ 等内部前缀（与日志 PathForDisplay 一致） */
  wchar_t psPath[MAX_PATH_EXT];
  PathForDisplayW(path, psPath, MAX_PATH_EXT);
  if (!psPath[0]) {
    wprintf(L"[WARN] Defender exclusion (%ls): empty path after normalize\n", tag);
    return FALSE;
  }

  /* 路径中含单引号会破坏 PowerShell 单引号参数，需改用手动排除或缩短路径 */
  if (wcschr(psPath, L'\'')) {
    wprintf(L"[WARN] Defender exclusion (%ls): path contains apostrophe (single quote); "
            L"add exclusion manually or rename path\n", tag);
    return FALSE;
  }

  wchar_t cmdline[MAX_PATH * 4];
  HRESULT hr = StringCchPrintfW(cmdline, MAX_PATH * 4,
      L"powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -Command "
      L"\"try { Add-MpPreference -ExclusionPath '%ls' -ErrorAction SilentlyContinue } catch {}\"",
      psPath);
  if (FAILED(hr)) {
    wprintf(L"[WARN] Defender exclusion (%ls): command line too long or invalid (HRESULT=0x%08lX). "
            L"Path may exceed internal buffer (~%u wchar)\n",
            tag, (unsigned long)hr, (unsigned)(MAX_PATH * 4));
    return FALSE;
  }

  STARTUPINFOW si = {0};
  si.cb          = sizeof(si);
  si.dwFlags     = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION pi = {0};

  if (!CreateProcessW(NULL, cmdline, NULL, NULL, FALSE,
                      CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
    DWORD e = GetLastError();
    wprintf(L"[WARN] Defender exclusion (%ls): CreateProcessW(powershell) failed, err=%lu "
            L"(e.g. 2=not found, check PATH and powershell.exe)\n",
            tag, (unsigned long)e);
    return FALSE;
  }

  DWORD wait = WaitForSingleObject(pi.hProcess, 8000);
  DWORD exitCode = 1;
  if (wait == WAIT_TIMEOUT) {
    TerminateProcess(pi.hProcess, 1);
    WaitForSingleObject(pi.hProcess, 3000);
    wprintf(L"[WARN] Defender exclusion (%ls): PowerShell timed out after 8s\n", tag);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return FALSE;
  }

  GetExitCodeProcess(pi.hProcess, &exitCode);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);

  if (exitCode != 0) {
    wprintf(L"[WARN] Defender exclusion (%ls): PowerShell exit code=%lu (0=success). "
            L"Common: Tamper Protection, GPO blocking exclusions, or MpPreference disabled.\n",
            tag, (unsigned long)exitCode);
    return FALSE;
  }

  wprintf(L"[INFO] Defender exclusion (%ls): OK — %ls\n", tag, psPath);
  return TRUE;
}

/* 一次 PowerShell 同时排除 src+dst，避免串行冷启动 CLR（约 3~8s） */
static BOOL AddDefenderExclusionsPair(const wchar_t *src, const wchar_t *dst) {
  wchar_t psSrc[MAX_PATH_EXT] = {0}, psDst[MAX_PATH_EXT] = {0};
  BOOL hasSrc = FALSE, hasDst = FALSE;
  if (src && src[0]) {
    PathForDisplayW(src, psSrc, MAX_PATH_EXT);
    if (psSrc[0] && !wcschr(psSrc, L'\'') &&
        !(psSrc[0] == L'\\' && psSrc[1] == L'\\' && psSrc[2] != L'?') &&
        wcsncmp(psSrc, L"\\\\?\\UNC\\", 8) != 0)
      hasSrc = TRUE;
  }
  if (dst && dst[0]) {
    PathForDisplayW(dst, psDst, MAX_PATH_EXT);
    if (psDst[0] && !wcschr(psDst, L'\'') &&
        !(psDst[0] == L'\\' && psDst[1] == L'\\' && psDst[2] != L'?') &&
        wcsncmp(psDst, L"\\\\?\\UNC\\", 8) != 0)
      hasDst = TRUE;
  }
  if (!hasSrc && !hasDst) return FALSE;
  if (hasSrc && !hasDst) return AddDefenderExclusion(src, L"src");
  if (!hasSrc && hasDst) return AddDefenderExclusion(dst, L"dst");

  wchar_t cmdline[MAX_PATH * 6];
  HRESULT hr = StringCchPrintfW(cmdline, MAX_PATH * 6,
      L"powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -Command "
      L"\"try { Add-MpPreference -ExclusionPath @('%ls','%ls') -ErrorAction SilentlyContinue } catch {}\"",
      psSrc, psDst);
  if (FAILED(hr)) {
    BOOL r1 = AddDefenderExclusion(src, L"src");
    BOOL r2 = AddDefenderExclusion(dst, L"dst");
    return r1 || r2;
  }
  STARTUPINFOW si = {0};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION pi = {0};
  if (!CreateProcessW(NULL, cmdline, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
    BOOL r1 = AddDefenderExclusion(src, L"src");
    BOOL r2 = AddDefenderExclusion(dst, L"dst");
    return r1 || r2;
  }
  DWORD wait = WaitForSingleObject(pi.hProcess, 12000);
  DWORD exitCode = 1;
  if (wait == WAIT_TIMEOUT) {
    TerminateProcess(pi.hProcess, 1);
    WaitForSingleObject(pi.hProcess, 3000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    wprintf(L"[WARN] Defender exclusion (pair): PowerShell timed out\n");
    return FALSE;
  }
  GetExitCodeProcess(pi.hProcess, &exitCode);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  if (exitCode != 0) {
    wprintf(L"[WARN] Defender exclusion (pair): exit=%lu\n", (unsigned long)exitCode);
    return FALSE;
  }
  wprintf(L"[INFO] Defender exclusion (pair): OK — %ls | %ls\n", psSrc, psDst);
  return TRUE;
}

static void AddDstDirCacheEx(const wchar_t *dir, size_t len) {
  DstDirCacheInit();
  if (len == 0) len = wcslen(dir);
  ULONG64 uHash = (ULONG64)XXH3_64bits(dir, len * sizeof(wchar_t));
  if (uHash == 0) uHash = 1;
  uint8_t targetCtrl = (uint8_t)((uHash >> 8) & 0x7F);
  if (targetCtrl == DST_DIR_CTRL_EMPTY) targetCtrl = 0x7F;
  LONG64 atomicHash = (LONG64)uHash;
  DWORD numGroups = DST_DIR_CACHE_SIZE / DST_DIR_GROUP_SIZE;
  DWORD mask = numGroups - 1;
  DWORD groupIdx = (DWORD)(uHash & mask);
  for (DWORD step = 0; step < numGroups && step < 1024; step++) {
    DWORD base = ((groupIdx + step) & mask) * DST_DIR_GROUP_SIZE;
    for (int i = 0; i < DST_DIR_GROUP_SIZE; i++) {
      struct DstDirSlot *s = &g_DstDirSlots[base + i];
      if (s->ctrl != DST_DIR_CTRL_EMPTY) {
        if (READ_VOLATILE_64(&s->hash) == atomicHash) return;
        continue;
      }
      LONG64 exist = READ_VOLATILE_64(&s->hash);
      if (exist == atomicHash) return;
      if (exist != 0) continue;
      /* D1 修复：先写 ctrl，再 CAS hash，消除短暂 hash≠0 但 ctrl==EMPTY 的不一致窗口。
       * x64 TSO 下 LIGHT_BARRIER() 已足够；ARM64 编译器会生成 stlb (store-release)。 */
      s->ctrl = targetCtrl;
      LIGHT_BARRIER();
      exist = InterlockedCompareExchange64(&s->hash, atomicHash, 0);
      if (exist == 0 || exist == atomicHash) {
        return;
      }
      /* CAS 失败：slot 已被其他线程占用，恢复 ctrl=EMPTY 让下一次探测正常工作 */
      s->ctrl = DST_DIR_CTRL_EMPTY;
    }
  }
}
#define AddDstDirCache(dir) AddDstDirCacheEx((dir), 0)

/* V123: 动态缓冲区降级读 - 遇到资源匮乏时缩小分块重试 */
static BOOL ReadFileWithReduce(HANDLE h, void *buf, DWORD size, DWORD *bytesRead) {
  DWORD totalRead = 0;
  DWORD toRead = size;
  BYTE *p = (BYTE *)buf;
  while (totalRead < size) {
    DWORD rd;
    if (ReadFile(h, p + totalRead, toRead, &rd, NULL)) {
      if (rd == 0) break;
      totalRead += rd;
      toRead = size - totalRead;
      if (toRead == 0) break;
    } else {
      if (GetLastError() == ERROR_NO_SYSTEM_RESOURCES && toRead > g_SectorSize) {
        toRead /= 2;
        continue;
      }
      if (bytesRead) *bytesRead = totalRead;
      return FALSE;
    }
  }
  if (bytesRead) *bytesRead = totalRead;
  return TRUE;
}

/* V123: 动态缓冲区降级写 - 解决大块 I/O 导致内核 Page Pool 枯竭的问题 */
static BOOL WriteFileWithReduce(HANDLE h, const void *buf, DWORD size, DWORD *bytesWritten) {
  DWORD totalWritten = 0;
  DWORD toWrite = size;
  const BYTE *p = (const BYTE *)buf;
  while (totalWritten < size) {
    DWORD wr;
    if (WriteFile(h, p + totalWritten, toWrite, &wr, NULL)) {
      if (wr == 0 && toWrite > 0) return FALSE;
      totalWritten += wr;
      toWrite = size - totalWritten;
      if (toWrite == 0) break;
    } else {
      if (GetLastError() == ERROR_NO_SYSTEM_RESOURCES && toWrite > g_SectorSize) {
        toWrite /= 2;
        continue;
      }
      if (bytesWritten) *bytesWritten = totalWritten;
      return FALSE;
    }
  }
  if (bytesWritten) *bytesWritten = totalWritten;
  ApplyIpGap((LONGLONG)totalWritten);
  return TRUE;
}

/* P2 乐观读：先 volatile 读，仅空槽时 CAS，大目录并发时消除 99% 总线锁 */
BOOL CheckAndAddDirCacheEx(const wchar_t *dir, size_t len) {
  if (len == 0) len = wcslen(dir);
  ULONG64 uHash = (ULONG64)XXH3_64bits(dir, len * sizeof(wchar_t));
  if (uHash == 0) uHash = 1;
  DWORD h2 = 1 + (DWORD)(uHash % (DIR_CACHE_SIZE - 1));
  DWORD idx = (DWORD)(uHash % DIR_CACHE_SIZE);
  LONG64 atomicHash = (LONG64)uHash;
  for (DWORD step = 0; step < DIR_CACHE_SIZE && step < 1024; step++) {
    DWORD curr = (idx + step * h2) % DIR_CACHE_SIZE;
    LONG64 exist = READ_VOLATILE_64(&g_DirCache[curr]);
    if (exist == atomicHash) return FALSE;
    if (exist == 0) {
      exist = InterlockedCompareExchange64(&g_DirCache[curr], atomicHash, 0);
      if (exist == 0) return TRUE;
      if (exist == atomicHash) return FALSE;
    }
  }
  return TRUE;
}
#define CheckAndAddDirCache(dir) CheckAndAddDirCacheEx((dir), 0)

#define SPLIT_THRESHOLD (1024 * 1024)
#define SMALL_FILE_THRESHOLD (1024 * 1024)
#define TINY_FILE_THRESHOLD (64 * 1024)
#define PROGRESSIVE_FLUSH_MB 32
#define MAX_RETRY_COUNT 5
#define RETRY_BASE_DELAY_MS 100
#define RETRY_MAX_DELAY_MS 5000
/* DLQ 同一任务反复 reflux→失败→再入队 的硬上限，防止无限循环占满 DLQ/IOCP */
#define MAX_DLQ_ROUND_TRIPS 3

/* 智能错误分类：ERR_SKIP 立刻放弃，ERR_TRANSIENT 短暂休眠，ERR_NETWORK_DROP 长跳避让 */
typedef enum {
  ERR_RETRY,         /* 通用重试，指数退避 */
  ERR_SKIP,          /* 致命/不可恢复，立即 break */
  ERR_TRANSIENT,     /* 共享冲突等瞬时错误，1ms/5ms 短暂休眠 */
  ERR_NETWORK_DROP   /* 网络瞬断/SMB 故障，15s/30s/60s 长跳避让，交换机主备/Nutanix CVM 漂移 */
} ErrorClass;
#define FLUSH_COUNT_THRESHOLD 12
#define RATIO_UPDATE_INTERVAL 50
#define FLUSH_TIME_MS 250
#define SPARSE_INIT_RANGES 64

DWORD g_BigBufferSize = 32 * 1024 * 1024;
DWORD g_SectorSize = 4096; /* 启动时探测，默认 4096 */
BOOL g_BigFileUseDirectIo = TRUE; /* 源/目均成功 IOCTL_STORAGE 对齐探测时才 TRUE */
#define IOSTRAT_BLOCK_CLONE     0
#define IOSTRAT_BIG_DIRECT_IO   1
#define IOSTRAT_BIG_BUFFERED    2
#define IOSTRAT_COUNT           3
volatile LONG64 g_IoStrategyStats[IOSTRAT_COUNT] = {0};
volatile LONG g_BlockCloneFsctlFailLogCount = 0; /* 限次 WARNING，防千万文件刷屏 */
volatile LONG g_MaxQueueDepth = 30000;

#define KEY_COPY_TASK 1
#define KEY_SCAN_TASK 2
#define KEY_TERMINATE 3
#define KEY_VERIFY 4
#define OVERFLOW_REFILL    80000    /* 低于 8 万时从溢出文件滑入，Consumer 滑入内存 */
#define OVERFLOW_IDLE_EXIT_MS 600000 /* 10min 无新数据才退出：百万级小文件时 drain 可阻塞数分钟，60s 仍会漏拷 */

HANDLE g_hBigFileSemaphore = NULL;
#define MMF_HIGH_WATER_MB 2048  /* 2GB 虚拟地址空间高水位，防止千万碎文件 MapViewOfFile 耗尽 VA */
HANDLE g_hMMFMapSemaphore = NULL;  /* 每 1MB 映射占 1 token，超限则阻塞或降级 ReadFile */
volatile LONG g_TotalFound = 0;
volatile LONG g_TotalCopied = 0;
volatile LONG64 g_TotalBytes = 0;
volatile LONG64 g_TotalFoundBytes = 0; /* 扫描阶段累加，用于 ETA */

/* Phase 8 分布式原子桶：64B 对齐消除缓存行失效风暴，每线程独占 Cache Line */
#define MAX_THREAD_BUCKETS 64
typedef struct {
  volatile LONG64 copiedBytes;
  volatile LONG copied;
  char _pad[64 - sizeof(LONG64) - sizeof(LONG)];  /* 填满 64B */
} CACHE_ALIGN ThreadBucket;
static ThreadBucket g_ThreadBuckets[MAX_THREAD_BUCKETS];
static int g_NumThreadBuckets = 0;

/* Phase 25 回滚：ThreadBucket 恢复 Interlocked，避免 -march=native 下部分 CPU 的可见性/顺序问题导致提前退出 */
#define AddBucketBytes(param, delta) do { \
  int _ti = (param) ? ((param)->ThreadIndex) : -1; \
  if (_ti >= 0 && _ti < g_NumThreadBuckets) \
    InterlockedAdd64((volatile LONGLONG *)&g_ThreadBuckets[_ti].copiedBytes, (delta)); \
  else \
    InterlockedAdd64(&g_TotalBytes, (delta)); \
} while(0)
#define AddBucketCopied(param, n) do { \
  int _ti = (param) ? ((param)->ThreadIndex) : -1; \
  if (_ti >= 0 && _ti < g_NumThreadBuckets) \
    InterlockedExchangeAdd(&g_ThreadBuckets[_ti].copied, (n)); \
  else \
    InterlockedExchangeAdd(&g_TotalCopied, (n)); \
} while(0)
static inline LONG64 SumBucketBytes(void) {
  LONG64 sum = 0;
  for (int i = 0; i < g_NumThreadBuckets; i++)
    sum += READ_VOLATILE_64(&g_ThreadBuckets[i].copiedBytes);
  return sum;
}
static inline LONG SumBucketCopied(void) {
  LONG sum = 0;
  for (int i = 0; i < g_NumThreadBuckets; i++)
    sum += READ_VOLATILE_32(&g_ThreadBuckets[i].copied);
  return sum;
}

CACHE_ALIGN volatile LONG g_PendingActive =
    0; /* 硬件级隔离，防止 False Sharing */
volatile LONG g_PendingCopyTasks = 0; /* 仅实体文件 Copy 任务，背压仅针对此，打破扫描器活锁 */
volatile LONG g_ActiveCopierLimit = 1;
#define ADAPTIVE_IO_SAMPLES 1000
#define ADAPTIVE_LOW_MS  1   /* <1ms 视为 NVMe，放开限流 */
#define ADAPTIVE_HIGH_MS 15  /* >15ms 视为 HDD/网络拥塞，收缩至 2-4 线程 */
static DWORD g_IoLatencySamples[ADAPTIVE_IO_SAMPLES];
static volatile LONG g_IoLatencyIdx = 0;
static volatile LONG g_IoLatencyCount = 0;
volatile LONG g_IsCanceling = 0; /* InterlockedExchange/InterlockedOr 保证跨线程可见性 */
/* -move 跨卷模式：收集待删源目录，主循环结束后自底向上 RemoveDirectoryW */
typedef struct { SLIST_ENTRY ItemEntry; wchar_t *Path; } MoveSourceDirEntry;
static PSLIST_HEADER g_MoveSourceDirsList = NULL;
static CRITICAL_SECTION g_MoveSourceDirsCs;
volatile LONG g_InsufficientSpace = 0; /* 前置容量预检：目标盘空间不足，退出码 2 */
/* 预检余量：MFT/元数据/舍入与流式统计与 GetDiskFreeSpaceEx 存在边界差，避免「差百兆级」误杀 */
#define DST_SPACE_PREFLIGHT_SLACK_BYTES ((LONGLONG)(256 * 1024 * 1024))
volatile LONG g_PipelineStarted = 0; /* 流水线已投递根任务后才响应 Ctrl+C，避免启动期虚假控制事件导致未复制即退出 */
DWORD g_PipelineStartTick = 0;       /* 流水线启动时刻 GetTickCount() */
volatile LONGLONG g_AvailableTokens = 0;   /* QoS 令牌桶 */
volatile LONGLONG g_SpeedLimitBps = 0;    /* 0=不限速 (Bytes per second) */
volatile LONG g_Md5Success = 0;
volatile LONG g_Md5Fail = 0;
volatile LONG g_SmallFiles = 0;
volatile LONG g_MediumFiles = 0;
volatile LONG g_LargeFiles = 0;
volatile LONG g_SmallFileRatio = 0;
volatile LONG g_HardLinkCount = 0;
volatile LONG64 g_HardLinkBytes = 0;
volatile LONG g_TotalFailed = 0;
volatile LONG g_PendingVerify = 0;
/* Robocopy 风格文件状态分类：审计日志用 */
volatile LONG g_StateLonely = 0;   /* 源有目标无，已复制 */
volatile LONG g_StateSame = 0;     /* 完全相同，跳过 */
volatile LONG g_StateOlder = 0;     /* 目标较旧，已覆盖 */
volatile LONG g_StateTweaked = 0;   /* 大小时间同，仅 attr/ACL 不同，已修复 */
HANDLE g_hVerifyIocp = NULL;
HANDLE *g_hVerifyThreads = NULL;
typedef struct _VerifyParam VerifyParam;
VerifyParam **g_VerifyParams = NULL; /* 每线程一个，启动时分配，零 malloc */
int g_NumVerifyThreads = 0;
volatile BOOL g_VerifyThreadRunning = TRUE;
BOOL g_IsSameVolume = FALSE;
/* advice1 P2: BlockClone 卷属性静态缓存（InitSameVolumeCache 一次探测） */
static BOOL g_BlockCloneProbed = FALSE;
static BOOL g_CanBlockClone = FALSE;
static DWORD g_BlockCloneAlignSize = 4096;
static DWORD g_BlockCloneVolSerial = 0;
BOOL g_IoRingAvailable = FALSE; /* 运行时检测：Win11/Server2022+ 为 TRUE */
#if HAS_VSS
/* VSS 全局持有：快照生命周期与 IVssBackupComponents 对象强绑定，必须持有到程序退出 */
static IVssBackupComponents *g_pVss = NULL;
static void CleanupVss(void) {
  if (g_pVss) {
    g_pVss->lpVtbl->Release(g_pVss);
    g_pVss = NULL;
    CoUninitialize();
  }
}
#endif
LARGE_INTEGER g_StartTime;
LARGE_INTEGER g_Freq;
HANDLE g_hTelemetryPipe = INVALID_HANDLE_VALUE;
static BOOL g_bTelemetryEnabled = FALSE;  /* Zero-Cost Headless：ParentPid==0 时跳过遥测构建 */
#if USE_SHM_TELEMETRY
HANDLE g_hTelemetryMapping = NULL;
SharedTelemetry *g_pTelemetryShared = NULL;
#endif
HANDLE g_hStopEvent = NULL;
HANDLE g_hPauseReleaseEvent = NULL;  /* Phase 15：恢复时 SetEvent，零 CPU 轮询暂停 */
/* 多后缀哈希过滤：-f ".txt;.log;.bak" 支持分号分隔，≤4 字符用 64 位比较，>4 用 XXH3 */
#define FILTER_EXT_MAX 16
typedef struct { UINT64 hash; int len; } FilterExtItem;
static FilterExtItem g_FilterExts[FILTER_EXT_MAX];
static int g_FilterExtCount = 0;
/* V6：有界扫描替代 wcslen，千万文件时消除 O(n) 遍历 */
static inline BOOL PassesExtFilter(const wchar_t *pDot) {
  if (!pDot || g_FilterExtCount <= 0) return FALSE;
  int len = 0;
  while (len < 128 && pDot[len]) len++;
  for (int i = 0; i < g_FilterExtCount; i++) {
    if (len != g_FilterExts[i].len) continue;
    if (g_FilterExts[i].len <= 4) {
      UINT64 raw;
      memcpy(&raw, pDot, sizeof(raw));
      if (g_Config.CaseInsensitive)
        raw |= 0x0020002000200020ULL;  /* ASCII a-z 转小写 */
      if (raw == g_FilterExts[i].hash) return TRUE;
    } else {
      wchar_t ext[128];
      StringCchCopyW(ext, 128, pDot);
      if (g_Config.CaseInsensitive) {
#if defined(USE_AVX2_ZERO_CHECK) && USE_AVX2_ZERO_CHECK
        ToLowerASCII_AVX2(ext, (size_t)len);
#else
        _wcslwr(ext);
#endif
      }
      if ((UINT64)XXH3_64bits(ext, (size_t)len * sizeof(wchar_t)) == g_FilterExts[i].hash)
        return TRUE;
    }
  }
  return FALSE;
}
HANDLE g_hOverflowFile = INVALID_HANDLE_VALUE;   /* MMF 溢出：写入端专用句柄 */
HANDLE g_hOverflowConsumer = NULL;
volatile LONGLONG g_OverflowWritePos = 0;        /* 原子写位置，Consumer 追赶；用 LONGLONG 防止 >2GB 时溢出 */
static wchar_t g_OverflowFilePath[MAX_PATH];    /* Round6 P0：Consumer 独立打开只读句柄用路径 */
static CRITICAL_SECTION g_OverflowCs;
#define OVERFLOW_BUF_SIZE (4 * 1024 * 1024)     /* 4MB 聚合缓冲，千万文件时系统调用从 3000 万降至数百 */
#define OVERFLOW_REC_MAGIC 0xDEADBEEF           /* QA：每条记录尾 4B 魔数，断电/截断时 Consumer 校验防越界崩溃 */
static BYTE *g_OverflowBuffer = NULL;
static DWORD g_OverflowBufUsed = 0;
static HANDLE g_OverflowIocp = NULL;             /* Consumer 投递用 */

/* P2 梯度重试：前 5 次 20ms，5 次 50ms，10 次 100ms，更快放弃或成功 */
#if USE_SHM_TELEMETRY
static HANDLE g_hLogRingMapping = NULL;
static HANDLE g_hLogRingBufMapping = NULL;
static HANDLE g_hLogRingNotifyEvent = NULL;    /* GUI 创建 Local\\PBXFlow_LogRing_Event_<ParentPid>，引擎 SetEvent */
static SharedLogRing *g_pLogRing = NULL;
static uint8_t *g_pLogRingBuffer = NULL;       /* P2：buffer 本地指针，Magic Ring 时 8MB 虚拟连续 */
static BOOL g_useMagicRingBuffer = FALSE;     /* P2：双重映射成功则 TRUE，写入无分支 */

/* Phase 21 SharedLogRing：SPSC 无锁，记录格式 [4B size][2B level][UTF-16 数据]
 * P3：线程局部 tmp 避免 2KB 栈分配；P2 Magic Ring：无分支单次 memcpy */
#if defined(_MSC_VER)
static __declspec(thread) uint8_t s_logRingTmp[2056];
#else
static __thread uint8_t s_logRingTmp[2056];
#endif
/* P1：LogRing 满时丢弃计数，首次告警便于诊断 GUI 卡顿导致日志积压 */
static volatile LONG s_LogRingDropCount = 0;
/* LogRing 唤醒节流：空环边沿 SetEvent；非空时最多每 64 条或 10ms 强制 SetEvent，抑制海量小文件下的内核切换 */
static volatile LONG s_LogRingWritesSinceSet = 0;
static DWORD s_LogRingLastSetTick = 0;
#ifndef LOG_RING_WAKE_BURST
#define LOG_RING_WAKE_BURST 64
#endif
#ifndef LOG_RING_WAKE_MS
#define LOG_RING_WAKE_MS 10
#endif
/* Phase 22：len>0 时透传省 wcslen，0 则内部 wcsnlen */
static void LogRingWriteEx(uint16_t level, const wchar_t *msg, size_t len) {
  SharedLogRing *ring = g_pLogRing;
  uint8_t *buf = g_pLogRingBuffer;
  if (!ring || !buf || !msg) return;
  if (len == 0) {
    for (len = 0; len < 1024 && msg[len]; len++) ;
  } else if (len > 1024) {
    len = 1024;
  }
  size_t req = 6 + (len + 1) * sizeof(wchar_t);
  if (req > LOG_RING_SIZE - 64) return;
  uint32_t h = (uint32_t)READ_VOLATILE_32((volatile LONG *)&ring->head);
  uint32_t t = (uint32_t)READ_VOLATILE_32((volatile LONG *)&ring->tail);
  uint32_t freeBytes = (t > h) ? (t - h - 1) : (LOG_RING_SIZE - h + t - 1);
  if (freeBytes < (uint32_t)req) {
    /* Round6 P1：审计红线——ERROR 绝不丢弃，绕过 Ring 直接写盘；INFO 等可安心丢弃 */
    if (level == (uint16_t)LOG_ERROR && g_fErrorLog) {
      fputws(msg, g_fErrorLog);
      fflush(g_fErrorLog);
    } else {
      LONG prev = InterlockedIncrement((volatile LONG *)&s_LogRingDropCount);
      if (prev == 1)
        fwprintf(stderr, L"[LogRing] Buffer full, log dropped. (GUI may be slow.)\n");
    }
    return;
  }
  uint8_t *tmp = s_logRingTmp;
  *(uint32_t *)tmp = (uint32_t)req;
  *(uint16_t *)(tmp + 4) = level;
  memcpy(tmp + 6, msg, (len + 1) * sizeof(wchar_t));
  if (g_useMagicRingBuffer) {
    /* P2 Magic Ring：单次 memcpy，越界时第二映射自动折回物理头部 */
    memcpy(buf + h, tmp, (size_t)req);
  } else {
    if (h + (uint32_t)req <= LOG_RING_SIZE) {
      memcpy(buf + h, tmp, (size_t)req);
    } else {
      uint32_t part1 = LOG_RING_SIZE - h;
      memcpy(buf + h, tmp, part1);
      memcpy(buf, tmp + part1, (size_t)req - part1);
    }
  }
  LIGHT_BARRIER();
  ring->head = (h + (uint32_t)req) % LOG_RING_SIZE;
  if (g_hLogRingNotifyEvent) {
    uint32_t was_empty = (h == t);
    if (was_empty) {
      SetEvent(g_hLogRingNotifyEvent);
      s_LogRingLastSetTick = GetTickCount();
      InterlockedExchange(&s_LogRingWritesSinceSet, 0);
    } else {
      LONG c = InterlockedIncrement(&s_LogRingWritesSinceSet);
      DWORD now = GetTickCount();
      if (s_LogRingLastSetTick == 0)
        s_LogRingLastSetTick = now;
      DWORD elapsed = (DWORD)(now - s_LogRingLastSetTick);
      if ((DWORD)c >= (DWORD)LOG_RING_WAKE_BURST || elapsed >= (DWORD)LOG_RING_WAKE_MS) {
        SetEvent(g_hLogRingNotifyEvent);
        s_LogRingLastSetTick = now;
        InterlockedExchange(&s_LogRingWritesSinceSet, 0);
      }
    }
  }
}
#define LogRingWrite(level, msg) LogRingWriteEx((level), (msg), 0)

static void InitTelemetryPipe(void) {
  if (g_Config.ParentPid == 0) return;
  wchar_t shmName[MAX_PATH];
  StringCchPrintfW(shmName, MAX_PATH, L"%s%u", TELEMETRY_SHM_PREFIX, (unsigned)g_Config.ParentPid);
  for (int retry = 0; retry < 20; retry++) {
    g_hTelemetryMapping = OpenFileMappingW(FILE_MAP_WRITE, FALSE, shmName);
    if (g_hTelemetryMapping) {
      g_pTelemetryShared = (SharedTelemetry *)MapViewOfFile(g_hTelemetryMapping, FILE_MAP_WRITE, 0, 0, SHARED_TELEMETRY_SIZE);
      if (g_pTelemetryShared) {
        /* P4 防御性清零：避免 GUI 异常退出后残留指令 */
        g_pTelemetryShared->data.cmd_Pause = 0;
        g_pTelemetryShared->data.cmd_Cancel = 0;
        g_pTelemetryShared->isDirty = 0;
        /* Phase 21 + P2 Magic Ring：打开 buffer 与 metadata，buffer 尝试双重映射 */
        wchar_t bufShmName[MAX_PATH];
        StringCchPrintfW(bufShmName, MAX_PATH, L"%s%u%s", TELEMETRY_SHM_PREFIX, (unsigned)g_Config.ParentPid, LOG_RING_BUF_SUFFIX);
        g_hLogRingBufMapping = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, bufShmName);
        if (g_hLogRingBufMapping) {
          void *baseAddr = VirtualAlloc(NULL, (SIZE_T)LOG_RING_SIZE * 2, MEM_RESERVE, PAGE_NOACCESS);
          if (baseAddr) {
            VirtualFree(baseAddr, 0, MEM_RELEASE);
            uint8_t *m1 = (uint8_t *)MapViewOfFileEx(g_hLogRingBufMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, LOG_RING_SIZE, baseAddr);
            uint8_t *m2 = (uint8_t *)MapViewOfFileEx(g_hLogRingBufMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, LOG_RING_SIZE, (uint8_t *)baseAddr + LOG_RING_SIZE);
            if (m1 == baseAddr && m2 == (uint8_t *)baseAddr + LOG_RING_SIZE) {
              g_pLogRingBuffer = m1;
              g_useMagicRingBuffer = TRUE;
            } else {
              if (m1) UnmapViewOfFile(m1);
              if (m2) UnmapViewOfFile(m2);
              g_pLogRingBuffer = (uint8_t *)MapViewOfFile(g_hLogRingBufMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, LOG_RING_SIZE);
            }
          }
          if (!g_pLogRingBuffer)
            g_pLogRingBuffer = (uint8_t *)MapViewOfFile(g_hLogRingBufMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, LOG_RING_SIZE);
        }
        StringCchPrintfW(shmName, MAX_PATH, L"%s%u%s", TELEMETRY_SHM_PREFIX, (unsigned)g_Config.ParentPid, LOG_RING_SHM_SUFFIX);
        g_hLogRingMapping = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, shmName);
        if (g_hLogRingMapping && g_pLogRingBuffer) {
          g_pLogRing = (SharedLogRing *)MapViewOfFile(g_hLogRingMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, SHARED_LOG_RING_META_SIZE);
          if (!g_pLogRing) { CloseHandle(g_hLogRingMapping); g_hLogRingMapping = NULL; }
        }
        if (g_pLogRing) {
          wchar_t evName[MAX_PATH];
          StringCchPrintfW(evName, MAX_PATH, L"%s%u", LOG_RING_EVENT_PREFIX, (unsigned)g_Config.ParentPid);
          g_hLogRingNotifyEvent = OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, evName);
        }
        /* V10：SHM 存在即启动 ControlSampler，唯一读取 isDirty 的线程，消灭多线程竞态 */
        if (!g_hTokenThread) {
          InterlockedExchange(&g_TokenThreadRunning, 1);
          g_hTokenThread = (HANDLE)_beginthreadex(NULL, 0, TokenBucketThread, NULL, 0, NULL);
        }
        break;
      }
      CloseHandle(g_hTelemetryMapping);
      g_hTelemetryMapping = NULL;
    } else if (retry == 19) {
      DWORD err = GetLastError();
      if (err == ERROR_FILE_NOT_FOUND || err == ERROR_INVALID_NAME)
        wprintf(L"[INFO] Telemetry SHM not ready (GUI may not have created mapping yet)\n");
    }
    Sleep(retry < 5 ? 20 : (retry < 10 ? 50 : 100));
  }
}
#else
static void InitTelemetryPipe(void) {
  if (g_Config.ParentPid == 0) return;
  wchar_t pipeName[MAX_PATH];
  StringCchPrintfW(pipeName, MAX_PATH, L"%s%u", TELEMETRY_PIPE_PREFIX, (unsigned)g_Config.ParentPid);
  for (int retry = 0; retry < 20; retry++) {
    g_hTelemetryPipe = CreateFileW(pipeName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (g_hTelemetryPipe != INVALID_HANDLE_VALUE) break;
    if (GetLastError() != ERROR_PIPE_BUSY) break;
    Sleep(retry < 5 ? 20 : (retry < 10 ? 50 : 100));
  }
}
#endif

static void InitStopEvent(void) {
  if (g_Config.ParentPid == 0) return;
  wchar_t evtName[MAX_PATH];
  StringCchPrintfW(evtName, MAX_PATH, L"%s%u", TELEMETRY_STOP_EVENT, (unsigned)g_Config.ParentPid);
  g_hStopEvent = OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, evtName);
  StringCchPrintfW(evtName, MAX_PATH, L"%s%u", TELEMETRY_PAUSE_RELEASE_EVENT, (unsigned)g_Config.ParentPid);
  g_hPauseReleaseEvent = OpenEventW(SYNCHRONIZE, FALSE, evtName);
}

/* Round4：提升为文件级全局，消除 static 局部变量的隐性单线程假设；
 * 两个 BroadcastTelemetry 实现（SHM / Pipe）共享同一节流时钟，防止未来扩展时引入竞态 */
static volatile DWORD g_LastTelemetryTick = 0;

/* P1 节流：最多 30 次/秒，与 GUI 刷新频率匹配；isFinished!=0 时强制发送 */
#if USE_SHM_TELEMETRY
static void BroadcastTelemetry(const TelemetryData *data) {
  if (!g_pTelemetryShared || !data) return;
  DWORD now = GetTickCount();
  if (data->isFinished == 0 && (now - g_LastTelemetryTick) < TELEMETRY_THROTTLE_MS) return;
  InterlockedExchange((volatile LONG *)&g_LastTelemetryTick, (LONG)now);
  SharedTelemetry *shm = g_pTelemetryShared;
  /* Phase 25 回滚：恢复 InterlockedIncrement，避免 CLI 独立运行时部分编译器/CPU 的 store 顺序问题
   * P4：显式内存屏障，ARM64 弱内存序下保证 memcpy 不被乱序泄漏到 seq 之外 */
  InterlockedIncrement(&shm->seq);  /* 奇数=写入中（seq 现为 volatile LONG，无需强制转换）*/
  MemoryBarrier();
  memcpy(&shm->data, data, offsetof(TelemetryData, cmd_Pause));
  shm->data.eta_seconds = data->eta_seconds;
  shm->data.failedFiles = data->failedFiles;
  shm->data.io_block_clone = data->io_block_clone;
  shm->data.io_direct_big = data->io_direct_big;
  shm->data.io_buffered_big = data->io_buffered_big;
  MemoryBarrier();
  InterlockedIncrement(&shm->seq);  /* 偶数=可读 */
}
#else
static void BroadcastTelemetry(const TelemetryData *data) {
  if (g_hTelemetryPipe == INVALID_HANDLE_VALUE || !data) return;
  DWORD now = GetTickCount();
  if (data->isFinished == 0 && (now - g_LastTelemetryTick) < TELEMETRY_THROTTLE_MS) return;
  InterlockedExchange((volatile LONG *)&g_LastTelemetryTick, (LONG)now);
  DWORD written = 0;
  if (!WriteFile(g_hTelemetryPipe, data, TELEMETRY_DATA_SIZE, &written, NULL) ||
      written != TELEMETRY_DATA_SIZE) {
    if (GetLastError() != ERROR_NO_DATA) {
      CloseHandle(g_hTelemetryPipe);
      g_hTelemetryPipe = INVALID_HANDLE_VALUE;
    }
  }
}
#endif

/* Phase 13 Dirty Flag：热路径仅 1 条 load(isDirty)，99.99% 直接放行；GUI 写 cmd_* 后置 1
 * 注意：多线程同时调用时可能竞态清 isDirty，导致某线程未读到最新 cmd_*；因 cmd_* 变化频率低，可接受 */
#if USE_SHM_TELEMETRY
static uint32_t s_cached_Cancel = 0, s_cached_Pause = 0, s_cached_SpeedLimit = 0;
static void ReadControlIfDirty(void) {
  SharedTelemetry *shm = g_pTelemetryShared;
  if (!shm) return;
  if (*(volatile const uint8_t *)&shm->isDirty) {
    LIGHT_BARRIER();  /* Phase 16：x64 TSO 仅需编译器屏障，0 时钟周期 */
    s_cached_Cancel = shm->data.cmd_Cancel;
    s_cached_Pause = shm->data.cmd_Pause;
    s_cached_SpeedLimit = shm->data.cmd_SpeedLimit;
    LIGHT_BARRIER();
    shm->isDirty = 0;
  }
}
#endif

static BOOL CheckStopEvent(void) {
  /* CLI 模式（无 GUI 父进程）：绝不响应停止事件，避免误判导致任务被丢弃、Done:0 即退出 */
  if (g_Config.ParentPid == 0) return FALSE;
#if USE_SHM_TELEMETRY
  if (UNLIKELY(s_cached_Cancel != 0)) return TRUE;  /* V10：只读缓存，TokenBucketThread 唯一更新 */
#endif
  if (!g_hStopEvent) return FALSE;
  return WaitForSingleObject(g_hStopEvent, 0) == WAIT_OBJECT_0;
}

#if USE_SHM_TELEMETRY
/* Phase 8 cmd_Pause：GUI 写入 1 时阻塞，释放 I/O 不占用内核；Worker 与主循环共用
 * Phase 15 PauseReleaseEvent：恢复时 SetEvent 唤醒，零 CPU 轮询 */
static void WaitIfPaused(void) {
  while (g_pTelemetryShared) {
    if (s_cached_Pause == 0) break;  /* V10：只读缓存 */
    if (CheckStopEvent()) break;
    if (IsCanceling()) break;  /* GUI 暴毙时 ParentWatcherThread 置位，穿透暂停避免死锁 */
    if (g_hPauseReleaseEvent)
      WaitForSingleObject(g_hPauseReleaseEvent, 100);
    else
      Sleep(100);
  }
}
#endif

/* Phase 9 路径字符串 Arena：Bump Pointer 替代 _wcsdup，消灭堆锁争用
 * P2 分片：8 个 Arena，Round4 改用 TLS 递增索引分配，取代 ThreadId%8（ThreadId 低位不均匀）
 * P3 溢出续接：链式 Chunk，64MB 满时自动 VirtualAlloc 新块，理论无限扩展
 * Round4 P2 架构1：TLS 槽保存每线程绑定的 Shard 索引（0~7），
 *   首次访问时用原子计数器分配，保证数学均衡（0,1,2,...7,0,1,...循环）。
 *   TLS 值存为 (idx+1)，以区分 0 和"未初始化的 NULL"。*/
#define STRING_ARENA_CHUNK_SIZE (64 * 1024 * 1024)  /* 64MB per chunk */
#define STRING_ARENA_SHARDS 8   /* V5：64 线程时每 shard 8 线程，降低锁争用 */
static DWORD g_TlsArenaShardSlot = TLS_OUT_OF_INDEXES;  /* Round4: TLS 均匀分片路由 */
static volatile LONG s_ArenaShardCounter = -1;           /* 原子计数器，每线程取走 1 个索引 */
typedef struct ArenaChunk {
  struct ArenaChunk *next;
  size_t offset;
  size_t capacity;
  char *data;
} ArenaChunk;
typedef struct {
  ArenaChunk *head;
  ArenaChunk *current;
  CRITICAL_SECTION cs;
} StringArena;
static StringArena *g_StringArenaShards[STRING_ARENA_SHARDS];
static StringArena *g_StringArena = NULL;  /* 兼容 IsArenaPtr：指向 shard[0] */

/* Phase 20 TLAB：每线程 2MB 线性分配，零锁竞争，纪元级释放。bytes 含 \\0 */
#define TLAB_CHUNK_SIZE (2 * 1024 * 1024)
#define MAX_TLAB_MEMORY (2LL * 1024 * 1024 * 1024)  /* 2GB 熔断 */
#ifdef _MSC_VER
#define DECLSPEC_ALIGN(x) __declspec(align(x))
#else
#ifndef DECLSPEC_ALIGN
#define DECLSPEC_ALIGN(x) __attribute__((aligned(x)))
#endif
#endif
typedef struct DECLSPEC_ALIGN(16) TlabChunk {
  SLIST_ENTRY Entry;
  char _pad[64 - sizeof(SLIST_ENTRY)];
  wchar_t Data[1];
} TlabChunk;
typedef struct {
  TlabChunk *currentChunk;
  size_t offset;
  size_t capacity;
} ThreadArena;
static PSLIST_HEADER g_GlobalTlabGarbageList = NULL;
static volatile LONG64 g_TotalTlabBytesAllocated = 0;
static CRITICAL_SECTION g_TlabChunkCs;
static BOOL g_TlabInitialized = FALSE;
#define TLAB_CHUNK_BASES_MAX 1024
static struct { void *base; size_t size; } g_TlabChunkBases[TLAB_CHUNK_BASES_MAX];
static int g_TlabChunkCount = 0;

static wchar_t *TlabStrDupEx(ThreadArena *arena, const wchar_t *str, size_t bytes) {
  if (!arena || !str || !g_GlobalTlabGarbageList) return _wcsdup(str);
  size_t alignedBytes = (bytes + 7) & ~(size_t)7;
  if (UNLIKELY(arena->offset + alignedBytes > arena->capacity)) {
    LONG64 prev = InterlockedAdd64(&g_TotalTlabBytesAllocated, (LONG64)TLAB_CHUNK_SIZE);
    if (prev >= MAX_TLAB_MEMORY) {
      InterlockedAdd64(&g_TotalTlabBytesAllocated, -(LONG64)TLAB_CHUNK_SIZE);
      return NULL;
    }
    if (arena->currentChunk) {
      InterlockedPushEntrySList(g_GlobalTlabGarbageList, &arena->currentChunk->Entry);
    }
    TlabChunk *chunk = (TlabChunk *)_aligned_malloc(TLAB_CHUNK_SIZE, 16);
    if (!chunk) {
      InterlockedAdd64(&g_TotalTlabBytesAllocated, -(LONG64)TLAB_CHUNK_SIZE);
      return NULL;
    }
    if (g_TlabInitialized) {
      EnterCriticalSection(&g_TlabChunkCs);
      if (g_TlabChunkCount < TLAB_CHUNK_BASES_MAX) {
        g_TlabChunkBases[g_TlabChunkCount].base = chunk;
        g_TlabChunkBases[g_TlabChunkCount].size = TLAB_CHUNK_SIZE - offsetof(TlabChunk, Data);
        g_TlabChunkCount++;
      }
      LeaveCriticalSection(&g_TlabChunkCs);
    }
    arena->currentChunk = chunk;
    arena->offset = 0;
    arena->capacity = TLAB_CHUNK_SIZE - offsetof(TlabChunk, Data);
  }
  wchar_t *ptr = (wchar_t *)((char *)arena->currentChunk->Data + arena->offset);
  arena->offset += alignedBytes;
  memcpy(ptr, str, bytes);
  return ptr;
}
static void TlabThreadExit(ThreadArena *arena) {
  if (!arena) return;
  if (arena->currentChunk) {
    InterlockedPushEntrySList(g_GlobalTlabGarbageList, &arena->currentChunk->Entry);
    arena->currentChunk = NULL;
  }
  arena->offset = arena->capacity = 0;
}
static void CleanupTlabGarbage(void) {
  if (!g_GlobalTlabGarbageList) return;
  PSLIST_ENTRY pEntry;
  while ((pEntry = InterlockedPopEntrySList(g_GlobalTlabGarbageList)) != NULL) {
    TlabChunk *chunk = (TlabChunk *)((char *)pEntry - offsetof(TlabChunk, Entry));
    PB_ALIGNED_FREE(chunk);
  }
  EnterCriticalSection(&g_TlabChunkCs);
  g_TlabChunkCount = 0;
  LeaveCriticalSection(&g_TlabChunkCs);
  InterlockedExchange64(&g_TotalTlabBytesAllocated, 0);
}

static wchar_t *ArenaStrDup(StringArena *arena, const wchar_t *str) {
  (void)arena;
  /* Round4 P2 架构1：TLS 均匀分片路由，取代 ThreadId%8（Windows ThreadId 低位分布不均匀）。
   * 每个线程首次进入时用原子递增计数器分配一个 Shard 索引，后续直接从 TLS 读取，零竞争。
   * 退回路径：TLS 槽未分配（初始化过早）时回退到 ThreadId%SHARDS，保证向后兼容。 */
  DWORD shardIdx = 0;
  if (g_TlsArenaShardSlot != TLS_OUT_OF_INDEXES) {
    LPVOID tlsVal = TlsGetValue(g_TlsArenaShardSlot);
    if (!tlsVal) {
      /* 首次访问：原子分配 Shard 索引，循环 [0, STRING_ARENA_SHARDS) */
      LONG raw = InterlockedIncrement(&s_ArenaShardCounter);
      shardIdx = (DWORD)(raw % STRING_ARENA_SHARDS);
      TlsSetValue(g_TlsArenaShardSlot, (LPVOID)(uintptr_t)(shardIdx + 1));
    } else {
      shardIdx = (DWORD)((uintptr_t)tlsVal - 1);
    }
  } else {
    shardIdx = (DWORD)GetCurrentThreadId() % STRING_ARENA_SHARDS;  /* 初始化前回退 */
  }
  StringArena *a = g_StringArenaShards ? g_StringArenaShards[shardIdx] : NULL;
  if (!a || !str) return _wcsdup(str);
  size_t len = wcslen(str);
  /* -Q 100000 加固：超长路径回退 _wcsdup，防止 Arena 块内越界 */
  if (len >= MAX_PATH_EXT) return _wcsdup(str);
  size_t bytes = (len + 1) * sizeof(wchar_t);
  wchar_t *ptr = NULL;
  EnterCriticalSection(&a->cs);
  for (;;) {
    if (a->current && a->current->offset + bytes <= a->current->capacity) {
      ptr = (wchar_t *)(a->current->data + a->current->offset);
      a->current->offset += bytes;
      break;
    }
    ArenaChunk *chunk = (ArenaChunk *)calloc(1, sizeof(ArenaChunk));
    if (!chunk) break;
    chunk->data = (char *)AllocBufferWithLargePagesFallback(STRING_ARENA_CHUNK_SIZE);
    if (!chunk->data) { free(chunk); break; }
    chunk->capacity = STRING_ARENA_CHUNK_SIZE;
    chunk->next = NULL;
    if (a->current) a->current->next = chunk;
    else a->head = chunk;
    a->current = chunk;
  }
  LeaveCriticalSection(&a->cs);
  if (ptr) {
    memcpy(ptr, str, bytes);
    return ptr;
  }
  return _wcsdup(str);  /* 回退堆分配 */
}
/* Round6 P1：CopyTask/ScanTask 瞬态路径用 _wcsdup，避免 Arena 只借不还导致 PB 级 OOM。DirMeta 仍用 StrDupWithLen。 */
static wchar_t *StrDupTransient(const wchar_t *str, size_t charLen) {
  if (!str || charLen >= MAX_PATH_EXT) return NULL;
  return _wcsdup(str);
}
/* 有 tlab 时优先 TLAB，否则回退 Arena；charLen 不含 \\0。仅用于 DirMeta 等长生命周期结构。 */
static wchar_t *StrDupWithLen(ThreadArena *tlab, StringArena *arena, const wchar_t *str, size_t charLen) {
  if (!str) return NULL;
  /* -Q 100000 加固：路径长度硬限制，防止超出 MAX_PATH_EXT 导致堆/栈溢出 */
  if (charLen >= MAX_PATH_EXT) return NULL;
  size_t bytes = (charLen + 1) * sizeof(wchar_t);
  if (tlab && g_GlobalTlabGarbageList) {
    wchar_t *r = TlabStrDupEx(tlab, str, bytes);
    if (r) return r;
  }
  return ArenaStrDup(arena, str);
}
static BOOL IsArenaPtr(const void *p) {
  if (!p) return FALSE;
  if (g_StringArenaShards) {
    for (int i = 0; i < STRING_ARENA_SHARDS; i++) {
      StringArena *a = g_StringArenaShards[i];
      if (!a) continue;
      for (ArenaChunk *c = a->head; c; c = c->next) {
        if (c->data && (const char *)p >= c->data && (const char *)p < c->data + c->capacity)
          return TRUE;
      }
    }
  }
  /* Phase 22 快速路径：g_TlabChunkCount==0 时跳过，避免无谓加锁 */
  if (g_TlabInitialized && g_TlabChunkCount > 0) {
    EnterCriticalSection(&g_TlabChunkCs);
    for (int i = 0; i < g_TlabChunkCount; i++) {
      const char *base = (const char *)g_TlabChunkBases[i].base;
      if (base && (const char *)p >= base && (const char *)p < base + g_TlabChunkBases[i].size)
        { LeaveCriticalSection(&g_TlabChunkCs); return TRUE; }
    }
    LeaveCriticalSection(&g_TlabChunkCs);
  }
  return FALSE;
}

struct _IO_BACKEND;  /* 前向声明，完整定义见 VFS 层 */
/* CopyTask：99.9% 路径 < MAX_PATH 时用内置 ShortSrc/ShortDst
 * 零堆分配，超长路径用 ArenaStrDup 或 _wcsdup
 * Phase 12 VFS 记忆化：pSrcBackend/pDstBackend 一次解析、全程复用，消除千万次 wcsncmp
 * Phase 20/3 长度透传：SrcLen/DstLen 字符数不含 \\0，uint32_t 足矣 (MAX_PATH_EXT 32767) */
/* BUG-C9 修复：pathFlags 在分配时记录来源，TLC_FreeCopyTask/FreeCopyTask 直接读取，
 * 消除每次释放 O(n) 扫描 Arena 分片的热路径开销（1000 万文件 = 2000 万次扫描）*/
#define TASK_PATH_FLAG_SRC_ARENA   0x01  /* SrcPath 来自 StringArena */
#define TASK_PATH_FLAG_DST_ARENA   0x02  /* DstPath 来自 StringArena */
#define TASK_PATH_FLAG_SRC_SHORT   0x04  /* SrcPath == ShortSrc（无需 free） */
#define TASK_PATH_FLAG_DST_SHORT   0x08  /* DstPath == ShortDst（无需 free） */

struct _CopyTask {
  SLIST_ENTRY ItemEntry;
  wchar_t *SrcPath;
  uint32_t SrcLen;   /* 字符数不含 \\0，0 表示未知需 wcslen */
  wchar_t *DstPath;
  uint32_t DstLen;
  wchar_t ShortSrc[MAX_PATH];
  wchar_t ShortDst[MAX_PATH];
  LONG64 FileSize;
  FILETIME CreationTime;
  FILETIME LastAccessTime;
  FILETIME LastWriteTime;
  DWORD FileAttributes;
  const struct _IO_BACKEND *pSrcBackend;  /* 记忆化：扫描时设置，复制时直接使用 */
  const struct _IO_BACKEND *pDstBackend;
  uint8_t pathFlags;  /* TASK_PATH_FLAG_* 组合，分配时设置，free 时无需 IsArenaPtr 扫描 */
  uint8_t DlqRoundCount; /* 入 DLQ 次数（reflux 后再失败会递增），>= MAX_DLQ_ROUND_TRIPS 则放弃 */
};
typedef struct _CopyTask CopyTask;

typedef struct {
  SLIST_ENTRY ItemEntry;
  wchar_t *SrcPath;
  uint32_t SrcLen;   /* 字符数不含 \\0 */
  wchar_t *DstPath;
  uint32_t DstLen;
  wchar_t ShortSrc[MAX_PATH];
  wchar_t ShortDst[MAX_PATH];
  uint8_t pathFlags;  /* D4：同 CopyTask.pathFlags，free 时无需 O(n) IsArenaPtr 扫描 */
} ScanTask;

/* Phase 10 BFS 扫描：FIFO 队列，同级目录批量处理，HDD 减少 MFT 寻道 */
typedef struct BfsScanQueue {
  CRITICAL_SECTION cs;
  ScanTask *head;
  ScanTask *tail;
  HANDLE hSem;
  volatile LONG count;
} BfsScanQueue;
static BfsScanQueue *g_BfsScanQueue = NULL;

static void PushBfsScanTask(ScanTask *t) {
  if (!g_BfsScanQueue || !t) return;
  t->ItemEntry.Next = NULL;
  EnterCriticalSection(&g_BfsScanQueue->cs);
  if (g_BfsScanQueue->tail)
    g_BfsScanQueue->tail->ItemEntry.Next = &t->ItemEntry;
  else
    g_BfsScanQueue->head = t;
  g_BfsScanQueue->tail = t;
  InterlockedIncrement(&g_BfsScanQueue->count);
  LeaveCriticalSection(&g_BfsScanQueue->cs);
  if (g_BfsScanQueue->hSem)
    ReleaseSemaphore(g_BfsScanQueue->hSem, 1, NULL);
}
static ScanTask *PopBfsScanTask(void) {
  if (!g_BfsScanQueue) return NULL;
  if (WaitForSingleObject(g_BfsScanQueue->hSem, 1000) != WAIT_OBJECT_0)
    return NULL;
  EnterCriticalSection(&g_BfsScanQueue->cs);
  ScanTask *t = g_BfsScanQueue->head;
  if (t) {
    g_BfsScanQueue->head = t->ItemEntry.Next ? (ScanTask *)t->ItemEntry.Next : NULL;
    if (!g_BfsScanQueue->head) g_BfsScanQueue->tail = NULL;
    InterlockedDecrement(&g_BfsScanQueue->count);
  }
  LeaveCriticalSection(&g_BfsScanQueue->cs);
  return t;
}
/* Ctrl+C / TERMINATE 路径：非阻塞 Pop，与 IOCP 上 ov=NULL 的 BFS 唤醒包一一对应 */
static ScanTask *TryPopBfsScanTask(void) {
  if (!g_BfsScanQueue) return NULL;
  if (WaitForSingleObject(g_BfsScanQueue->hSem, 0) != WAIT_OBJECT_0)
    return NULL;
  EnterCriticalSection(&g_BfsScanQueue->cs);
  ScanTask *t = g_BfsScanQueue->head;
  if (t) {
    g_BfsScanQueue->head = t->ItemEntry.Next ? (ScanTask *)t->ItemEntry.Next : NULL;
    if (!g_BfsScanQueue->head) g_BfsScanQueue->tail = NULL;
    InterlockedDecrement(&g_BfsScanQueue->count);
  }
  LeaveCriticalSection(&g_BfsScanQueue->cs);
  return t;
}

/* -O 物理顺序：按 FileId 排序减少 HDD 寻道，单目录超 5 万项不排序
 * Phase 20：nameLen 透传，排序后循环零 wcslen */
#define ORDER_BY_PHYSICAL_MAX_ENTRIES 50000
typedef struct {
  LONGLONG FileId;
  DWORD FileAttributes;
  ULARGE_INTEGER EndOfFile;
  FILETIME CreationTime;
  FILETIME LastAccessTime;
  FILETIME LastWriteTime;
  DWORD nameLen;           /* 字符数不含 \\0 */
  wchar_t FileName[MAX_PATH];
} DirEntryForSort;

/* 瘦身：仅指针+元数据，1000万目录 ~480MB；原 ShortSrc/ShortDst 会导致 11GB OOM
 * Phase 20/3 长度透传：SrcLen/DstLen 字符数不含 \\0，uint32_t 足矣 */
typedef struct {
  SLIST_ENTRY ItemEntry;
  wchar_t *SrcPath;
  uint32_t SrcLen;
  wchar_t *DstPath;
  uint32_t DstLen;
  FILETIME CreationTime;
  FILETIME LastAccessTime;
  FILETIME LastWriteTime;
  DWORD FileAttributes;
  uint8_t pathFlags;  /* D4：同 CopyTask.pathFlags，free 时无需 O(n) IsArenaPtr 扫描 */
} DirMetaTask;

typedef struct {
  SLIST_ENTRY ItemEntry;
  wchar_t *DstPath;
  wchar_t ShortDst[MAX_PATH]; /* 99.9% 路径内联，零 _wcsdup */
  wchar_t *SrcPath;   /* 闭环重试用：校验失败时需 SrcPath 重新拷贝，NULL=不重试 */
  wchar_t ShortSrc[MAX_PATH];
  BYTE ExpectedHash[16];
  LONGLONG FileSize; /* >0 且 >= SAMPLE_THRESHOLD 时 VerifyThread 用抽样校验 */
  DWORD FileAttributes; /* 重试时用于稀疏文件检测 */
} VerifyTask;

struct _VerifyParam {
  BYTE *HashBuffer;
  XXH3_state_t *Xxh3State;
  /* Phase 20 P2: IoRing 离散读抽样，懒分配 */
  void *hIoRingVerify;
  BYTE *IoRingSampleBuf;
  size_t IoRingSampleBufSize;
};

typedef struct {
  SLIST_ENTRY ItemEntry;
  BYTE *Buffer;
} BigBufferObj;

/* Ring Buffer：大文件高队列深度 I/O (QD 4~8)，榨干 NVMe/网络 */
#define BIGFILE_QUEUE_DEPTH 8
#define BIGFILE_QUEUE_DEPTH_MAX 64
int g_BigFileQD = 8; /* 运行时设定：HDD=2, SSD=8, 网络=16 */
#define ADAPTIVE_QD_SAMPLES 64
#define ADAPTIVE_QD_MIN_SAMPLES 10
volatile LONG g_AdaptiveQDBias = 0;  /* PID 输出：目标 5ms 延迟，范围 [-16,16] */
#define PID_LATENCY_SETPOINT_MS 5
#define PID_KP 0.25
#define PID_KI 0.02
#define PID_MAX_INTEGRAL 50  /* 抗积分饱和：NVMe 热缩频等长时间高延迟后防止 Windup */
#define PID_KD 0.4
static CRITICAL_SECTION g_PidCs;
static double g_PidIntegral = 0;
static LONGLONG g_PidLastError = 0;
static DWORD g_PidLastTick = 0;
#define KEY_BIGFILE_READ  ((ULONG_PTR)0x100)
#define KEY_BIGFILE_WRITE ((ULONG_PTR)0x200)
#define GQCSEx_BATCH_SIZE 64    /* P1 批处理收割：一次系统调用取多完成包，降内核切换 */
/* CopierThread：短超时心跳（非 INFINITE），空窗期可刷 IoRing 尾批，避免末尾“卡最后 0.x%” */
#define COPIER_GQCS_HEARTBEAT_MS 50

typedef enum { BUF_FREE, BUF_READING, BUF_WRITING, BUF_FREE_WAIT_HASH } BufState;

typedef struct {
  OVERLAPPED ov;
  BigBufferObj *bufObj;
  int state;
  LONGLONG offset;
  DWORD length;
} IoBlock;

/* 异步清理任务 */
typedef struct {
  SLIST_ENTRY ItemEntry;
  wchar_t *Path;
} CleanupTask;

PSLIST_HEADER g_CopyTaskPool = NULL;
PSLIST_HEADER g_DeadLetterQueue = NULL; /* 重试耗尽的任务，主流水线结束后慢速挣扎 */
/* 迭代二：单块静态池，零 malloc/Slab，彻底消除 CRT 堆锁 */
#define COPY_TASK_ALIGNED_SIZE ((sizeof(CopyTask) + 15) & ~(size_t)15)
/* CopyTask 静态池槽数硬顶：InitMemoryPools 用 min(Q+numCopiers*2, COPY_POOL_STATIC_MAX)；改一处即可调预分配/常驻 WS */
#define COPY_POOL_STATIC_MAX 8192
static CopyTask *g_CopyTaskStaticBlock = NULL;  /* 单块基址，释放时 _aligned_free */
static volatile size_t g_CopyTaskStaticTotalSize = 0;  /* 记录静态池总字节数，弹性兜底边界判定；volatile 防优化/跨线程可见 */
volatile BOOL g_NoDLQ = FALSE; /* TRUE 时禁止向 DLQ 入队，防止并发重试阶段无限循环 */

/* Round4 P2 架构2：DLQ 常驻后台渐进式重试线程
 * 背景：百TB/亿文件任务持续数天，早期瞬时错误在 DLQ 中驻留数天造成内存背压。
 * 解法：低优先级常驻线程，每 DLQ_DRAIN_INTERVAL_MS 检查一次；
 *       仅当主队列水位低于 50% 时才将 DLQ 中的旧任务反刍回 IOCP 主队列，
 *       避免与主流水线抢占调度资源。线程在 g_NoDLQ=TRUE 前（并发重试前）优雅退出。*/
#define DLQ_DRAIN_INTERVAL_MS  300000   /* 5 分钟检查一次 */
#define DLQ_DRAIN_BATCH_MAX    1000     /* 单次最多反刍 1000 个任务，避免瞬间淹没主队列 */
static volatile HANDLE g_hCopyIocp = NULL;        /* 主 IOCP 句柄（线程安全写入一次）*/
static volatile BOOL   g_DLQBackgroundRun = FALSE; /* FALSE 时后台线程退出 */
static HANDLE g_hDLQBackgroundThread = NULL;
static HANDLE g_hDLQQuitEvent = NULL;              /* Round6 P1：事件唤醒，主线程 SetEvent 后 0ms 退出 */

static unsigned __stdcall DLQBackgroundThread(void *p) {
  (void)p;
  ULONGLONG lastDrainTick = GetTickCount64();
  while (READ_VOLATILE_32(&g_DLQBackgroundRun)) {
    /* Round6 P1：WaitForSingleObject 替代 Sleep，主线程 SetEvent 后瞬间唤醒，实现秒退 */
    if (g_hDLQQuitEvent)
      WaitForSingleObject(g_hDLQQuitEvent, 1000);
    else
      Sleep(1000);  /* CreateEvent 失败时回退 */
    if (!READ_VOLATILE_32(&g_DLQBackgroundRun)) break;
    if (IsCanceling()) break;
    /* 时间门：距上次反刍未满 DLQ_DRAIN_INTERVAL_MS，继续等待 */
    ULONGLONG now = GetTickCount64();
    if (now - lastDrainTick < DLQ_DRAIN_INTERVAL_MS) continue;
    lastDrainTick = now;
    /* DLQ 为空或全局 IOCP 未就绪，跳过 */
    if (!g_DeadLetterQueue || !*(volatile HANDLE *)&g_hCopyIocp) continue;
    LONG dlqN = (LONG)QueryDepthSList(g_DeadLetterQueue);
    if (dlqN <= 0) continue;
    /* 水位门：主队列已超 50% 容量，让主流水线优先 */
    LONG pending = READ_VOLATILE_32(&g_PendingCopyTasks);
    LONG maxQ    = READ_VOLATILE_32(&g_MaxQueueDepth);
    if (pending >= maxQ / 2) continue;
    /* 渐进反刍：每次最多取 DLQ_DRAIN_BATCH_MAX 个任务，且不超过可用队列空间的一半 */
    LONG canDrain = (maxQ / 2 - pending);
    if (canDrain > DLQ_DRAIN_BATCH_MAX) canDrain = DLQ_DRAIN_BATCH_MAX;
    LONG drained = 0;
    HANDLE iocp = (HANDLE)g_hCopyIocp;
    while (drained < canDrain && READ_VOLATILE_32(&g_DLQBackgroundRun)) {
      if (READ_VOLATILE_32(&g_PendingCopyTasks) >= maxQ / 2) break;
      PSLIST_ENTRY e = InterlockedPopEntrySList(g_DeadLetterQueue);
      if (!e) break;
      InterlockedIncrement(&g_PendingActive);
      InterlockedIncrement(&g_PendingCopyTasks);
      PostQueuedCompletionStatus(iocp, 0, KEY_COPY_TASK, (LPOVERLAPPED)e);
      drained++;
    }
    if (drained > 0)
      LogMessage(LOG_INFO, L"[DLQ-BG] Refluxed %ld tasks back to main queue (DLQ remaining: %ld).\n",
                 (long)drained, (long)QueryDepthSList(g_DeadLetterQueue));
  }
  return 0;
}
PSLIST_HEADER g_ScanTaskPool = NULL;
/* 迭代二：ScanTask 单块静态池，零池空时 _aligned_malloc */
#define SCAN_TASK_ALIGNED_SIZE ((sizeof(ScanTask) + 15) & ~(size_t)15)
static ScanTask *g_ScanTaskStaticBlock = NULL;
static volatile size_t g_ScanTaskStaticTotalSize = 0; /* 记录静态池总字节数，弹性兜底边界判定；volatile 防优化/跨线程可见 */
PSLIST_HEADER g_DirMetaStack = NULL;
PSLIST_HEADER g_DirMetaPool = NULL;
PSLIST_HEADER g_VerifyTaskPool = NULL;
PSLIST_HEADER g_BigBufferPool = NULL;

#define OOM_RETRY_MAX 30000  /* 10ms * 30000 = 5min，避免 OOM 死循环 */
static DirMetaTask *AllocDirMetaTask(void) {
  DirMetaTask *dmt = NULL;
  int retries = 0;
  while (!dmt) {
    if (IsCanceling() || retries >= OOM_RETRY_MAX)
      return NULL; /* 用户取消或超时，避免死锁 */
    if (g_DirMetaPool) {
      PSLIST_ENTRY e = InterlockedPopEntrySList(g_DirMetaPool);
      dmt = e ? (DirMetaTask *)e : NULL;
    }
    if (!dmt)
      dmt = (DirMetaTask *)_aligned_malloc(sizeof(DirMetaTask), 16);
    if (!dmt) {
      Sleep(10);
      retries++;
    }
  }
  return dmt;
}
static void FreeDirMetaTask(DirMetaTask *dmt) {
  /* D4 修复：直接读 pathFlags，无需 O(n) IsArenaPtr 扫描 */
  if (dmt->SrcPath && !(dmt->pathFlags & (TASK_PATH_FLAG_SRC_ARENA | TASK_PATH_FLAG_SRC_SHORT)))
    free(dmt->SrcPath);
  dmt->SrcPath = NULL;
  if (dmt->DstPath && !(dmt->pathFlags & (TASK_PATH_FLAG_DST_ARENA | TASK_PATH_FLAG_DST_SHORT)))
    free(dmt->DstPath);
  dmt->DstPath = NULL;
  if (g_DirMetaPool)
    InterlockedPushEntrySList(g_DirMetaPool, &dmt->ItemEntry);
  else
    PB_ALIGNED_FREE(dmt);
}
PSLIST_HEADER g_CleanupPool = NULL;
PSLIST_HEADER g_CleanupQueue = NULL;
HANDLE g_hCleanupEvent = NULL;
HANDLE g_hCleanupThread = NULL;
volatile BOOL g_CleanupThreadRunning = TRUE;

#define LOCAL_POOL_SIZE 128
#define TLC_BATCH_SIZE 64
#define IORING_BATCH_SIZE_DEFAULT 256 /* 高延迟网络 BDP 友好，IoRingProbe 会截断 */
#define IORING_MAX_FILE_SIZE (1024 * 1024) /* 接管 90% 办公/多媒体文件，单文件上限 */
#define THREAD_IORING_BUFFER_SIZE (8 * 1024 * 1024) /* 每线程 8MB 紧凑缓冲，64 线程=512MB，避免 16GB OOM */

int g_IoRingBatchSize = IORING_BATCH_SIZE_DEFAULT; /* -j 可调，IoRingProbe 会按 caps 截断 */
static UINT32 g_IoRingQueueSize = 256; /* CreateIoRing 队列深度，IoRingProbe 设置 */

/* x64 ABI：CreateIoRing 第二参数为 IORING_CREATE_FLAGS 按值传递，非指针 */
typedef struct { UINT32 Required; UINT32 Advisory; } IORING_CREATE_FLAGS;
typedef HRESULT(WINAPI *CreateIoRingFn)(UINT32, IORING_CREATE_FLAGS, UINT32, UINT32, void **);
typedef HRESULT(WINAPI *BuildIoRingReadFileFn)(void *, void *, void *, UINT32,
                                               UINT64, UINT_PTR, UINT32);
typedef HRESULT(WINAPI *BuildIoRingWriteFileFn)(void *, void *, void *, UINT32,
                                                 UINT64, UINT32, UINT_PTR, UINT32);
typedef HRESULT(WINAPI *SubmitIoRingFn)(void *, UINT32, UINT32, UINT32 *);
typedef HRESULT(WINAPI *PopIoRingCompletionFn)(void *, void *);
typedef HRESULT(WINAPI *CloseIoRingFn)(void *);
/* RegisterBuffers：预注册缓冲，内核一次校验，降低每批 I/O 开销 */
typedef struct { void *Address; UINT32 Length; } IORING_BUFFER_INFO_LOCAL;
typedef HRESULT(WINAPI *BuildIoRingRegisterBuffersFn)(void *, UINT32,
                                                      const IORING_BUFFER_INFO_LOCAL *, UINT_PTR);
/* Phase 18：RegisterFileHandles 绕过内核句柄表，ObReferenceObjectByHandle 一次解析缓存 */
typedef HRESULT(WINAPI *BuildIoRingRegisterFileHandlesFn)(void *, UINT32, HANDLE const *, UINT_PTR);
#define IORING_REF_RAW 0
#define IORING_REF_REGISTERED 1

static CreateIoRingFn g_pCreateIoRing = NULL;
static BuildIoRingReadFileFn g_pBuildIoRingReadFile = NULL;
static BuildIoRingWriteFileFn g_pBuildIoRingWriteFile = NULL;
static SubmitIoRingFn g_pSubmitIoRing = NULL;
static PopIoRingCompletionFn g_pPopIoRingCompletion = NULL;
static CloseIoRingFn g_pCloseIoRing = NULL;
static BuildIoRingRegisterBuffersFn g_pBuildIoRingRegisterBuffers = NULL;
static BuildIoRingRegisterFileHandlesFn g_pBuildIoRingRegisterFileHandles = NULL;

/* CopyFile2 (Win8+)：ODX 加速、ReFS 块克隆、Skip ADS 等；动态加载兼容旧系统 */
#ifndef COPY_FILE_SKIP_ALTERNATE_STREAMS
#define COPY_FILE_SKIP_ALTERNATE_STREAMS 0x00008000
#endif
#ifndef COPY_FILE_REQUEST_COMPRESSED_TRAFFIC
#define COPY_FILE_REQUEST_COMPRESSED_TRAFFIC 0x10000000  /* Win10 1903+ SMB 压缩 */
#endif
typedef struct {
  DWORD dwSize;
  DWORD dwCopyFlags;
  BOOL *pfCancel;
  void *pProgressRoutine;
  void *pvCallbackContext;
} COPYFILE2_EXTENDED_PARAMETERS_LOCAL;
typedef HRESULT(WINAPI *CopyFile2Fn)(LPCWSTR, LPCWSTR, COPYFILE2_EXTENDED_PARAMETERS_LOCAL *);
static CopyFile2Fn g_pCopyFile2 = NULL;
/* Phase 18 MMCSS：主线程提前加载，CopierThread 直接使用 */
static HANDLE (WINAPI *g_pAvSetMmThreadCharacteristics)(LPCWSTR, LPDWORD) = NULL;
static BOOL (WINAPI *g_pAvSetMmThreadPriority)(HANDLE, int) = NULL;
static BOOL (WINAPI *g_pAvRevertMmThreadCharacteristics)(HANDLE) = NULL;
static BOOL g_CopyFile2Available = FALSE;

/* CopyFile2 封装：优先 CopyFile2（ODX/块克隆），不可用时回退 CopyFileW；skipADS=TRUE 时 FastMode 跳过 ADS */
static BOOL CopyFile2Ex(LPCWSTR src, LPCWSTR dst, BOOL skipADS) {
  if (g_pCopyFile2 && g_CopyFile2Available) {
    COPYFILE2_EXTENDED_PARAMETERS_LOCAL params = {0};
    params.dwSize = sizeof(params);
    params.dwCopyFlags = skipADS ? COPY_FILE_SKIP_ALTERNATE_STREAMS : 0;
    /* SMB 网络路径请求压缩传输（NetApp/厂商建议），不支持时自动忽略 */
    if (IsUncPath(src) || IsUncPath(dst))
      params.dwCopyFlags |= COPY_FILE_REQUEST_COMPRESSED_TRAFFIC;
    params.pfCancel = NULL;
    params.pProgressRoutine = NULL;
    params.pvCallbackContext = NULL;
    HRESULT hr = g_pCopyFile2(src, dst, &params);
    if (SUCCEEDED(hr))
      return TRUE;
    SetLastError(HRESULT_CODE(hr));
  }
  return CopyFileW(src, dst, FALSE);
}

static void CopyFile2Probe(void) {
  if (g_pCopyFile2)
    return;
  HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
  if (!hKernel)
    return;
  g_pCopyFile2 = (CopyFile2Fn)GetProcAddress(hKernel, "CopyFile2");
  g_CopyFile2Available = (g_pCopyFile2 != NULL);
}

/* Phase 18：主线程提前加载 MMCSS，避免 CopierThread 竞态 */
static void InitMmcss(void) {
  HMODULE hAvrt = LoadLibraryW(L"avrt.dll");
  if (hAvrt) {
    g_pAvSetMmThreadCharacteristics = (void *)GetProcAddress(hAvrt, "AvSetMmThreadCharacteristicsW");
    g_pAvSetMmThreadPriority = (void *)GetProcAddress(hAvrt, "AvSetMmThreadPriority");
    g_pAvRevertMmThreadCharacteristics = (void *)GetProcAddress(hAvrt, "AvRevertMmThreadCharacteristics");
  }
}

/* Cache Line 隔离：64B 对齐消除 False Sharing，多核下避免缓存行乒乓 */
#define NTAPI_DIR_LRU_SLOTS 8
struct _CopierParam {
  HANDLE hIocp;
  int ThreadIndex;
  LONG LocalCopied;
  LONG64 LocalBytes;
  LONG LocalSmallFiles;
  LONG LocalMediumFiles;
  LONG LocalLargeFiles;
  int TasksSinceRatioUpdate;
  DWORD LastFlushTick;
  CopyTask *LocalTaskPool[LOCAL_POOL_SIZE];
  int LocalCount;
  CopyTask **IoRingBatch;   /* 动态分配，大小 g_IoRingBatchSize */
  int IoRingBatchCount;
  DWORD IoRingBatchTotalBytes; /* 当前批次已消耗字节数，紧凑打包水位 */
  BOOL *IoRingBatchOk;      /* 动态分配，大小 g_IoRingBatchSize */
  BYTE *IoRingBuffer;       /* 线程私有 8MB 紧凑缓冲，零 OOM */
  /* 以下 5 个数组从栈移至堆，消除 CopySmallFilesBatchIoRing 中 ~32KB 栈压力 */
  HANDLE *IoRingHandleSrc; /* 动态分配，大小 g_IoRingBatchSize */
  HANDLE *IoRingHandleDst;
  BYTE **IoRingBufs;
  BOOL *IoRingReadOk;
  BOOL *IoRingWriteOk;
  HANDLE *IoRingRegHandles; /* N6：预分配 2×BatchSize，消除 CopySmallFilesBatchIoRing 每批 malloc/free */
  void *hIoRing;      /* 线程专属持久化 IoRing，零 Create/Close 风暴 */
  BOOL IoRingBuffersRegistered; /* RegisterBuffers 成功，使用 Index 引用降低内核校验开销 */
  XXH3_state_t *Xxh3State; /* 线程私有 XXH3 状态，零 malloc 风暴 */
  BYTE *HashBuffer;   /* 线程私有 1MB 哈希缓冲，CheckIncrementalSync/CalculateFileHash 零分配 */
  ThreadArena tlab;   /* Phase 20 TLAB：每线程 2MB 线性分配，零锁 */
  BYTE ScanBuffer[SCAN_BUFFER_SIZE];      /* 目录扫描缓冲，零 malloc */
  wchar_t ScanWorkSrc[MAX_PATH_EXT];     /* 扫描路径工作区 */
  wchar_t ScanWorkDst[MAX_PATH_EXT];
  wchar_t ScanTempNorm[MAX_PATH_EXT];
  /* 动态 QD 滑动窗口：GetQueuedCompletionStatus 等待耗时，用于 HDD/SSD 自适应 */
  LONGLONG IoLatencySamples[ADAPTIVE_QD_SAMPLES];
  int IoLatencyCount;
  LONGLONG IoLatencySum;
  HANDLE hMmcssTask;  /* Phase 18：MMCSS Pro-Audio 句柄，线程退出时 AvRevert */
  LONGLONG LocalTokens;  /* Phase 19：发牌人模式，TokenBucketThread 单向写入，本线程只读，零 Interlocked */
  /* advice1 P1: 8 槽线程本地 LRU 目录句柄（交错子目录命中率） */
  struct { wchar_t path[MAX_PATH]; HANDLE hDir; DWORD lastUsed; } NtApiDstLru[NTAPI_DIR_LRU_SLOTS];
  struct { wchar_t path[MAX_PATH]; HANDLE hDir; DWORD lastUsed; } NtApiSrcLru[NTAPI_DIR_LRU_SLOTS];
  DWORD NtApiLruClock;
  /* advice1 P1: 线程持久化大文件子 IOCP，消灭每文件 CreateIoCompletionPort */
  HANDLE hFileIocp;
  /* advice1 P0: 拷贝路径已在 Close 前写 FileBasicInfo，跳过再开 SetFileTime */
  BOOL TimestampsAlreadySet;
  /* 同父目录跳过 EnsureParentDirExists + XXH3 */
  wchar_t LastEnsuredParent[MAX_PATH];
  size_t LastEnsuredParentLen;
  /* ACL SD 缓存：同源父目录假定继承同一 DACL，跳过重复 GetFileSecurity */
  PSECURITY_DESCRIPTOR SdCacheBlob;
  DWORD SdCacheLen;
  UINT64 SdCacheHash;
  BOOL SdCacheValid;
  wchar_t SdCacheSrcParent[MAX_PATH];
  size_t SdCacheSrcParentLen;
  /* IoRing 批内源哈希（-J -D）：每槽 8 字节 XXH3 */
  BYTE *IoRingSrcHashes; /* g_IoRingBatchSize * 8 */
} CACHE_ALIGN;
typedef struct _CopierParam CopierParam;

/* Phase 19 发牌人模式（已修复 BUG-C1）：
 * TokenBucketThread 发牌（add）、工作线程消费（subtract）均通过 InterlockedAdd64 原子操作，
 * 消除裸 LONGLONG read-modify-write 的数据竞争。 */
static void AcquireBandwidthTokens(LONGLONG n) {
  if (g_SpeedLimitBps <= 0 || n <= 0)
    return;
  CopierParam *param = NULL;
  if (g_TlsCopierParamSlot != TLS_OUT_OF_INDEXES)
    param = (CopierParam *)TlsGetValue(g_TlsCopierParamSlot);
  if (param && g_CopierParams) {
    int backoff = 0;  /* P4：WaitOnAddress 不可用时梯度退避，避免 64 线程全开时 CPU 100% 空转 */
    while (LIKELY(!IsCanceling())) {
      LONGLONG cur = READ_VOLATILE_64(&param->LocalTokens);
      if (cur >= n) {
        /* 原子 CAS 消费 n 个 token */
        if (InterlockedCompareExchange64((volatile LONGLONG *)&param->LocalTokens,
                                         cur - n, cur) == cur)
          return;
        /* CAS 失败：Banker 或 Refund 同时修改，立即重试不睡眠 */
        continue;
      }
      /* D7 优化：token 不足时用 WaitOnAddress 休眠代替 SwitchToThread 忙等。
       * TokenBucketThread 每次发牌后会调用 WakeByAddressAll 唤醒所有等待者。
       * P4：Win7 下梯度降级 _mm_pause -> SwitchToThread -> Sleep(0) -> Sleep(1) */
      LONGLONG zero = 0;
      if (g_pfnWaitOnAddress)
        g_pfnWaitOnAddress((volatile void *)&param->LocalTokens, &zero, 8, 2);
      else {
        if (backoff < 4) {
          for (int i = 0; i < (1 << backoff); i++) _mm_pause();
          backoff++;
        } else if (backoff < 8) {
          SwitchToThread();
          backoff++;
        } else if (backoff < 12) {
          Sleep(0);
          backoff++;
        } else {
          Sleep(1);
          backoff = 0;
        }
      }
    }
    return;
  }
  /* TlsAlloc 已在主线程完成，此处直接使用 */
  LONGLONG *pLocal = (g_TlsTokenSlot != TLS_OUT_OF_INDEXES) ?
      (LONGLONG *)TlsGetValue(g_TlsTokenSlot) : NULL;
  if (!pLocal) {
    pLocal = (LONGLONG *)malloc(sizeof(LONGLONG));
    if (pLocal) { *pLocal = 0; TlsSetValue(g_TlsTokenSlot, pLocal); }
  }
  if (pLocal && *pLocal >= n) {
    *pLocal -= n;
    return;
  }
  LONGLONG toAcquire = (n > TOKEN_CHUNK_SIZE) ? n : TOKEN_CHUNK_SIZE;
  int spin = 0;  /* P4：梯度退避，降低无 CopierParam 时的 CPU 空转 */
  while (LIKELY(!IsCanceling())) {
    LONGLONG cur = READ_VOLATILE_64(&g_AvailableTokens);
    if (cur < 0) cur = 0;
    if (cur >= toAcquire) {
      if (InterlockedCompareExchange64((volatile LONGLONG *)&g_AvailableTokens,
                                       cur - toAcquire, cur) == cur) {
        if (pLocal) *pLocal = toAcquire - n;
        break;
      }
    }
    if (spin < 4) { _mm_pause(); spin++; }
    else if (spin < 8) { SwitchToThread(); spin++; }
    else if (spin < 12) { Sleep(0); spin++; }
    else { Sleep(1); spin = 0; }
  }
}

/* OPT-03: 退还令牌——写入失败时将已扣令牌归还。Phase 19 发牌人模式：优先归还到 param->LocalTokens */
static void RefundBandwidthTokens(LONGLONG n) {
  if (g_SpeedLimitBps <= 0 || n <= 0)
    return;
  CopierParam *param = (g_TlsCopierParamSlot != TLS_OUT_OF_INDEXES) ?
      (CopierParam *)TlsGetValue(g_TlsCopierParamSlot) : NULL;
  if (param && g_CopierParams) {
    LONGLONG maxCap = g_SpeedLimitBps * 2;
    if (maxCap < (LONGLONG)g_BigBufferSize) maxCap = (LONGLONG)g_BigBufferSize;
    if (maxCap < 8 * 1024 * 1024) maxCap = 8 * 1024 * 1024;
    /* 原子归还：CAS 保证不超过 maxCap */
    for (;;) {
      LONGLONG cur = READ_VOLATILE_64(&param->LocalTokens);
      LONGLONG newVal = cur + n;
      if (newVal > maxCap) newVal = maxCap;
      if (InterlockedCompareExchange64((volatile LONGLONG *)&param->LocalTokens,
                                       newVal, cur) == cur)
        break;
    }
    return;
  }
  LONGLONG maxCap = g_SpeedLimitBps * 2;
  if (maxCap < (LONGLONG)g_BigBufferSize) maxCap = (LONGLONG)g_BigBufferSize;
  if (maxCap < 8 * 1024 * 1024) maxCap = 8 * 1024 * 1024;
  for (;;) {
    LONGLONG cur = READ_VOLATILE_64(&g_AvailableTokens);
    LONGLONG newVal = cur + n;
    if (newVal > maxCap) newVal = maxCap;
    if (InterlockedCompareExchange64((volatile LONGLONG *)&g_AvailableTokens, newVal, cur) == cur)
      break;
  }
}

CopyTask *AllocCopyTask(void);
void CopyFileSecurityAndAttributes(const wchar_t *src, const wchar_t *dst,
                                   const CopyTask *task);
/* timestampsAlreadySet：IoRing 已在 Close 前 SetFileTime，跳过再开 dst；param 供 SD 缓存 */
static void CopyFileSecurityAndAttributesEx(const wchar_t *src, const wchar_t *dst,
    const CopyTask *task, BOOL timestampsAlreadySet, CopierParam *param);
static void ApplyFileBasicInfoBeforeClose(HANDLE hDst, const CopyTask *task, CopierParam *param);

static BOOL CalculateFileHash(const wchar_t *path, BYTE *out, CopierParam *param);
static void PostVerifyTask(const wchar_t *dst, const BYTE *expectedHash);
static void PostVerifyTaskEx(const wchar_t *dst, const BYTE *expectedHash,
    LONGLONG fileSize); /* 前置声明：PostVerifyTask 调用它但定义在后 */
static void PostVerifyTaskExForRetry(const wchar_t *dst, const BYTE *expectedHash,
    LONGLONG fileSize, const wchar_t *src, DWORD fileAttributes);

/* ========== VFS 虚拟文件系统层（为 FTP/SFTP 预留） ==========
 * 统一 I/O 接口，本地盘后端封装 CreateFile/ReadFile/WriteFile，
 * 后续可接入 libssh2/libcurl 实现 SFTP 后端。 */
typedef void *IO_HANDLE;
#define IO_HANDLE_INVALID NULL

typedef enum { IO_MODE_READ, IO_MODE_WRITE_CREATE } IO_MODE;

/* 异步驱动器：供 Ring Buffer 通用泵使用，SFTP 后端实现后与本地 IOCP 共用同一套调度逻辑 */
typedef BOOL (*SubmitReadFn)(IO_HANDLE h, void *buf, DWORD size, LONGLONG offset,
                             void *userData);
typedef BOOL (*SubmitWriteFn)(IO_HANDLE h, const void *buf, DWORD size,
                              LONGLONG offset, void *userData);
typedef BOOL (*PollCompletionFn)(IO_HANDLE h, DWORD *bytesTransferred,
                                 void **userData, DWORD timeout);

/* V3.0 Roadmap: 补齐 OpenDir/ReadDir/CloseDir 可通吃 sftp:// 等协议目录扫描 */
typedef struct _IO_BACKEND {
  const char *name;
  IO_HANDLE (*Open)(const wchar_t *path, IO_MODE mode, BOOL useOverlapped);
  BOOL (*Read)(IO_HANDLE h, void *buf, DWORD size, DWORD *bytesRead);
  BOOL (*Write)(IO_HANDLE h, const void *buf, DWORD size, DWORD *bytesWritten);
  void (*Close)(IO_HANDLE h);
  BOOL (*IsAsyncSupported)(void);
  HANDLE (*GetNativeHandle)(IO_HANDLE h);
  SubmitReadFn SubmitRead;   /* 可选，NULL 表示走 GetNativeHandle + IOCP */
  SubmitWriteFn SubmitWrite;
  PollCompletionFn PollCompletion;
} IO_BACKEND;

const IO_BACKEND *VFS_GetBackend(const wchar_t *path);

/* 线程本地 Magazine：从全局 g_CopyTaskPool SList 批量拉取；跨线程释放仍 Push 回全局池，真池是全局 SList */
static CopyTask *TLC_AllocCopyTask(CopierParam *param) {
  CopyTask *t = NULL;
  if (param->LocalCount > 0) {
    t = param->LocalTaskPool[--param->LocalCount];
  } else {
    for (int i = 0; i < TLC_BATCH_SIZE; i++) {
      PSLIST_ENTRY e = InterlockedPopEntrySList(g_CopyTaskPool);
      if (e)
        param->LocalTaskPool[param->LocalCount++] = (CopyTask *)e;
      else
        break;
    }
    if (param->LocalCount > 0)
      t = param->LocalTaskPool[--param->LocalCount];
  }
  if (!t)
    return AllocCopyTask();
  /* 【关键修复】：本地池重用的任务必须清零，绝对不能复用脏状态！ */
  memset((char *)t + sizeof(SLIST_ENTRY), 0, sizeof(CopyTask) - sizeof(SLIST_ENTRY));
  return t;
}

static void TLC_FreeCopyTask(CopierParam *param, CopyTask *t) {
  if (!t) return;
  /* BUG-C9 修复：直接读 pathFlags，无需 O(n) IsArenaPtr 扫描 */
  if (t->SrcPath && !(t->pathFlags & (TASK_PATH_FLAG_SRC_ARENA | TASK_PATH_FLAG_SRC_SHORT)))
    free(t->SrcPath);
  if (t->DstPath && !(t->pathFlags & (TASK_PATH_FLAG_DST_ARENA | TASK_PATH_FLAG_DST_SHORT)))
    free(t->DstPath);
  t->SrcPath = t->DstPath = NULL;
  if (param->LocalCount < LOCAL_POOL_SIZE) {
    param->LocalTaskPool[param->LocalCount++] = t;
  } else {
    int half = LOCAL_POOL_SIZE / 2;
    for (int i = 0; i < half; i++) {
      CopyTask *p = param->LocalTaskPool[--param->LocalCount];
      /* 弹性兜底：drain 时精准判定，静态池回收 vs 弹性溢出 _aligned_free */
      if (g_CopyTaskStaticBlock && g_CopyTaskStaticTotalSize > 0 &&
          (char *)p >= (char *)g_CopyTaskStaticBlock &&
          (char *)p < (char *)g_CopyTaskStaticBlock + g_CopyTaskStaticTotalSize) {
        InterlockedPushEntrySList(g_CopyTaskPool, &p->ItemEntry);
      } else {
        _aligned_free(p);
      }
    }
    param->LocalTaskPool[param->LocalCount++] = t;
  }
}

/* 迭代二+弹性兜底：前 N 万任务无锁极速，超水位线降级 _aligned_malloc，回收时精准归还 */
CopyTask *AllocCopyTask(void) {
  PSLIST_ENTRY e = InterlockedPopEntrySList(g_CopyTaskPool);
  CopyTask *t = (CopyTask *)e;
  if (!t) {
    int retries = 0;
    while (!t && retries < OOM_RETRY_MAX) {
      if (IsCanceling()) break;
      t = (CopyTask *)_aligned_malloc(COPY_TASK_ALIGNED_SIZE, 16);
      if (!t) { Sleep(10); retries++; }
    }
  }
  if (!t) return NULL;
  memset((char *)t + sizeof(SLIST_ENTRY), 0,
         sizeof(CopyTask) - sizeof(SLIST_ENTRY));
  return t;
}

void FreeCopyTask(CopyTask *t) {
  if (!t) return;
  /* BUG-C9 修复：直接读 pathFlags，无需 O(n) IsArenaPtr 扫描 */
  if (t->SrcPath && !(t->pathFlags & (TASK_PATH_FLAG_SRC_ARENA | TASK_PATH_FLAG_SRC_SHORT)))
    free(t->SrcPath);
  if (t->DstPath && !(t->pathFlags & (TASK_PATH_FLAG_DST_ARENA | TASK_PATH_FLAG_DST_SHORT)))
    free(t->DstPath);
  t->SrcPath = t->DstPath = NULL;
  /* 弹性兜底：边界判定，静态池极速回收 vs 弹性溢出 _aligned_free */
  if (g_CopyTaskStaticBlock && g_CopyTaskStaticTotalSize > 0 &&
      (char *)t >= (char *)g_CopyTaskStaticBlock &&
      (char *)t < (char *)g_CopyTaskStaticBlock + g_CopyTaskStaticTotalSize) {
    InterlockedPushEntrySList(g_CopyTaskPool, &t->ItemEntry);
  } else {
    _aligned_free(t);
  }
}

/* 扫描/列表/MFT 等生产者：主队列满时阻塞等待 Copier 消费，不丢任务、不进 DLQ。
 * PostCopyTask 仅负责计数 + PostQueuedCompletionStatus，不做背压与 DLQ。 */
/* advice1 P2: 背压 WaitOnAddress + 迟滞唤醒（见 NotePendingCopyDec） */
static void NotePendingCopyDec(LONG after) {
  LONG maxQ = READ_VOLATILE_32(&g_MaxQueueDepth);
  LONG wakeAt = maxQ - 512;
  if (wakeAt < 0) wakeAt = 0;
  if (after <= wakeAt && g_pfnWakeByAddressAll)
    g_pfnWakeByAddressAll((void *)&g_PendingCopyTasks);
}
static void WaitCopyQueueCapacity(void) {
  for (;;) {
    LONG q = READ_VOLATILE_32(&g_PendingCopyTasks);
    LONG maxQ = READ_VOLATILE_32(&g_MaxQueueDepth);
    if (q < maxQ)
      return;
    if (IsCanceling())
      return;
    if (g_pfnWaitOnAddress) {
      LONG observed = q;
      g_pfnWaitOnAddress((volatile void *)&g_PendingCopyTasks, &observed, sizeof(LONG), 2);
    } else
      Sleep(1);
  }
}

static void PostCopyTask(HANDLE hIocp, CopyTask *ct) {
  InterlockedIncrement(&g_PendingActive);
  InterlockedIncrement(&g_PendingCopyTasks);
  PostQueuedCompletionStatus(hIocp, 0, KEY_COPY_TASK, (LPOVERLAPPED)ct);
}


/* 迭代二+弹性兜底：静态池空时降级 _aligned_malloc，回收时精准归还 */
ScanTask *AllocScanTask() {
  PSLIST_ENTRY e = InterlockedPopEntrySList(g_ScanTaskPool);
  ScanTask *t = (ScanTask *)e;
  if (!t) {
    int retries = 0;
    while (!t && retries < OOM_RETRY_MAX) {
      if (IsCanceling()) break;
      t = (ScanTask *)_aligned_malloc(SCAN_TASK_ALIGNED_SIZE, 16);
      if (!t) { Sleep(10); retries++; }
    }
  }
  if (!t) return NULL;
  memset((char *)t + sizeof(SLIST_ENTRY), 0,
         sizeof(ScanTask) - sizeof(SLIST_ENTRY));
  return t;
}

void FreeScanTask(ScanTask *t) {
  if (!t) return;
  /* D4 修复：直接读 pathFlags，无需 O(n) IsArenaPtr 扫描 */
  if (t->SrcPath && !(t->pathFlags & (TASK_PATH_FLAG_SRC_ARENA | TASK_PATH_FLAG_SRC_SHORT)))
    free(t->SrcPath);
  t->SrcPath = NULL;
  if (t->DstPath && !(t->pathFlags & (TASK_PATH_FLAG_DST_ARENA | TASK_PATH_FLAG_DST_SHORT)))
    free(t->DstPath);
  t->DstPath = NULL;
  /* 弹性兜底：边界判定，静态池极速回收 vs 弹性溢出 _aligned_free */
  if (g_ScanTaskStaticBlock && g_ScanTaskStaticTotalSize > 0 &&
      (char *)t >= (char *)g_ScanTaskStaticBlock &&
      (char *)t < (char *)g_ScanTaskStaticBlock + g_ScanTaskStaticTotalSize) {
    InterlockedPushEntrySList(g_ScanTaskPool, &t->ItemEntry);
  } else {
    _aligned_free(t);
  }
}

/* 4MB 缓冲满时落盘，系统调用从 3 次/任务降至 1 次/4MB */
static void FlushOverflowBuffer(void) {
  if (!g_OverflowBuffer || g_OverflowBufUsed == 0) return;
  DWORD wr;
  WriteFile(g_hOverflowFile, g_OverflowBuffer, g_OverflowBufUsed, &wr, NULL);
  g_OverflowBufUsed = 0;
}

/* MMF 溢出：写入 %TEMP%\\pb_xflow_tasks.dat（当前无调用方；背压由 WaitCopyQueueCapacity 承担，保留以备极端扩展） */
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable:4505) /* unreferenced function with internal linkage */
#endif
static BOOL OverflowWrite(const wchar_t *src, const wchar_t *dst, LONGLONG fileSize,
    const FILETIME *creation, const FILETIME *lastAccess, const FILETIME *lastWrite, DWORD attrs,
    HANDLE hIocp) {
  if (g_hOverflowFile == INVALID_HANDLE_VALUE) {
    wchar_t path[MAX_PATH];
    if (GetTempPathW(MAX_PATH, path) == 0) return FALSE;
    StringCchCatW(path, MAX_PATH, L"pb_xflow_tasks.dat");
    StringCchCopyW(g_OverflowFilePath, MAX_PATH, path);  /* Round6 P0：Consumer 独立句柄用 */
    InitializeCriticalSection(&g_OverflowCs);
    /* Round6 P0：FILE_SHARE_WRITE 允许 Consumer 以只读句柄并发打开，读写句柄物理隔离消灭文件指针竞态 */
    g_hOverflowFile = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (g_hOverflowFile == INVALID_HANDLE_VALUE) return FALSE;
    g_OverflowBuffer = (BYTE *)VirtualAlloc(NULL, OVERFLOW_BUF_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_OverflowBuffer) {
      CloseHandle(g_hOverflowFile);
      g_hOverflowFile = INVALID_HANDLE_VALUE;
      return FALSE;
    }
    g_OverflowBufUsed = 0;
    g_OverflowIocp = hIocp;
    /* 占一个 g_PendingActive slot，防止主循环在 Consumer 还未排空溢出文件前提前退出。
     * Consumer 线程结束前负责 InterlockedDecrement(&g_PendingActive)。 */
    InterlockedIncrement(&g_PendingActive);
    g_hOverflowConsumer = (HANDLE)_beginthreadex(NULL, 0, OverflowConsumerThread, hIocp, 0, NULL);
    if (!g_hOverflowConsumer) InterlockedDecrement(&g_PendingActive); /* 启动失败则还原 */
  }
  DWORD srcLen = (DWORD)(wcslen(src) * sizeof(wchar_t));
  DWORD dstLen = (DWORD)(wcslen(dst) * sizeof(wchar_t));
  DWORD recLen = 48 + srcLen + dstLen;  /* 44 + 4(magic) + src + dst */
  char rec[52];
  memcpy(rec, &srcLen, 4); memcpy(rec+4, &dstLen, 4);
  memcpy(rec+8, &fileSize, 8);
  memcpy(rec+16, creation, 8); memcpy(rec+24, lastAccess, 8); memcpy(rec+32, lastWrite, 8);
  memcpy(rec+40, &attrs, 4);
  { DWORD m = OVERFLOW_REC_MAGIC; memcpy(rec+44, &m, 4); }
  EnterCriticalSection(&g_OverflowCs);
  if (g_OverflowBufUsed + recLen > OVERFLOW_BUF_SIZE)
    FlushOverflowBuffer();
  memcpy(g_OverflowBuffer + g_OverflowBufUsed, rec, 48);
  memcpy(g_OverflowBuffer + g_OverflowBufUsed + 48, src, srcLen);
  memcpy(g_OverflowBuffer + g_OverflowBufUsed + 48 + srcLen, dst, dstLen);
  g_OverflowBufUsed += recLen;
  InterlockedAdd64((volatile LONGLONG *)&g_OverflowWritePos, recLen);
  LeaveCriticalSection(&g_OverflowCs);
  return TRUE;
}
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

/* Round6 P1：非阻塞投递 —— 队列满时通过 OverflowWrite 溢出至磁盘，
 * 避免 Copier 线程在生产者模式下阻塞导致消费能力丢失（死锁）。 */
static void PostCopyTaskWithOverflow(CopierParam *param, CopyTask *ct, HANDLE hIocp) {
  if (READ_VOLATILE_32(&g_PendingCopyTasks) >= READ_VOLATILE_32(&g_MaxQueueDepth)) {
    if (OverflowWrite(ct->SrcPath, ct->DstPath, ct->FileSize,
                      &ct->CreationTime, &ct->LastAccessTime, &ct->LastWriteTime,
                      ct->FileAttributes, hIocp)) {
      if (param) TLC_FreeCopyTask(param, ct);
      else FreeCopyTask(ct);
      return;
    }
  }
  PostCopyTask(hIocp, ct);
}

static unsigned __stdcall OverflowConsumerThread(void *p) {
  HANDLE hIocp = (HANDLE)p;
  if (!hIocp || g_hOverflowFile == INVALID_HANDLE_VALUE) {
      InterlockedDecrement(&g_PendingActive); // 修复早期退出的泄露
      return 1;
  }
  /* Round6 P0：Consumer 独立只读句柄，必须包含 FILE_SHARE_DELETE，因为原句柄有 DELETE_ON_CLOSE */
  HANDLE hRead = CreateFileW(g_OverflowFilePath, GENERIC_READ, 
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, // <--- 增加 FILE_SHARE_DELETE
                             NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hRead == INVALID_HANDLE_VALUE) {
      InterlockedDecrement(&g_PendingActive); // 修复创建失败的泄露
      return 1;
  }
  LONGLONG readPos = 0;
  BYTE *chunk = (BYTE *)malloc(OVERFLOW_BUF_SIZE);
  if (!chunk) { CloseHandle(hRead); return 1; }
  DWORD chunkLen = 0, chunkPtr = 0;
  wchar_t srcBuf[MAX_PATH_EXT], dstBuf[MAX_PATH_EXT];
  int idleCount = 0;
  int quickSleepCount = 0;  /* 首轮短 Sleep 加快滑入 */
  while (!IsCanceling()) {
    if (READ_VOLATILE_32(&g_PendingCopyTasks) >= OVERFLOW_REFILL) {
      Sleep(quickSleepCount < 5 ? 10 : 50);
      if (quickSleepCount < 10) quickSleepCount++;
      continue;
    }
    quickSleepCount = 0;
    LONGLONG writePos = READ_VOLATILE_64(&g_OverflowWritePos);
    if (readPos >= writePos) {
      /* g_OverflowWritePos 在数据写入内存缓冲区时即递增，但磁盘文件可能落后。
       * 此处主动 flush，确保缓冲区数据落盘后 Consumer 可以读到，避免漏拷。*/
      EnterCriticalSection(&g_OverflowCs);
      if (g_OverflowBufUsed > 0) FlushOverflowBuffer();
      LeaveCriticalSection(&g_OverflowCs);
      writePos = READ_VOLATILE_64(&g_OverflowWritePos);
      if (readPos >= writePos) {
        /* 优化：缓冲区为空、所有数据已读完，且扫描器已全部结束（g_PendingActive 仅剩
         * 我们自己的 slot=1），则无更多数据会写入，立即退出，避免等待 10 分钟超时。 */
        if (g_OverflowBufUsed == 0 && READ_VOLATILE_32(&g_PendingActive) <= 1) break;
        if (++idleCount > (OVERFLOW_IDLE_EXIT_MS / 50)) break;
        Sleep(idleCount <= 3 ? 10 : 50);  /* 首轮短 Sleep 加快检测新数据 */
        continue;
      }
      idleCount = 0; /* flush 后发现有新数据，重置计数 */
    } else {
      idleCount = 0;
    }
    /* 大块读取：chunk 不足 48 字节(含 magic)时补充 */
    if (chunkPtr + 48 > chunkLen) {
      if (chunkLen > chunkPtr)
        memmove(chunk, chunk + chunkPtr, chunkLen - chunkPtr);
      chunkLen -= chunkPtr;
      chunkPtr = 0;
      EnterCriticalSection(&g_OverflowCs);
      if (g_OverflowBufUsed > 0) FlushOverflowBuffer(); /* 读前再次确保落盘 */
      { LARGE_INTEGER li; li.QuadPart = readPos + chunkLen; SetFilePointerEx(hRead, li, NULL, FILE_BEGIN); }
      DWORD rd;
      if (!ReadFile(hRead, chunk + chunkLen, OVERFLOW_BUF_SIZE - chunkLen, &rd, NULL) || rd == 0) {
        LeaveCriticalSection(&g_OverflowCs);
        break;
      }
      chunkLen += rd;
      LeaveCriticalSection(&g_OverflowCs);
    }
    if (chunkPtr + 48 > chunkLen) break;
    DWORD srcLen, dstLen;
    memcpy(&srcLen, chunk + chunkPtr, 4); memcpy(&dstLen, chunk + chunkPtr + 4, 4);
    { DWORD magic; memcpy(&magic, chunk + chunkPtr + 44, 4);
      if (magic != OVERFLOW_REC_MAGIC) {
        static volatile LONG s_OverflowCorruptWarn = 0;
        if (InterlockedIncrement(&s_OverflowCorruptWarn) == 1)
          wprintf(L"\n[FATAL] Overflow file corrupted (magic mismatch). Power loss? Stopping.\n");
        break;
      }
    }
    if (srcLen >= sizeof(srcBuf) || dstLen >= sizeof(dstBuf)) break;  /* >= 保留 \0 空间，防越界 */
    if (chunkPtr + 48 + srcLen + dstLen > chunkLen) {
      if (chunkLen > chunkPtr)
        memmove(chunk, chunk + chunkPtr, chunkLen - chunkPtr);
      chunkLen -= chunkPtr;
      chunkPtr = 0;
      EnterCriticalSection(&g_OverflowCs);
      if (g_OverflowBufUsed > 0) FlushOverflowBuffer(); /* 确保记录完整落盘再读 */
      { LARGE_INTEGER li; li.QuadPart = readPos + chunkLen; SetFilePointerEx(hRead, li, NULL, FILE_BEGIN); }
      DWORD rd;
      if (!ReadFile(hRead, chunk + chunkLen, OVERFLOW_BUF_SIZE - chunkLen, &rd, NULL) || rd == 0) {
        LeaveCriticalSection(&g_OverflowCs);
        break;
      }
      chunkLen += rd;
      LeaveCriticalSection(&g_OverflowCs);
    }
    if (chunkPtr + 48 + srcLen + dstLen > chunkLen) break;
    LONGLONG fileSize; FILETIME creation, lastAccess, lastWrite; DWORD attrs;
    memcpy(&fileSize, chunk + chunkPtr + 8, 8);
    memcpy(&creation, chunk + chunkPtr + 16, 8); memcpy(&lastAccess, chunk + chunkPtr + 24, 8);
    memcpy(&lastWrite, chunk + chunkPtr + 32, 8); memcpy(&attrs, chunk + chunkPtr + 40, 4);
    memcpy(srcBuf, chunk + chunkPtr + 48, srcLen);
    memcpy(dstBuf, chunk + chunkPtr + 48 + srcLen, dstLen);
    readPos += 48 + srcLen + dstLen;
    chunkPtr += 48 + srcLen + dstLen;
    srcBuf[srcLen/sizeof(wchar_t)] = L'\0';
    dstBuf[dstLen/sizeof(wchar_t)] = L'\0';
    size_t srcCharLen = srcLen / sizeof(wchar_t);
    size_t dstCharLen = dstLen / sizeof(wchar_t);
    CopyTask *cT = AllocCopyTask();
    if (!cT) continue;
    cT->SrcLen = (uint32_t)srcCharLen;
    cT->DstLen = (uint32_t)dstCharLen;
    if (srcCharLen < MAX_PATH && dstCharLen < MAX_PATH) {
      StringCchCopyW(cT->ShortSrc, MAX_PATH, srcBuf);
      StringCchCopyW(cT->ShortDst, MAX_PATH, dstBuf);
      cT->SrcPath = cT->ShortSrc;
      cT->DstPath = cT->ShortDst;
      cT->pathFlags = TASK_PATH_FLAG_SRC_SHORT | TASK_PATH_FLAG_DST_SHORT;
    } else {
      cT->SrcPath = StrDupTransient(srcBuf, srcCharLen);
      cT->DstPath = cT->SrcPath ? StrDupTransient(dstBuf, dstCharLen) : NULL;
      if (!cT->SrcPath || !cT->DstPath) {
        FreeCopyTask(cT);
        continue;
      }
      cT->pathFlags = 0;  /* Round6 P1：malloc 路径，TLC_FreeCopyTask 会 free */
    }
    cT->FileSize = fileSize;
    cT->CreationTime = creation; cT->LastAccessTime = lastAccess; cT->LastWriteTime = lastWrite;
    cT->FileAttributes = attrs;
    cT->pSrcBackend = VFS_GetBackend(srcBuf);
    cT->pDstBackend = VFS_GetBackend(dstBuf);
    WaitCopyQueueCapacity();
    if (!IsCanceling())
      PostCopyTask(hIocp, cT);
    else
      FreeCopyTask(cT);
  }
  free(chunk);
  CloseHandle(hRead);  /* Round6 P0：释放 Consumer 专属只读句柄 */
  /* 释放启动时占用的 g_PendingActive slot，通知主循环 Consumer 已彻底结束 */
  InterlockedDecrement(&g_PendingActive);
  return 0;
}

/* Phase 17 BypassIO：Win11+ 对 NO_BUFFERING 读句柄启用，剥离 Filter Driver 栈直通 NVMe */
static void TryEnableBypassIO(HANDLE h) {
  BPIO_INPUT in = { 1, 0, 0, 0 };  /* Operation=FS_BPIO_OP_ENABLE */
  BPIO_OUTPUT out = { 0 };
  DWORD bytesRet;
  (void)DeviceIoControl(h, FSCTL_MANAGE_BYPASS_IO, &in, sizeof(in),
                       &out, sizeof(out), &bytesRet, NULL);
  /* 失败静默：Win10/非 NTFS/稀疏/加密等自动 veto，不影响主路径 */
}

/* 迭代一：利用 RootDirectory 实现 O(1) 路径解析的文件创建
 * hRootDir: 已打开的目标文件夹句柄 | fileName: 纯文件名（不得含 \\）
 * pAllocationSize: 可选，非 NULL 且 >0 时在创建瞬间预分配，省去后续 SetFileInformationByHandle */
static HANDLE CreateFileRelativeW(HANDLE hRootDir, LPCWSTR fileName,
    DWORD dwDesiredAccess, DWORD dwShareMode, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, PLARGE_INTEGER pAllocationSize) {
  if (!g_NtCreateFile || !hRootDir || hRootDir == INVALID_HANDLE_VALUE) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return INVALID_HANDLE_VALUE;
  }
  UNICODE_STRING usName;
  usName.Length = (USHORT)(wcslen(fileName) * sizeof(WCHAR));
  usName.MaximumLength = usName.Length + sizeof(WCHAR);
  usName.Buffer = (PWSTR)fileName;
  OBJECT_ATTRIBUTES objAttr;
  InitializeObjectAttributes(&objAttr, &usName, OBJ_CASE_INSENSITIVE, hRootDir, NULL);
  ULONG ntDisp;
  switch (dwCreationDisposition) {
    case CREATE_NEW:        ntDisp = 2; break;
    case CREATE_ALWAYS:     ntDisp = 5; break;
    case OPEN_EXISTING:     ntDisp = 1; break;
    case OPEN_ALWAYS:       ntDisp = 3; break;
    case TRUNCATE_EXISTING: ntDisp = 4; break;
    default:                ntDisp = 1; break;
  }
  ULONG createOpt = 0x40; /* FILE_NON_DIRECTORY_FILE */
  if (dwFlagsAndAttributes & FILE_FLAG_SEQUENTIAL_SCAN) createOpt |= 0x04;
  if (dwFlagsAndAttributes & FILE_FLAG_NO_BUFFERING)    createOpt |= 0x08;
  if (dwFlagsAndAttributes & FILE_FLAG_WRITE_THROUGH)   createOpt |= 0x02;
  /* 无条件 SYNCHRONIZE：Win32 CreateFile 会自动附加；NtCreateFile 必须显式给出，
   * 否则 GetOverlappedResult(hFile, …, TRUE) / 部分 FSCTL 返回 STATUS_ACCESS_DENIED。
   * FILE_READ_ATTRIBUTES：属性查询与部分卷操作常用。 */
  dwDesiredAccess |= SYNCHRONIZE | FILE_READ_ATTRIBUTES;
  if ((dwFlagsAndAttributes & FILE_FLAG_OVERLAPPED) == 0)
    createOpt |= 0x20; /* FILE_SYNCHRONOUS_IO_NONALERT */
  IO_STATUS_BLOCK ioStatus;
  HANDLE hFile = INVALID_HANDLE_VALUE;
  NTSTATUS status = g_NtCreateFile(&hFile, dwDesiredAccess, &objAttr, &ioStatus,
      pAllocationSize, (ULONG)(dwFlagsAndAttributes & FILE_ATTRIBUTE_VALID_FLAGS), dwShareMode, ntDisp,
      createOpt, NULL, 0);
  if (NT_SUCCESS(status))
    return hFile;
  if (g_RtlNtStatusToDosError)
    SetLastError(g_RtlNtStatusToDosError(status));
  return INVALID_HANDLE_VALUE;
}

/* 从完整路径提取纯文件名，返回指向 path 内部的指针 */
static LPCWSTR GetFileNameFromPath(LPCWSTR path) {
  if (!path || !path[0]) return path;
  const wchar_t *last = wcsrchr(path, L'\\');
  return last ? (last + 1) : path;
}

/* 迭代一：优先 NTAPI 相对路径创建，同目录连续创建零 VFS 解析。失败或未启用时回退 CreateFileW
 * 【关键】：hRootDir 必须为文件的直接父目录，fileName 必须为纯文件名（不含 \\）
 * 本实现用 wcsrchr 取最后一层，parent=D:\\a\\b, fileName=file.txt，满足 NtCreateFile 要求 */
static HANDLE NtApiLruLookupOrOpen(CopierParam *param, int isSrc, LPCWSTR parent) {
  int i, victim = 0;
  DWORD oldest = 0xFFFFFFFF;
  DWORD clock = ++param->NtApiLruClock;
  if (isSrc) {
    for (i = 0; i < NTAPI_DIR_LRU_SLOTS; i++) {
      if (param->NtApiSrcLru[i].hDir && param->NtApiSrcLru[i].hDir != INVALID_HANDLE_VALUE &&
          wcsncmp(param->NtApiSrcLru[i].path, parent, MAX_PATH) == 0) {
        param->NtApiSrcLru[i].lastUsed = clock;
        return param->NtApiSrcLru[i].hDir;
      }
      if (!param->NtApiSrcLru[i].hDir || param->NtApiSrcLru[i].hDir == INVALID_HANDLE_VALUE) {
        victim = i; oldest = 0; break;
      }
      if (param->NtApiSrcLru[i].lastUsed < oldest) {
        oldest = param->NtApiSrcLru[i].lastUsed;
        victim = i;
      }
    }
    if (param->NtApiSrcLru[victim].hDir && param->NtApiSrcLru[victim].hDir != INVALID_HANDLE_VALUE)
      CloseHandle(param->NtApiSrcLru[victim].hDir);
    HANDLE hDir = CreateFileW(parent, GENERIC_READ | FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hDir == INVALID_HANDLE_VALUE) {
      param->NtApiSrcLru[victim].hDir = INVALID_HANDLE_VALUE;
      param->NtApiSrcLru[victim].path[0] = L'\0';
      return INVALID_HANDLE_VALUE;
    }
    StringCchCopyW(param->NtApiSrcLru[victim].path, MAX_PATH, parent);
    param->NtApiSrcLru[victim].hDir = hDir;
    param->NtApiSrcLru[victim].lastUsed = clock;
    return hDir;
  }
  for (i = 0; i < NTAPI_DIR_LRU_SLOTS; i++) {
    if (param->NtApiDstLru[i].hDir && param->NtApiDstLru[i].hDir != INVALID_HANDLE_VALUE &&
        wcsncmp(param->NtApiDstLru[i].path, parent, MAX_PATH) == 0) {
      param->NtApiDstLru[i].lastUsed = clock;
      return param->NtApiDstLru[i].hDir;
    }
    if (!param->NtApiDstLru[i].hDir || param->NtApiDstLru[i].hDir == INVALID_HANDLE_VALUE) {
      victim = i; oldest = 0; break;
    }
    if (param->NtApiDstLru[i].lastUsed < oldest) {
      oldest = param->NtApiDstLru[i].lastUsed;
      victim = i;
    }
  }
  if (param->NtApiDstLru[victim].hDir && param->NtApiDstLru[victim].hDir != INVALID_HANDLE_VALUE)
    CloseHandle(param->NtApiDstLru[victim].hDir);
  HANDLE hDir = CreateFileW(parent, GENERIC_READ | FILE_LIST_DIRECTORY | FILE_ADD_FILE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
  if (hDir == INVALID_HANDLE_VALUE) {
    param->NtApiDstLru[victim].hDir = INVALID_HANDLE_VALUE;
    param->NtApiDstLru[victim].path[0] = L'\0';
    return INVALID_HANDLE_VALUE;
  }
  StringCchCopyW(param->NtApiDstLru[victim].path, MAX_PATH, parent);
  param->NtApiDstLru[victim].hDir = hDir;
  param->NtApiDstLru[victim].lastUsed = clock;
  return hDir;
}

static HANDLE OpenDstFileWithNtApi(CopierParam *param, LPCWSTR dstPath,
    DWORD access, DWORD share, DWORD disp, DWORD flags, LONGLONG allocationSize) {
  if (!g_NtCreateFile || !param) goto fallback;
  const wchar_t *slash = wcsrchr(dstPath, L'\\');
  if (!slash || slash <= dstPath) goto fallback;
  size_t parentLen = (size_t)(slash - dstPath);
  if (parentLen >= MAX_PATH) goto fallback;
  if (dstPath[0] == L'\\' && dstPath[1] == L'\\') goto fallback;

  wchar_t parent[MAX_PATH];
  memcpy(parent, dstPath, parentLen * sizeof(wchar_t));
  parent[parentLen] = L'\0';

  LPCWSTR fileName = slash + 1;
  if (!fileName[0]) goto fallback;

  HANDLE hDir = NtApiLruLookupOrOpen(param, 0, parent);
  if (hDir == INVALID_HANDLE_VALUE) goto fallback;

  LARGE_INTEGER liAlloc;
  PLARGE_INTEGER pAlloc = NULL;
  if (allocationSize > 0) {
    liAlloc.QuadPart = allocationSize;
    pAlloc = &liAlloc;
  }
  HANDLE h = CreateFileRelativeW(hDir, fileName, access, share, disp, flags, pAlloc);
  if (h != INVALID_HANDLE_VALUE) return h;
fallback:
  return CreateFileW(dstPath, access, share, NULL, disp, flags, NULL);
}

void EnsureParentDirExistsEx(const wchar_t *filePath, size_t parentLen); /* 前置：EnsureParentDirExistsCached */

/* PB：源文件相对打开，与 OpenDstFileWithNtApi 对称；失败回退全路径 CreateFileW */
static HANDLE OpenSrcFileWithNtApi(CopierParam *param, LPCWSTR srcPath,
    DWORD access, DWORD share, DWORD flags) {
  if (!g_NtCreateFile || !param) goto fallback_src;
  const wchar_t *slash = wcsrchr(srcPath, L'\\');
  if (!slash || slash <= srcPath) goto fallback_src;
  size_t parentLen = (size_t)(slash - srcPath);
  if (parentLen >= MAX_PATH) goto fallback_src;
  if (srcPath[0] == L'\\' && srcPath[1] == L'\\') goto fallback_src;

  wchar_t parent[MAX_PATH];
  memcpy(parent, srcPath, parentLen * sizeof(wchar_t));
  parent[parentLen] = L'\0';
  LPCWSTR fileName = slash + 1;
  if (!fileName[0]) goto fallback_src;

  HANDLE hDir = NtApiLruLookupOrOpen(param, 1, parent);
  if (hDir == INVALID_HANDLE_VALUE) goto fallback_src;
  HANDLE h = CreateFileRelativeW(hDir, fileName, access, share, OPEN_EXISTING, flags, NULL);
  if (h != INVALID_HANDLE_VALUE) return h;
fallback_src:
  return CreateFileW(srcPath, access, share, NULL, OPEN_EXISTING, flags, NULL);
}

/* 同父目录连续拷贝：跳过 EnsureParent + DstDirCache XXH3 */
static void EnsureParentDirExistsCached(CopierParam *param, const wchar_t *dstPath) {
  if (!dstPath || !dstPath[0]) return;
  const wchar_t *slash = wcsrchr(dstPath, L'\\');
  if (!slash || slash <= dstPath) {
    EnsureParentDirExistsEx(dstPath, 0);
    return;
  }
  size_t plen = (size_t)(slash - dstPath);
  if (param && plen < MAX_PATH && param->LastEnsuredParentLen == plen &&
      wcsncmp(param->LastEnsuredParent, dstPath, plen) == 0)
    return;
  EnsureParentDirExistsEx(dstPath, plen);
  if (param && plen < MAX_PATH) {
    memcpy(param->LastEnsuredParent, dstPath, plen * sizeof(wchar_t));
    param->LastEnsuredParent[plen] = L'\0';
    param->LastEnsuredParentLen = plen;
  }
}

/* ---------- VFS 本地盘后端 ----------
 * 【契约式设计】：path 由 ProcessScanTask 建树时已规格化，此处零 NormalizePath 开销 */
static IO_HANDLE VFS_Local_Open(const wchar_t *path, IO_MODE mode,
                                BOOL useOverlapped) {
  DWORD access = (mode == IO_MODE_READ) ? GENERIC_READ : GENERIC_WRITE;
  DWORD share = (mode == IO_MODE_READ) ?
      (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE) : 0;
  DWORD disp = (mode == IO_MODE_WRITE_CREATE) ? CREATE_ALWAYS : OPEN_EXISTING;
  DWORD flags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN |
                FILE_FLAG_BACKUP_SEMANTICS;
  if (mode == IO_MODE_WRITE_CREATE)
    flags |= FILE_ATTRIBUTE_TEMPORARY; /* 减少 Search Indexer/Explorer 干扰 */
  if (useOverlapped)
    flags |= FILE_FLAG_OVERLAPPED;
  HANDLE h = CreateFileW(path, access, share, NULL, disp, flags, NULL);
  if (h != INVALID_HANDLE_VALUE && (g_Config.HighPriority || g_Config.LowIoPriority)) {
    /* Phase 12 句柄级 I/O 优先级：比线程级更细粒度，存储栈直接响应 */
#ifndef FileIoPriorityHintInformation
#define FileIoPriorityHintInformation ((FILE_INFO_BY_HANDLE_CLASS)50)
#endif
    typedef struct { IO_PRIORITY_HINT PriorityHint; } FILE_IO_PRIORITY_HINT_INFO;
    FILE_IO_PRIORITY_HINT_INFO hint;
    hint.PriorityHint = g_Config.HighPriority ? IoPriorityHigh :
        (g_Config.LowIoPriority ? IoPriorityLow : IoPriorityNormal);
    SetFileInformationByHandle(h, FileIoPriorityHintInformation, &hint, sizeof(hint));
  }
  return (h != INVALID_HANDLE_VALUE) ? (IO_HANDLE)h : IO_HANDLE_INVALID;
}

static BOOL VFS_Local_Read(IO_HANDLE h, void *buf, DWORD size, DWORD *bytesRead) {
  return ReadFile((HANDLE)h, buf, size, bytesRead, NULL);
}

static BOOL VFS_Local_Write(IO_HANDLE h, const void *buf, DWORD size,
                            DWORD *bytesWritten) {
  return WriteFile((HANDLE)h, buf, size, bytesWritten, NULL);
}

static void VFS_Local_Close(IO_HANDLE h) {
  if (h != IO_HANDLE_INVALID)
    CloseHandle((HANDLE)h);
}

static BOOL VFS_Local_IsAsyncSupported(void) { return TRUE; }

static HANDLE VFS_Local_GetNativeHandle(IO_HANDLE h) {
  return (h != IO_HANDLE_INVALID) ? (HANDLE)h : INVALID_HANDLE_VALUE;
}

static const IO_BACKEND g_VFS_LocalBackend = {
    "local",
    VFS_Local_Open,
    VFS_Local_Read,
    VFS_Local_Write,
    VFS_Local_Close,
    VFS_Local_IsAsyncSupported,
    VFS_Local_GetNativeHandle,
    NULL, /* SubmitRead: 本地走 GetNativeHandle + IOCP */
    NULL,
    NULL,
};

const IO_BACKEND *VFS_GetBackend(const wchar_t *path) {
  if (!path || !path[0])
    return &g_VFS_LocalBackend;
  /* 热路径快速路径：本地路径占绝大多数，首字符非 s/f 直接返回，避免 wcsncmp */
  wchar_t c = path[0];
  if (c != L's' && c != L'S' && c != L'f' && c != L'F')
    return &g_VFS_LocalBackend;
  if (wcsncmp(path, L"sftp://", 7) == 0 || wcsncmp(path, L"SFTP://", 7) == 0)
    return NULL; /* SFTP 后端未实现 */
  if (wcsncmp(path, L"ftp://", 6) == 0 || wcsncmp(path, L"FTP://", 6) == 0)
    return NULL; /* FTP 后端未实现 */
  return &g_VFS_LocalBackend;
}

#ifdef VFS_FUTURE
/* 通过 VFS 同步复制（SFTP/FTP 接入后启用；当前未使用） */
static BOOL CopyFileViaVFS(const wchar_t *src, const wchar_t *dst,
                           LONGLONG fileSize) {
  const IO_BACKEND *srcBack = VFS_GetBackend(src);
  const IO_BACKEND *dstBack = VFS_GetBackend(dst);
  if (!srcBack || !dstBack)
    return FALSE;
  IO_HANDLE hSrc = srcBack->Open(src, IO_MODE_READ, FALSE);
  IO_HANDLE hDst = dstBack->Open(dst, IO_MODE_WRITE_CREATE, FALSE);
  if (hSrc == IO_HANDLE_INVALID || hDst == IO_HANDLE_INVALID) {
    if (hSrc != IO_HANDLE_INVALID) srcBack->Close(hSrc);
    if (hDst != IO_HANDLE_INVALID) dstBack->Close(hDst);
    return FALSE;
  }
  BYTE *buf = (BYTE *)malloc(65536);
  if (!buf) {
    srcBack->Close(hSrc);
    dstBack->Close(hDst);
    return FALSE;
  }
  DWORD rd, wr;
  BOOL ok = TRUE;
  while (ok) {
    if (!srcBack->Read(hSrc, buf, 65536, &rd)) {
      ok = FALSE;
      break;
    }
    if (rd == 0)
      break;
    if (!dstBack->Write(hDst, buf, rd, &wr) || wr != rd) {
      ok = FALSE;
      break;
    }
  }
  free(buf);
  srcBack->Close(hSrc);
  dstBack->Close(hDst);
  return ok;
}
#endif

/* V8：池空时丢弃计数，前 3 次同步降级，第 4 次起静默丢弃，避免 I/O 热路径阻塞 */
static volatile LONG s_LogDropCount = 0;

void LogMessageAsync(LogLevel level, const wchar_t *format, va_list args) {
  /* 删除模式等早期阶段 g_LogQueue 未初始化，直接 wprintf 避免解引用 NULL 崩溃 */
  if (!g_LogQueue || !g_hLogEvent) {
    wchar_t buf[1024];
    StringCchVPrintfW(buf, 1024, format, args);
    wprintf(L"%s", buf);
    return;
  }
  LogEntry *entry = NULL;
  if (g_LogEntryPool) {
    PSLIST_ENTRY e = InterlockedPopEntrySList(g_LogEntryPool);
    if (e)
      entry = (LogEntry *)e;
  }
  if (!entry)
    entry = (LogEntry *)_aligned_malloc(sizeof(LogEntry),
                                        MEMORY_ALLOCATION_ALIGNMENT);
  /* V5：高并发下瞬时池空，Sleep(1) 给 LogThread 消费机会，重试一次减少同步降级 */
  if (!entry && g_LogEntryPool) {
    Sleep(1);
    { PSLIST_ENTRY e = InterlockedPopEntrySList(g_LogEntryPool);
      if (e) entry = (LogEntry *)e; }
    if (!entry)
      entry = (LogEntry *)_aligned_malloc(sizeof(LogEntry), MEMORY_ALLOCATION_ALIGNMENT);
  }
  if (!entry) {
    LONG n = InterlockedIncrement(&s_LogDropCount);
    /* QA：LOG_ERROR 永不丢弃，审计链不断；LOG_INFO/DEBUG 第 4 次起可静默丢弃 */
    if (n <= 3 || level == LOG_ERROR) {
      wchar_t buf[1024];
      StringCchVPrintfW(buf, 1024, format, args);
      EnterCriticalSection(&g_LogCs);
      wprintf(L"%s", buf);
      if (g_fNormalLog || g_fErrorLog) {
        FILE *f = (level == LOG_ERROR) ? g_fErrorLog : g_fNormalLog;
        if (f) {
          fputws(buf, f);
          fflush(f);
        }
      }
      LeaveCriticalSection(&g_LogCs);
    }
    return;
  }
  entry->isRaw = 0;
  entry->u.fmt.level = level;
  StringCchVPrintfW(entry->u.fmt.msg, 1024, format, args);
  InterlockedPushEntrySList(g_LogQueue, &(entry->ItemEntry));
  SetEvent(g_hLogEvent);
}

/* 无等待二进制日志：热路径零 vswprintf，仅 memcpy 压队，保护 L1 缓存 */
void LogMessageRaw(LogLevel level, DWORD errCode, const wchar_t *path, uint64_t fileSize, int rawType) {
  if (level > g_Config.LogVerbosity) return;
  if (g_Config.Quiet && level != LOG_ERROR) return;
  LogEntry *entry = NULL;
  if (g_LogEntryPool) {
    PSLIST_ENTRY e = InterlockedPopEntrySList(g_LogEntryPool);
    if (e) entry = (LogEntry *)e;
  }
  if (!entry)
    entry = (LogEntry *)_aligned_malloc(sizeof(LogEntry), MEMORY_ALLOCATION_ALIGNMENT);
  if (!entry) {
    LogMessage(level, L"\n[ERR] FAILED (Err: %lu): %ls\n", (unsigned long)errCode, path ? path : L"");
    return;
  }
  entry->isRaw = 1;
  entry->u.raw.timestamp = GetTickCount();
  entry->u.raw.level = (int)level;
  entry->u.raw.errCode = errCode;
  entry->u.raw.fileSize = fileSize;
  entry->u.raw.rawType = rawType;
  /* Round4 P1 Bug1：_wcsdup 支持任意长度路径（含 MAX_PATH_EXT 超长路径）。
   * OOM 时回退：截断至 MAX_PATH-1 并在末尾追加 "[len=N,TRUNCATED]" 标记，
   * 保证审计链不静默断裂——运维人员至少知道路径已截断及原始长度。 */
  if (path) {
    entry->u.raw.path = _wcsdup(path);
    if (!entry->u.raw.path) {  /* OOM 回退 */
      size_t n = wcslen(path);
      size_t bufSz = MAX_PATH + 32;
      wchar_t *fb = (wchar_t *)malloc(bufSz * sizeof(wchar_t));
      if (fb) {
        wcsncpy_s(fb, bufSz, path, MAX_PATH - 1);
        fb[MAX_PATH - 1] = L'\0';
        /* 追加截断标记，让审计人员知道路径不完整及原始长度 */
        StringCchPrintfW(fb + MAX_PATH - 1, 32, L"...[len=%zu,TRUNCATED]", n);
        entry->u.raw.path = fb;
      } else {
        entry->u.raw.path = NULL;  /* 极端 OOM：路径记为空，errCode 仍保留 */
      }
    }
  } else {
    entry->u.raw.path = NULL;
  }
  InterlockedPushEntrySList(g_LogQueue, &(entry->ItemEntry));
  SetEvent(g_hLogEvent);
}

/* 强制打印到屏幕并写入常规日志（无视 -z 参数），用于记录开头和结尾的统计信息 */
void PrintAndLog(const wchar_t *format, ...) {
  va_list args;
  va_start(args, format);
  wchar_t buf[2048];
  StringCchVPrintfW(buf, 2048, format, args);
  
  /* 宽缓冲须用 fputws；wprintf 配合 %s + wchar_t* 在部分 CRT 下会误按窄串解释 */
  fputws(buf, stdout);
  fflush(stdout);
  
  // 2. 强制写入常规日志文件
  if (g_fNormalLog) {
    EnterCriticalSection(&g_LogCs);
    fputws(buf, g_fNormalLog);
    fflush(g_fNormalLog);
    LeaveCriticalSection(&g_LogCs);
  }
  va_end(args);
}

/* 单行 JSON（ASCII 载荷），供 Fluentd/Vector 采集；须与 PrintAndLog 一致用 fputws 写 UTF-8 流。
 * 禁止在此对 ccs=UTF-8 的 FILE 使用 fwrite 原始字节，否则与 fputws 混用易破坏 CRT 流状态导致尾部乱码。 */
static void EmitIoStrategyJsonUtf8ToLog(void) {
  if (!g_fNormalLog)
    return;
  LONG64 bc = READ_VOLATILE_64(&g_IoStrategyStats[IOSTRAT_BLOCK_CLONE]);
  LONG64 bd = READ_VOLATILE_64(&g_IoStrategyStats[IOSTRAT_BIG_DIRECT_IO]);
  LONG64 bb = READ_VOLATILE_64(&g_IoStrategyStats[IOSTRAT_BIG_BUFFERED]);
  LONG fc = g_NumThreadBuckets > 0 ? SumBucketCopied() : g_TotalCopied;
  LONG64 fb = g_NumThreadBuckets > 0 ? SumBucketBytes() : g_TotalBytes;
  LONG totalFiles = fc + g_TotalFailed;
  wchar_t buf[640];
  if (FAILED(StringCchPrintfW(buf, 640,
          L"{\"telemetry\":\"pb_xflow.iostrategy\",\"protocol_version\":%u,"
          L"\"total_files\":%ld,\"total_bytes\":%llu,"
          L"\"block_clone\":%llu,\"direct_io\":%llu,\"buffered\":%llu}\n",
          TELEMETRY_PROTOCOL_VERSION, (long)totalFiles, (unsigned long long)fb,
          (unsigned long long)bc, (unsigned long long)bd, (unsigned long long)bb)))
    return;
  EnterCriticalSection(&g_LogCs);
  fputws(buf, g_fNormalLog);
  fflush(g_fNormalLog);
  LeaveCriticalSection(&g_LogCs);
}

void LogMessage(LogLevel level, const wchar_t *format, ...) {
  if (level > g_Config.LogVerbosity)
    return;
  if (g_Config.Quiet && level != LOG_ERROR)
    return; /* -z: 仅保留错误，防管道反向阻塞 */
  va_list args;
  va_start(args, format);
  LogMessageAsync(level, format, args);
  va_end(args);
}

/* full 审计 Phase1：MFT 投递结束后，主线程在 Phase2 MFT 前等待 IOCP 上 CopyTask 全部完成 */
static void AuditWaitDrainIocp(void) {
  DWORD lastLog = GetTickCount();
  while ((READ_VOLATILE_32(&g_PendingActive) > 0 || READ_VOLATILE_32(&g_PendingCopyTasks) > 0) &&
         !IsCanceling()) {
    Sleep(10);
    if (GetTickCount() - lastLog > 5000) {
      lastLog = GetTickCount();
      LogMessage(LOG_DEBUG, L"[AUDIT] Phase1 drain: PendingActive=%ld Q=%ld\n",
          (long)READ_VOLATILE_32(&g_PendingActive),
          (long)READ_VOLATILE_32(&g_PendingCopyTasks));
    }
  }
}

/* 当前进程的父进程 PID（CreateToolhelp32Snapshot）；失败返回 0 */
static DWORD QueryParentProcessIdWin32(DWORD pid) {
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE)
    return 0;
  PROCESSENTRY32W pe;
  pe.dwSize = sizeof(pe);
  DWORD parent = 0;
  if (Process32FirstW(snap, &pe)) {
    do {
      if (pe.th32ProcessID == pid) {
        parent = pe.th32ParentProcessID;
        break;
      }
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  return parent;
}

/* 父进程监控：GUI 崩溃时优雅退出，避免目标文件截断残次 */
unsigned __stdcall ParentWatcherThread(void *pParam) {
  DWORD pid = (DWORD)(UINT_PTR)pParam;
  if (pid == 0) return 0;
  HANDLE hParent = OpenProcess(SYNCHRONIZE, FALSE, pid);
  if (!hParent || hParent == INVALID_HANDLE_VALUE) return 0;
  if (WaitForSingleObject(hParent, INFINITE) == WAIT_OBJECT_0) {
    InterlockedExchange(&g_IsCanceling, 1);
    /* Round5 P2-架构1：立即唤醒所有挂在 WaitIfPaused 的线程，避免 100ms 集体延迟 */
    if (g_hPauseReleaseEvent)
      SetEvent(g_hPauseReleaseEvent);
    wprintf(L"\n[WARN] Parent process (PID %lu) exited, initiating graceful shutdown...\n", (unsigned long)pid);
  }
  CloseHandle(hParent);
  return 0;
}

#define HOST_AWARE_CPU_THRESHOLD 80   /* Phase 20: CPU>80% 触发降速 */
#define HOST_AWARE_DISKQ_THRESHOLD 10 /* Phase 20: 磁盘队列>10 触发降速 */
#define HOST_AWARE_FACTOR 0.7f        /* Phase 20: 降速系数 */

/* QoS 令牌桶发牌线程：1ms 发牌。Phase 19 发牌人模式：有 g_CopierParams 时直接写入各线程 LocalTokens，零 Interlocked
 * V10：唯一执行 ReadControlIfDirty 的监控线程，工作线程只读 s_cached_*，消灭 IPC 竞态
 * P3：Host-Aware 读 g_CachedCpuLoad/g_CachedDiskQueue，OsTelemetryThread 唯一 PDH 采样
 * P4：QPC 真实流逝时间发牌，解除 addTokens 与 Sleep 精度的物理绑定，消除 10GB/s+ 限速下的微爆发 */
unsigned __stdcall TokenBucketThread(void *pParam) {
  UNREFERENCED_PARAMETER(pParam);
  DWORD interval = 1;
  LARGE_INTEGER freq, lastTick, nowTick;
  QueryPerformanceFrequency(&freq);
  QueryPerformanceCounter(&lastTick);
  while (g_TokenThreadRunning) {
    ReadControlIfDirty();  /* V10：单一监控点，工作线程绝不碰 shm->isDirty */
    QueryPerformanceCounter(&nowTick);
    LONGLONG elapsedUs = (nowTick.QuadPart - lastTick.QuadPart) * 1000000 / freq.QuadPart;
    lastTick = nowTick;
    if (elapsedUs < 100) elapsedUs = 100;   /* 防止除零与异常短间隔 */
    if (elapsedUs > 50000) elapsedUs = 50000; /* 防止长时间挂起后令牌爆炸 */
    LONGLONG limitBps = READ_VOLATILE_64(&g_SpeedLimitBps);
    if (limitBps > 0) {
      /* Phase 20 Host-Aware: 系统负载高时主动降速，P3 读 OsTelemetryThread 缓存，零 PDH 调用 */
      if (g_Config.HostAware) {
        DWORD cpu = g_CachedCpuLoad;
        DWORD diskQ = g_CachedDiskQueue;
        if (cpu >= HOST_AWARE_CPU_THRESHOLD || diskQ >= HOST_AWARE_DISKQ_THRESHOLD)
          limitBps = (LONGLONG)(limitBps * HOST_AWARE_FACTOR);
      }
      /* P4：按真实流逝微秒比例发牌，消除 Sleep 抖动导致的吞吐量暴跌 */
      LONGLONG addTokens = limitBps * elapsedUs / 1000000;
      if (addTokens <= 0) addTokens = 1;  /* 极低速限速时至少发 1 token */
      LONGLONG maxCapacity = limitBps * 2;
      if (maxCapacity < (LONGLONG)g_BigBufferSize)
        maxCapacity = (LONGLONG)g_BigBufferSize;
      if (maxCapacity < THREAD_IORING_BUFFER_SIZE)
        maxCapacity = THREAD_IORING_BUFFER_SIZE;
      int nWorkers = g_NumCopierParams > 0 ? g_NumCopierParams : 1;
      if (g_CopierParams && nWorkers > 0) {
        /* Phase 19（已修复 BUG-C1 + D3）：原子发牌，余数持续补偿避免 token 流失
       * D3：addTokens % nWorkers 的余数累计进 bankerRemainder，超过 1 token/thread 时补发 */
        static LONGLONG bankerRemainder = 0;
        bankerRemainder += addTokens % nWorkers;
        LONGLONG bonus = bankerRemainder / nWorkers;
        if (bonus > 0) bankerRemainder -= bonus * nWorkers;
        LONGLONG perThread = addTokens / nWorkers + bonus;
        if (perThread > 0) {
          BOOL anyWoke = FALSE;
          for (int i = 0; i < nWorkers; i++) {
            CopierParam *p = g_CopierParams[i];
            if (p) {
              LONGLONG prev = READ_VOLATILE_64(&p->LocalTokens);
              /* 原子发牌：若已超上限则不再追加 */
              for (;;) {
                LONGLONG cur = READ_VOLATILE_64(&p->LocalTokens);
                LONGLONG add = (cur + perThread > maxCapacity) ? (maxCapacity - cur) : perThread;
                if (add <= 0) break;
                if (InterlockedCompareExchange64((volatile LONGLONG *)&p->LocalTokens,
                                                 cur + add, cur) == cur) break;
              }
              /* D7：若之前 token 为 0（工作线程可能在 WaitOnAddress 等待），发送唤醒 */
              if (prev == 0 && READ_VOLATILE_64(&p->LocalTokens) > 0) {
                if (g_pfnWakeByAddressAll) g_pfnWakeByAddressAll((void *)&p->LocalTokens);
                anyWoke = TRUE;
              }
            }
          }
          (void)anyWoke;
        }
      } else {
        LONGLONG cur = READ_VOLATILE_64(&g_AvailableTokens);
        if (cur < 0) cur = 0;
        if (cur < maxCapacity)
          InterlockedAdd64((volatile LONGLONG *)&g_AvailableTokens, addTokens);
      }
    }
    Sleep(interval);
  }
  return 0;
}

/* 异步清理线程：处理复制失败后的文件删除，不阻塞 Copier 线程 */
unsigned __stdcall CleanupThread(void *pParam) {
  UNREFERENCED_PARAMETER(pParam);
  while (g_CleanupThreadRunning) {
    PSLIST_ENTRY pList = InterlockedFlushSList(g_CleanupQueue);
    if (!pList) {
      WaitForSingleObject(g_hCleanupEvent, 1000);
      if (!g_CleanupThreadRunning && QueryDepthSList(g_CleanupQueue) == 0)
        break;
      continue;
    }
    PSLIST_ENTRY pCurr = pList;
    while (pCurr) {
      PSLIST_ENTRY pNext = pCurr->Next;
      CleanupTask *t = (CleanupTask *)pCurr;
      if (t->Path) {
        DeleteFileW(t->Path);
        free(t->Path);
        t->Path = NULL;
      }
      InterlockedPushEntrySList(g_CleanupPool, &t->ItemEntry);
      pCurr = pNext;
    }
  }
  return 0;
}

void RequestAsyncCleanup(const wchar_t *path) {
  CleanupTask *t = NULL;
  int retries = 0;
  while (!t) {
    if (IsCanceling() || retries >= OOM_RETRY_MAX) {
      LogMessage(LOG_WARNING, L"[RequestAsyncCleanup] OOM/cancel, path not queued: %ls\n", path);
      return;
    }
    if (g_CleanupPool) {
      PSLIST_ENTRY e = InterlockedPopEntrySList(g_CleanupPool);
      t = e ? (CleanupTask *)e : NULL;
    }
    if (!t)
      t = (CleanupTask *)_aligned_malloc(sizeof(CleanupTask), 16);
    if (!t) {
      Sleep(10);
      retries++;
    }
  }
  t->Path = _wcsdup(path);
  if (t->Path) {
    InterlockedPushEntrySList(g_CleanupQueue, &t->ItemEntry);
    SetEvent(g_hCleanupEvent);
  } else {
    LogMessage(LOG_WARNING, L"[RequestAsyncCleanup] _wcsdup failed, path not "
                            L"queued for cleanup: %ls\n", path);
    InterlockedPushEntrySList(g_CleanupPool, &t->ItemEntry);
  }
}

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

/* Win10+ ConPTY：stdout 常为 Pipe，GetConsoleScreenBufferInfo(STD_OUTPUT) 失败时用 CONOUT$。
 * [RUN] 必须用 dwCursorPosition.Y（光标真实行）清行重写；勿用 srWindow.Bottom（视口底行会留空/错位），
 * 勿 Y+1（会触发滚动导致刷屏）。管道/GUI 捕获时无屏幕缓冲，fallback 必须带 \r。 */
static HANDLE g_hConsoleOutForScreen = NULL;
static BOOL g_triedOpenConout = FALSE;

static HANDLE ResolveConsoleScreenHandle(void) {
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
  if (h && h != INVALID_HANDLE_VALUE && GetConsoleScreenBufferInfo(h, &csbi))
    return h;
  if (!g_triedOpenConout) {
    g_triedOpenConout = TRUE;
    h = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_EXISTING, 0, NULL);
    g_hConsoleOutForScreen = (h != INVALID_HANDLE_VALUE) ? h : NULL;
  }
  if (g_hConsoleOutForScreen && GetConsoleScreenBufferInfo(g_hConsoleOutForScreen, &csbi))
    return g_hConsoleOutForScreen;
  return NULL;
}

/* [RUN]：当前光标行清空后重写，光标回行首；p 已去掉前导 \r */
static void ConsoleWriteRunStatusLine(const wchar_t *msg) {
  const wchar_t *p = msg;
  if (!p)
    return;
  if (p[0] == L'\r')
    p++;

  HANDLE hOut = ResolveConsoleScreenHandle();
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  if (!hOut || !GetConsoleScreenBufferInfo(hOut, &csbi)) {
    /* 管道/重定向到文件时 \r 无法清行，子进程日志会粘成 [RUN]...[RUN]...；仅真控制台用 \r */
    HANDLE hStd = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD ft = (hStd && hStd != INVALID_HANDLE_VALUE) ? GetFileType(hStd) : FILE_TYPE_UNKNOWN;
    if (ft == FILE_TYPE_CHAR)
      wprintf(L"\r%s", p);
    else
      /* 管道模式下每次进度都输出独立完整行，避免与下一条日志粘连 */
      wprintf(L"\n%s\n", p);
    fflush(stdout);
    return;
  }

  SHORT y = csbi.dwCursorPosition.Y;
  COORD pos = {0, y};
  DWORD width = (DWORD)csbi.dwSize.X;
  if (width == 0 || width > 16384)
    width = 120;
  DWORD n;
  FillConsoleOutputCharacterW(hOut, L' ', width, pos, &n);
  FillConsoleOutputAttribute(hOut, csbi.wAttributes, width, pos, &n);
  SetConsoleCursorPosition(hOut, pos);
  if (p[0]) {
    DWORD m = (DWORD)wcslen(p);
    if (m >= width)
      m = width - 1;
    WriteConsoleW(hOut, p, m, &n, NULL);
  }
  pos.X = 0;
  pos.Y = y;
  SetConsoleCursorPosition(hOut, pos);
}

unsigned __stdcall LogThread(void *pParam) {
  UNREFERENCED_PARAMETER(pParam);
  while (g_LogThreadRunning || QueryDepthSList(g_LogQueue) > 0) {
    PSLIST_ENTRY pList = InterlockedFlushSList(g_LogQueue);
    if (!pList) {
      if (!g_LogThreadRunning && QueryDepthSList(g_LogQueue) == 0)
        break;
      WaitForSingleObject(g_hLogEvent, g_LogThreadRunning ? 500 : 100);
      continue;
    }
    PSLIST_ENTRY pPrev = NULL, pCurr = pList, pNext;
    while (pCurr) {
      pNext = pCurr->Next;
      pCurr->Next = pPrev;
      pPrev = pCurr;
      pCurr = pNext;
    }
    pCurr = pPrev;
    EnterCriticalSection(&g_LogCs);
    int suppressStdout = (g_pTelemetryShared && g_Config.ParentPid != 0);
    while (pCurr) {
      LogEntry *entry = (LogEntry *)pCurr;
      if (entry->isRaw == 1) {  /* 1=raw error; 0=fmt, 2=Stats 均走 fmt 分支 */
        const wchar_t *fmts[] = {
          L"\n[ERR] FAILED (Err: %lu): %ls\n",
          L"\n[DLQ] FAILED after slow retry (Err: %lu): %ls\n",
          L"\n[DLQ] FAILED after concurrent retry (Err: %lu): %ls\n",
          L"\n[ERR] FAILED (IoRing & Fallback) (Err: %lu): %ls\n"
        };
        int t = entry->u.raw.rawType;
        if (t < 0 || t > 3) t = 0;
        /* Round5 P2-Bug5：pathLen<900 用栈 buf，否则堆分配，避免 1024 静默截断超长路径 */
        size_t pathLen = entry->u.raw.path ? wcslen(entry->u.raw.path) : 0;
        wchar_t *buf = NULL;
        wchar_t stackBuf[1024];
        if (pathLen < 900) {
          StringCchPrintfW(stackBuf, 1024, fmts[t], (unsigned long)entry->u.raw.errCode,
                          entry->u.raw.path ? entry->u.raw.path : L"");
          buf = stackBuf;
        } else {
          size_t needed = pathLen + 128;
          buf = (wchar_t *)malloc(needed * sizeof(wchar_t));
          if (buf) {
            StringCchPrintfW(buf, (size_t)needed, fmts[t], (unsigned long)entry->u.raw.errCode,
                            entry->u.raw.path ? entry->u.raw.path : L"");
          } else {
            /* OOM：回退栈 buf，StringCchPrintfW 会截断，至少保留审计线索 */
            StringCchPrintfW(stackBuf, 1024, fmts[t], (unsigned long)entry->u.raw.errCode,
                            entry->u.raw.path ? entry->u.raw.path : L"");
            buf = stackBuf;
          }
        }
        if (g_pLogRing) LogRingWrite((uint16_t)entry->u.raw.level, buf);
        else if (!suppressStdout) {
          HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);
          if (hCon && hCon != INVALID_HANDLE_VALUE && GetFileType(hCon) == FILE_TYPE_CHAR) {
            DWORD nw = 0;
            WriteConsoleW(hCon, buf, (DWORD)wcslen(buf), &nw, NULL);
          } else wprintf(L"%s", buf);
        }
        FILE *f = (entry->u.raw.level == (int)LOG_ERROR) ? g_fErrorLog : g_fNormalLog;
        if (f) fputws(buf, f);
        if (buf != stackBuf) free(buf);
      } else {
        /* isRaw==0 或 2(Stats)：统一按 fmt 输出 */
        if (g_pLogRing) LogRingWrite((uint16_t)entry->u.fmt.level, entry->u.fmt.msg);
        else if (!suppressStdout) {
          /* Stats(isRaw==2)：CONOUT$/VT 单行刷新，勿依赖 FILE_TYPE_CHAR（ConPTY 下 stdout 常为 Pipe） */
          HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);
          if (entry->isRaw == 2) {
            ConsoleWriteRunStatusLine(entry->u.fmt.msg);
          } else if (hCon && hCon != INVALID_HANDLE_VALUE && GetFileType(hCon) == FILE_TYPE_CHAR) {
            DWORD nw = 0;
            WriteConsoleW(hCon, entry->u.fmt.msg, (DWORD)wcslen(entry->u.fmt.msg), &nw, NULL);
          } else {
            wprintf(L"%s", entry->u.fmt.msg);
            if (entry->u.fmt.msg[0] == L'\r')
              fflush(stdout);
          }
        }
        FILE *f = (entry->u.fmt.level == LOG_ERROR) ? g_fErrorLog : g_fNormalLog;
        // 【核心修改】：如果它是刷屏的进度条(isRaw == 2)，就跳过，绝不写入日志文件！
        if (f && entry->isRaw != 2)
          fputws(entry->u.fmt.msg, f);
      }
      pNext = pCurr->Next;
      /* Round4 P1 Bug1：raw 条目的 path 为堆指针，归还池前必须释放，防止内存泄漏 */
      if (entry->isRaw == 1) {
        free(entry->u.raw.path);
        entry->u.raw.path = NULL;
      }
      if (entry->isRaw == 2 && g_StatsEntryPool)
        InterlockedPushEntrySList(g_StatsEntryPool, &(entry->ItemEntry));
      else if (g_LogEntryPool)
        InterlockedPushEntrySList(g_LogEntryPool, &(entry->ItemEntry));
      else
        PB_ALIGNED_FREE(entry);
      pCurr = pNext;
    }
    /* V8：池空丢弃审计——在批次处理完后追加 dropped N 提示，保留审计线索 */
    {
      LONG dropped = InterlockedExchange(&s_LogDropCount, 0);
      if (dropped > 0) {
        wchar_t dropBuf[128];
        StringCchPrintfW(dropBuf, 128, L"... [WARN] Too many logs, dropped %ld messages.\n", (long)dropped);
        if (g_pLogRing) LogRingWrite((uint16_t)LOG_WARNING, dropBuf);
        else if (!suppressStdout) wprintf(L"%s", dropBuf);
        if (g_fNormalLog) fputws(dropBuf, g_fNormalLog);
      }
    }
    /* 批量刷新：整批 fputws 后统一 fflush，避免每条日志触发同步落盘 */
    if (g_fNormalLog)
      fflush(g_fNormalLog);
    if (g_fErrorLog)
      fflush(g_fErrorLog);
    LeaveCriticalSection(&g_LogCs);
  }
  return 0;
}

#define SPEED_HISTORY_SIZE 10
void PrintStats(int force) {
  if (!g_bTelemetryEnabled && !g_Config.RealTimeStats) return;  /* Zero-Cost Headless */
  static DWORD lastTick = 0;
  static double lastElapsed = 0;
  static LONG64 lastBytes = 0;
  static double speedHistory[SPEED_HISTORY_SIZE];
  static int speedHistoryCount = 0;
  static int speedHistoryIdx = 0;
  DWORD currentTick = GetTickCount();
  if (!force && (currentTick - lastTick < (DWORD)g_Config.RefreshInterval))
    return;

  /* P3：RealTimeStats 读 OsTelemetryThread 缓存，零 PDH 调用 */
  DWORD diskQ = g_Config.RealTimeStats ? g_CachedDiskQueue : 0;
  LARGE_INTEGER now;
  QueryPerformanceCounter(&now);
  double totalElapsed =
      (double)(now.QuadPart - g_StartTime.QuadPart) / g_Freq.QuadPart;
  if (totalElapsed <= 0)
    totalElapsed = 0.001;
  LONG64 totalBytes = g_NumThreadBuckets > 0 ? SumBucketBytes() : READ_VOLATILE_64(&g_TotalBytes);
  LONG64 totalFoundBytes = READ_VOLATILE_64(&g_TotalFoundBytes);
  LONG totalCopied = g_NumThreadBuckets > 0 ? SumBucketCopied() : READ_VOLATILE_32(&g_TotalCopied);
  LONG totalFailed = READ_VOLATILE_32(&g_TotalFailed);
  LONG totalDone = totalCopied + totalFailed;
  LONG found = READ_VOLATILE_32(&g_TotalFound);
  LONG vSuccess = READ_VOLATILE_32(&g_Md5Success);
  LONG vFail = READ_VOLATILE_32(&g_Md5Fail);

  double speedMB = 0;
  if (totalElapsed - lastElapsed > 0.1) {
    speedMB = (double)(totalBytes - lastBytes) / (1024.0 * 1024.0) /
              (totalElapsed - lastElapsed);
    if (speedMB < 0)
      speedMB = 0;
    speedHistory[speedHistoryIdx] = speedMB;
    speedHistoryIdx = (speedHistoryIdx + 1) % SPEED_HISTORY_SIZE;
    if (speedHistoryCount < SPEED_HISTORY_SIZE)
      speedHistoryCount++;
  }
  lastTick = currentTick;
  lastElapsed = totalElapsed;
  lastBytes = totalBytes;

  /* 滑动窗口 EMA：去最高最低取平均 */
  double smoothedMB = speedMB;
  if (speedHistoryCount >= 3) {
    double minV = speedHistory[0], maxV = speedHistory[0], sum = 0;
    for (int i = 0; i < speedHistoryCount; i++) {
      if (speedHistory[i] < minV) minV = speedHistory[i];
      if (speedHistory[i] > maxV) maxV = speedHistory[i];
      sum += speedHistory[i];
    }
    smoothedMB = (sum - minV - maxV) / (speedHistoryCount - 2);
    if (smoothedMB < 0) smoothedMB = 0;
  }

  /* 已耗时（始终显示）*/
  int elapsedSec = (int)totalElapsed;
  int elH = elapsedSec / 3600, elM = (elapsedSec % 3600) / 60, elS = elapsedSec % 60;

  /* 动态限速：GUI 写入 cmd_SpeedLimit，V10 由 TokenBucketThread 唯一读取 isDirty 并更新 s_cached_* */
#if USE_SHM_TELEMETRY
  if (g_pTelemetryShared) {
    uint32_t targetMB = s_cached_SpeedLimit;
    LONGLONG newBps = (LONGLONG)targetMB * 1024 * 1024;
    if (newBps != READ_VOLATILE_64(&g_SpeedLimitBps)) {
      InterlockedExchange64((volatile LONGLONG *)&g_SpeedLimitBps, newBps);
      if (targetMB > 0 && !g_hTokenThread) {
        InterlockedExchange(&g_TokenThreadRunning, 1);
        g_hTokenThread = (HANDLE)_beginthreadex(NULL, 0, TokenBucketThread, NULL, 0, NULL);
        if (!g_hTokenThread) InterlockedExchange(&g_TokenThreadRunning, 0);
      }
    }
  }
#endif

  /* 二进制 IPC 遥测：向 GUI 发送（SHM 或管道）；Headless 时跳过 */
  if (g_bTelemetryEnabled) {
#if USE_SHM_TELEMETRY
  if (g_pTelemetryShared) {
#else
  if (g_hTelemetryPipe != INVALID_HANDLE_VALUE) {
#endif
    TelemetryData td = {0};
    td.magic = TELEMETRY_MAGIC;
    td.totalFiles = (uint64_t)found;
    td.copiedFiles = (uint64_t)totalCopied;
    td.totalBytes = (uint64_t)totalFoundBytes;
    td.copiedBytes = (uint64_t)totalBytes;
    td.currentSpeedMBps = (uint32_t)(smoothedMB + 0.5);
    td.activeThreads = (uint32_t)g_ActiveCopierLimit;
    td.isFinished = 0;
    td.version = TELEMETRY_PROTOCOL_VERSION;
#if USE_SHM_TELEMETRY
    td.ack_SpeedLimit = (uint8_t)(s_cached_SpeedLimit > 255 ? 255 : s_cached_SpeedLimit);
    td.ack_Pause = (uint8_t)s_cached_Pause;
#else
    td.ack_SpeedLimit = 0;
    td.ack_Pause = 0;
#endif
    /* Round4 Single Source of Truth：失败计数直接来自引擎原子变量，GUI 无需文本解析 */
    td.failedFiles = (uint32_t)READ_VOLATILE_32(&g_TotalFailed);
    td.io_block_clone = (uint64_t)READ_VOLATILE_64(&g_IoStrategyStats[IOSTRAT_BLOCK_CLONE]);
    td.io_direct_big = (uint64_t)READ_VOLATILE_64(&g_IoStrategyStats[IOSTRAT_BIG_DIRECT_IO]);
    td.io_buffered_big = (uint64_t)READ_VOLATILE_64(&g_IoStrategyStats[IOSTRAT_BIG_BUFFERED]);
    /* Phase 3 ETA：剩余秒数，progress 在 (0.1, 100) 时计算 */
    if (totalFoundBytes > 0 && totalBytes < totalFoundBytes) {
      double progress = (double)totalBytes / (double)totalFoundBytes * 100.0;
      if (progress > 0.1 && progress < 100.0) {
        double eta = (double)totalElapsed * (100.0 - progress) / progress;
        if (eta > 0 && eta < 86400.0 * 365.0)
          td.eta_seconds = (uint32_t)(eta + 0.5);
      }
    }
    BroadcastTelemetry(&td);
  }
  }

  /* V7：解耦 g_LogCs，进度行投递到 g_LogQueue 由 LogThread 输出，避免主循环持锁阻塞 */
  LONG queued = READ_VOLATILE_32(&g_PendingCopyTasks);
  LONG dlqDepth = g_DeadLetterQueue ? (LONG)QueryDepthSList(g_DeadLetterQueue) : 0;
  int suppressStdout = 0;
#if USE_SHM_TELEMETRY
  if (g_pTelemetryShared && g_Config.ParentPid != 0)
    suppressStdout = 1;
#else
  if (g_hTelemetryPipe != INVALID_HANDLE_VALUE && g_Config.ParentPid != 0)
    suppressStdout = 1;
#endif
  /* GUI 模式(suppressStdout)下若有 LogRing 仍需投递进度行，供 Python 实时日志显示 */
  if (g_Config.RealTimeStats && (!suppressStdout || g_pLogRing) && g_LogQueue && g_hLogEvent) {
    double progress;
    if (totalFoundBytes > 0) {
      progress = (double)totalBytes / (double)totalFoundBytes;
      if (progress > 1.0) progress = 1.0;
    } else {
      progress = (found > 0) ? (double)totalDone / found : 0.0;
      if (progress > 1.0) progress = 1.0;
    }
    /* V8：PrintStats 专用小池，与 LogEntry 池解耦，确保进度行不受日志洪峰影响 */
    LogEntry *e = NULL;
    if (g_StatsEntryPool) {
      PSLIST_ENTRY ep = InterlockedPopEntrySList(g_StatsEntryPool);
      if (ep) e = (LogEntry *)ep;
    }
    if (!e) return;  /* 4 Slot 均在飞行中则跳过本次刷新，33ms 后重试 */
    e->isRaw = 2;  /* 2=Stats，LogThread 归还到 g_StatsEntryPool */
    e->u.fmt.level = LOG_INFO;
    if (g_Config.CompareContent) {
      if (g_Config.AuditOnly) {
        StringCchPrintfW(e->u.fmt.msg, 1024,
          L"\r[RUN] Q:%-6ld | DLQ:%-6ld | Done:%-7ld | Verified:%-7ld | %-5.1f MB/s | DiskQ:%-2ld | "
          L"V:%ld/%ld | SSD:%c | %.1f%% | Elapsed %02d:%02d:%02d   ",
          queued, dlqDepth, totalDone, totalCopied, smoothedMB, diskQ, vSuccess, vFail,
          g_Config.IsSSD ? 'Y' : 'N', progress * 100.0, elH, elM, elS);
      } else {
        StringCchPrintfW(e->u.fmt.msg, 1024,
          L"\r[RUN] Q:%-6ld | DLQ:%-6ld | Done:%-7ld | Copied:%-7ld | %-5.1f MB/s | DiskQ:%-2ld | "
          L"V:%ld/%ld | SSD:%c | %.1f%% | Elapsed %02d:%02d:%02d   ",
          queued, dlqDepth, totalDone, totalCopied, smoothedMB, diskQ, vSuccess, vFail,
          g_Config.IsSSD ? 'Y' : 'N', progress * 100.0, elH, elM, elS);
      }
    } else {
      if (g_Config.AuditOnly) {
        StringCchPrintfW(e->u.fmt.msg, 1024,
          L"\r[RUN] Q:%-6ld | DLQ:%-6ld | Done:%-7ld | Verified:%-7ld | %-5.1f MB/s | DiskQ:%-2ld | "
          L"SSD:%c | %.1f%% | Elapsed %02d:%02d:%02d   ",
          queued, dlqDepth, totalDone, totalCopied, smoothedMB, diskQ, g_Config.IsSSD ? 'Y' : 'N',
          progress * 100.0, elH, elM, elS);
      } else {
        StringCchPrintfW(e->u.fmt.msg, 1024,
          L"\r[RUN] Q:%-6ld | DLQ:%-6ld | Done:%-7ld | Copied:%-7ld | %-5.1f MB/s | DiskQ:%-2ld | "
          L"SSD:%c | %.1f%% | Elapsed %02d:%02d:%02d   ",
          queued, dlqDepth, totalDone, totalCopied, smoothedMB, diskQ, g_Config.IsSSD ? 'Y' : 'N',
          progress * 100.0, elH, elM, elS);
      }
    }
    InterlockedPushEntrySList(g_LogQueue, &e->ItemEntry);
    SetEvent(g_hLogEvent);
	// 【核心修改】：如果是复制结束时的最后一次调用 (force 为真)，强制向日志文件特批写入一行！
    if (force && g_fNormalLog) {
        EnterCriticalSection(&g_LogCs);
        fputws(e->u.fmt.msg, g_fNormalLog);
        fputws(L"\n", g_fNormalLog); // 强制换行，以免和后面的 --- COMPLETED --- 粘在一起
        fflush(g_fNormalLog);
        LeaveCriticalSection(&g_LogCs);
    }
  }
}

void FlushLocalCounters(CopierParam *param, BOOL force) {
  /* 未达门槛时直接返回，斩断 GetTickCount 等多余指令，消除千万次 Syscall 放大 */
  if (!force && param->LocalCopied < FLUSH_COUNT_THRESHOLD &&
      param->LocalBytes < (5 * 1024 * 1024))
    return;
  DWORD now = GetTickCount();
  BOOL timeToFlush = (now - param->LastFlushTick >= FLUSH_TIME_MS);
  if (force || param->LocalCopied >= FLUSH_COUNT_THRESHOLD ||
      param->LocalBytes >= (5 * 1024 * 1024) ||
      (timeToFlush && (param->LocalCopied > 0 || param->LocalBytes > 0))) {
    if (param->LocalCopied > 0)
      AddBucketCopied(param, param->LocalCopied);
    if (param->LocalBytes > 0)
      AddBucketBytes(param, param->LocalBytes);
    param->LocalCopied = 0;
    param->LocalBytes = 0;
    if (param->LocalSmallFiles > 0) {
      InterlockedExchangeAdd(&g_SmallFiles, param->LocalSmallFiles);
      param->LocalSmallFiles = 0;
    }
    if (param->LocalMediumFiles > 0) {
      InterlockedExchangeAdd(&g_MediumFiles, param->LocalMediumFiles);
      param->LocalMediumFiles = 0;
    }
    if (param->LocalLargeFiles > 0) {
      InterlockedExchangeAdd(&g_LargeFiles, param->LocalLargeFiles);
      param->LocalLargeFiles = 0;
    }
    param->LastFlushTick = now;
  }
}

/* 滑动窗口：基于增量感知瞬时路况，避免历史大文件稀释导致 HDD 节流阀失效 */
void UpdateSmallFileRatio(void) {
  static LONG s_LastTotal = 0;
  static LONG s_LastSmall = 0;

  LONG currentTotal = g_NumThreadBuckets > 0 ? SumBucketCopied() : READ_VOLATILE_32(&g_TotalCopied);
  LONG currentSmall = READ_VOLATILE_32(&g_SmallFiles);

  LONG deltaTotal = currentTotal - s_LastTotal;
  LONG deltaSmall = currentSmall - s_LastSmall;

  if (deltaTotal > 500) {
    InterlockedExchange(&g_SmallFileRatio,
                        (LONG)(deltaTotal > 0 ? ((LONG64)deltaSmall * 100) / deltaTotal : 0));
    s_LastTotal = currentTotal;
    s_LastSmall = currentSmall;
  }
}


/* 稀疏文件复制：仅复制已分配区间，复用 BigBufferPool，支持 ERROR_MORE_DATA
 * 调用方 ProcessTask 已持 g_hBigFileSemaphore，此处不再获取
 * param/outHash 非空且 -X 时边拷边算 Hash，砍掉二次读取的 I/O 放大 */
BOOL CopySparseFile(const wchar_t *src, const wchar_t *dst, LONGLONG fileSize,
                    CopierParam *param, BYTE *outHash) {
  HANDLE hSrc = CreateFileW(src, GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            NULL, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
                            NULL);
  if (hSrc == INVALID_HANDLE_VALUE)
    return FALSE;
  /* OPT-05: 分块迭代查询，支持数十万碎片的 SQL .mdf/.dbf，不再 4MB 上限回退全量拷贝
   * 固定 64KB 输出缓冲（512 区间/块），ERROR_MORE_DATA 时缩小输入范围而非扩容 */
#define SPARSE_BUF_RANGES 512
  DWORD bufSize = SPARSE_BUF_RANGES * sizeof(FILE_ALLOCATED_RANGE_BUFFER);
  FILE_ALLOCATED_RANGE_BUFFER *outRanges =
      (FILE_ALLOCATED_RANGE_BUFFER *)malloc(bufSize);
  if (!outRanges) {
    CloseHandle(hSrc);
    return FALSE;
  }
  /* 收集所有区间的动态数组，用于后续拷贝循环 */
  FILE_ALLOCATED_RANGE_BUFFER *allRanges = NULL;
  int allCap = 0, allCount = 0;
  LONGLONG queryOffset = 0;
  LONGLONG queryLen = fileSize;
  BOOL isNonSparse = FALSE;
  while (queryOffset < fileSize) {
    FILE_ALLOCATED_RANGE_BUFFER inRange = {{0}, {0}};
    inRange.FileOffset.QuadPart = queryOffset;
    inRange.Length.QuadPart = queryLen;
    DWORD bytesReturned = 0;
    if (DeviceIoControl(hSrc, FSCTL_QUERY_ALLOCATED_RANGES, &inRange,
                        sizeof(inRange), outRanges, bufSize, &bytesReturned,
                        NULL)) {
      int numRanges = bytesReturned / (int)sizeof(FILE_ALLOCATED_RANGE_BUFFER);
      LONGLONG allocated = 0;
      for (int j = 0; j < numRanges; j++)
        allocated += outRanges[j].Length.QuadPart;
      if (numRanges > 0 && allocated >= fileSize) {
        isNonSparse = TRUE;
        break;
      }
      if (numRanges > 0) {
        if (allCount + numRanges > allCap) {
          int newCap = (allCap == 0) ? 1024 : allCap * 2;  /* P3 预分配 1024，减少 realloc */
          while (newCap < allCount + numRanges) newCap *= 2;
          FILE_ALLOCATED_RANGE_BUFFER *np = (FILE_ALLOCATED_RANGE_BUFFER *)
              realloc(allRanges, (size_t)newCap * sizeof(FILE_ALLOCATED_RANGE_BUFFER));
          if (!np) {
            LogMessage(LOG_WARNING, L"[CopySparse] realloc failed at %d ranges, aborting\n", allCount);
            break;
          }
          allRanges = np;
          allCap = newCap;
        }
        memcpy(allRanges + allCount, outRanges, (size_t)numRanges * sizeof(FILE_ALLOCATED_RANGE_BUFFER));
        allCount += numRanges;
        LONGLONG lastEnd = outRanges[numRanges - 1].FileOffset.QuadPart +
            outRanges[numRanges - 1].Length.QuadPart;
        queryOffset = lastEnd;
      } else {
        queryOffset = fileSize;
      }
      queryLen = fileSize - queryOffset;
    } else {
      if (GetLastError() != ERROR_MORE_DATA) break;
      queryLen = queryLen / 2;
      if (queryLen < 65536) break; /* 64KB 内仍超 512 区间，极罕见，放弃 */
    }
  }
  free(outRanges); /* 释放临时查询缓冲 */
  if (isNonSparse || allCount == 0 || queryOffset < fileSize) {
    if (allRanges) free(allRanges);
    CloseHandle(hSrc);
    return FALSE;
  }
  int numRanges = allCount;
  outRanges = allRanges;
  HANDLE hDst = OpenDstFileWithNtApi(param, dst, GENERIC_WRITE, 0, CREATE_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY |
                                    FILE_FLAG_BACKUP_SEMANTICS, 0);
  if (hDst == INVALID_HANDLE_VALUE) {
    free(outRanges);
    CloseHandle(hSrc);
    return FALSE;
  }
  DWORD dummy;
  DeviceIoControl(hDst, FSCTL_SET_SPARSE, NULL, 0, NULL, 0, &dummy, NULL);
  LARGE_INTEGER li;
  li.QuadPart = fileSize;
  SetFilePointerEx(hDst, li, NULL, FILE_BEGIN);
  SetEndOfFile(hDst);
  PSLIST_ENTRY entry = InterlockedPopEntrySList(g_BigBufferPool);
  BigBufferObj *bufObj = entry ? (BigBufferObj *)entry : NULL;
  DWORD copyBufSize = bufObj ? g_BigBufferSize : 1024 * 1024;
  BYTE *buf = bufObj ? bufObj->Buffer : (BYTE *)malloc(copyBufSize);
  if (!buf) {
    free(outRanges);
    CloseHandle(hSrc);
    CloseHandle(hDst);
    return FALSE;
  }
  /* 稀疏文件边拷边算：支持 XXH3 与 MD5(-D)，避免拷贝后整文件重读算哈希 */
  BOOL doHash = (param && outHash && g_Config.CompareContent);
  XXH3_state_t *state = NULL;
  HCRYPTPROV hProv = 0;
  HCRYPTHASH hHash = 0;
  if (doHash) {
    if (g_Config.UseXxh3 && param->Xxh3State) {
      state = param->Xxh3State;
      if (XXH3_128bits_reset(state) != XXH_OK)
        doHash = FALSE;
    } else if (!g_Config.UseXxh3) {
      if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL,
                                CRYPT_VERIFYCONTEXT) ||
          !CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
        doHash = FALSE;
    } else
      doHash = FALSE;
  }
  LONGLONG hashPos = 0;

  BOOL success = TRUE;
  LONGLONG totalWrittenLocally = 0;
  LONGLONG totalFlushedToGlobal = 0;
  for (int i = 0; i < numRanges && success; i++) {
    if (IsCanceling()) {
      success = FALSE;
      break;
    }
    if (doHash) {
      LONGLONG gap = outRanges[i].FileOffset.QuadPart - hashPos;
      while (gap > 0 && success) {
        size_t chunk = (size_t)min(gap, 1024 * 1024);
        if (state) {
          if (XXH3_128bits_update(state, g_ZeroBuffer, chunk) != XXH_OK)
            success = FALSE;
        } else {
          if (!CryptHashData(hHash, (BYTE *)g_ZeroBuffer, (DWORD)chunk, 0))
            success = FALSE;
        }
        if (success) {
          hashPos += chunk;
          gap -= chunk;
        }
      }
    }
    LONGLONG len = outRanges[i].Length.QuadPart;
    SetFilePointerEx(hSrc, outRanges[i].FileOffset, NULL, FILE_BEGIN);
    SetFilePointerEx(hDst, outRanges[i].FileOffset, NULL, FILE_BEGIN);
    while (len > 0 && success) {
      if (IsCanceling()) {
        success = FALSE;
        break;
      }
      DWORD toDo = (DWORD)min(len, copyBufSize);
      DWORD rd, wr;
      AcquireBandwidthTokens((LONGLONG)toDo);
      /* Phase 17 无分支累积：XOR 替代条件跳转，Happy Path 零气泡 */
      {
        UINT64 errMask = 0;
        errMask |= (ReadFileWithReduce(hSrc, buf, toDo, &rd) ? 0 : 1) | (UINT64)(rd ^ toDo);
        if (errMask) { success = FALSE; break; }
        errMask |= (WriteFileWithReduce(hDst, buf, toDo, &wr) ? 0 : 1) | (UINT64)(wr ^ toDo);
        if (errMask) { success = FALSE; break; }
      }
      {
        if (doHash) {
          if (state) {
            if (XXH3_128bits_update(state, buf, rd) != XXH_OK)
              success = FALSE;
          } else if (!CryptHashData(hHash, buf, rd, 0))
            success = FALSE;
        }
        if (success) {
          if (doHash)
            hashPos += rd;
          len -= toDo;
          totalWrittenLocally += toDo;
          if (totalWrittenLocally >= PROGRESSIVE_FLUSH_MB * (1024 * 1024)) {
            LONGLONG toFlush =
                (totalWrittenLocally / (PROGRESSIVE_FLUSH_MB * 1024 * 1024)) *
                (PROGRESSIVE_FLUSH_MB * 1024 * 1024);
            if (toFlush > 0) {
              AddBucketBytes(param, toFlush);
              totalFlushedToGlobal += toFlush;
              totalWrittenLocally -= toFlush;
            }
          }
        }
      }
    }
    if (doHash)
      hashPos = outRanges[i].FileOffset.QuadPart + outRanges[i].Length.QuadPart;
  }
  if (!success && totalFlushedToGlobal > 0)
    AddBucketBytes(param, -totalFlushedToGlobal);
  if (doHash && success) {
    LONGLONG gap = fileSize - hashPos;
    while (gap > 0) {
      size_t chunk = (size_t)min(gap, 1024 * 1024);
      if (state) {
        if (XXH3_128bits_update(state, g_ZeroBuffer, chunk) != XXH_OK) {
          success = FALSE;
          break;
        }
      } else if (!CryptHashData(hHash, (BYTE *)g_ZeroBuffer, (DWORD)chunk, 0)) {
        success = FALSE;
        break;
      }
      hashPos += chunk;
      gap -= chunk;
    }
    if (success) {
      if (state) {
        XXH128_hash_t h = XXH3_128bits_digest(state);
        memcpy(outHash, &h.low64, 8);
        memcpy(outHash + 8, &h.high64, 8);
      } else {
        DWORD hLen = 16;
        CryptGetHashParam(hHash, HP_HASHVAL, outHash, &hLen, 0);
      }
    }
  }
  if (hHash)
    CryptDestroyHash(hHash);
  if (hProv)
    CryptReleaseContext(hProv, 0);
  if (bufObj)
    InterlockedPushEntrySList(g_BigBufferPool, &bufObj->ItemEntry);
  else
    free(buf);
  free(allRanges);
  CloseHandle(hSrc);
  CloseHandle(hDst);
  if (success && totalWrittenLocally > 0)
    AddBucketBytes(param, totalWrittenLocally);
  return success;
}

/* 小文件复制：VFS 全协议（本地/SFTP 接入后），集成 MD5/XXH3；param 提供 Xxh3State
 * Phase 12：srcBack/dstBack 非 NULL 时直接使用，否则 VFS_GetBackend，消除热路径 wcsncmp */
BOOL CopySmallFile(const wchar_t *src, const wchar_t *dst, LONGLONG fileSize,
                   CopierParam *param, const IO_BACKEND *srcBack, const IO_BACKEND *dstBack,
                   const CopyTask *taskMeta) {
  if (!srcBack) srcBack = VFS_GetBackend(src);
  if (!dstBack) dstBack = VFS_GetBackend(dst);
  if (!srcBack || !dstBack)
    return FALSE;

  IO_HANDLE hSrc = srcBack->Open(src, IO_MODE_READ, FALSE);
  IO_HANDLE hDst;
  if (dstBack == &g_VFS_LocalBackend && param && g_NtCreateFile)
    hDst = (IO_HANDLE)OpenDstFileWithNtApi(param, dst, GENERIC_WRITE, 0, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_SEQUENTIAL_SCAN |
        FILE_FLAG_BACKUP_SEMANTICS, 0);
  else
    hDst = dstBack->Open(dst, IO_MODE_WRITE_CREATE, FALSE);
  if (hSrc == IO_HANDLE_INVALID || hDst == IO_HANDLE_INVALID) {
    if (hSrc != IO_HANDLE_INVALID) srcBack->Close(hSrc);
    if (hDst != IO_HANDLE_INVALID) dstBack->Close(hDst);
    return FALSE;
  }

  /* 复用 HashBuffer(1MB) 或 malloc(64KB)，动态块大小消除 Syscall 雪崩 */
  BYTE *buf = (param && param->HashBuffer) ? param->HashBuffer : NULL;
  BOOL ownBuf = (buf == NULL);
  DWORD bufSize = ownBuf ? 65536 : (1024 * 1024);
  if (ownBuf) {
    buf = (BYTE *)malloc(bufSize);
    if (!buf) {
      srcBack->Close(hSrc);
      dstBack->Close(hDst);
      return FALSE;
    }
  }
  DWORD rd, wr;
  BOOL s = TRUE;
  BOOL readSuccess = TRUE;
  BYTE srcHash[16];

  if (g_Config.CompareContent) {
    if (g_Config.UseXxh3) {
      XXH3_state_t *state = (param && param->Xxh3State) ? param->Xxh3State : XXH3_createState();
      if (!state) {
        if (ownBuf) free(buf);
        srcBack->Close(hSrc);
        dstBack->Close(hDst);
        return FALSE;
      }
      if (XXH3_128bits_reset(state) != XXH_OK) {
        if (!param || !param->Xxh3State)
          XXH3_freeState(state);
        if (ownBuf) free(buf);
        srcBack->Close(hSrc);
        dstBack->Close(hDst);
        return FALSE;
      }
      while (s) {
        if (IsCanceling()) {
          s = FALSE;
          SetLastError(ERROR_OPERATION_ABORTED);
          break;
        }
        if (!srcBack->Read(hSrc, buf, bufSize, &rd)) {
          readSuccess = FALSE;
          s = FALSE;
          break;
        }
        if (rd == 0)
          break;
        AcquireBandwidthTokens((LONGLONG)rd);
        if (XXH3_128bits_update(state, buf, rd) != XXH_OK) {
          s = FALSE;
          break;
        }
        if (!WriteFileWithReduce(hDst, buf, rd, &wr) || wr != rd) {
          s = FALSE;
          break;
        }
      }
      if (s && readSuccess) {
        XXH128_hash_t h = XXH3_128bits_digest(state);
        memcpy(srcHash, &h.low64, 8);
        memcpy(srcHash + 8, &h.high64, 8);
      }
      if (!param || !param->Xxh3State)
        XXH3_freeState(state);
    } else {
      HCRYPTPROV p = 0;
      HCRYPTHASH h = 0;
      if (CryptAcquireContextW(&p, NULL, NULL, PROV_RSA_FULL,
                               CRYPT_VERIFYCONTEXT) &&
          CryptCreateHash(p, CALG_MD5, 0, 0, &h)) {
        while (s) {
          if (IsCanceling()) {
            s = FALSE;
            SetLastError(ERROR_OPERATION_ABORTED);
            break;
          }
        if (!srcBack->Read(hSrc, buf, bufSize, &rd)) {
          readSuccess = FALSE;
          s = FALSE;
          break;
        }
        if (rd == 0)
          break;
        AcquireBandwidthTokens((LONGLONG)rd);
        CryptHashData(h, buf, rd, 0);
          if (!dstBack->Write(hDst, buf, rd, &wr) || wr != rd) {
            s = FALSE;
            break;
          }
        }
        if (s && readSuccess) {
          DWORD hLen = 16;
          CryptGetHashParam(h, HP_HASHVAL, srcHash, &hLen, 0);
        }
        CryptDestroyHash(h);
      } else {
        s = FALSE;
      }
      if (p) CryptReleaseContext(p, 0);
    }
  } else {
    /* 无校验：纯拷贝 */
    while (s) {
      if (IsCanceling()) {
        s = FALSE;
        SetLastError(ERROR_OPERATION_ABORTED);
        break;
      }
      if (!srcBack->Read(hSrc, buf, bufSize, &rd)) {
        readSuccess = FALSE;
        s = FALSE;
        break;
      }
      if (rd == 0)
        break;
      AcquireBandwidthTokens((LONGLONG)rd);
      if (!dstBack->Write(hDst, buf, rd, &wr) || wr != rd) {
        s = FALSE;
        break;
      }
    }
  }

  srcBack->Close(hSrc);
  if (s && readSuccess && taskMeta && param && dstBack == &g_VFS_LocalBackend)
    ApplyFileBasicInfoBeforeClose((HANDLE)hDst, taskMeta, param);
  dstBack->Close(hDst);
  if (ownBuf)
    free(buf);

  if (s && readSuccess && g_Config.CompareContent)
    PostVerifyTaskExForRetry(dst, srcHash, fileSize, src, taskMeta ? taskMeta->FileAttributes : 0);
  return s;
}

/* IoRing 运行时检测：Win11/Server2022+ 返回 TRUE；成功时加载全局函数指针（仅一次） */
static BOOL IoRingProbe(void) {
  HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
  if (!hKernel)
    return FALSE;
  typedef HRESULT(WINAPI * QueryIoRingCapabilitiesFn)(void *);
  QueryIoRingCapabilitiesFn pQuery =
      (QueryIoRingCapabilitiesFn)GetProcAddress(hKernel, "QueryIoRingCapabilities");
  if (!pQuery)
    return FALSE;
  struct {
    UINT32 MaxVersion;
    UINT32 MaxSubmissionQueueSize;
    UINT32 MaxCompletionQueueSize;
    UINT32 FeatureFlags;
  } caps = {0};
  if (FAILED(pQuery(&caps)))
    return FALSE;
  if (caps.MaxVersion < 1)
    return FALSE;
  /* 按系统能力截断批大小，避免超出内核队列配额 */
  if ((UINT32)g_IoRingBatchSize > caps.MaxSubmissionQueueSize / 2)
    g_IoRingBatchSize = (int)(caps.MaxSubmissionQueueSize / 2);
  if (g_IoRingBatchSize < 1)
    g_IoRingBatchSize = 1;
  /* 队列深度：每批 2*BatchSize（读+写），至少 256 */
  g_IoRingQueueSize = (UINT32)(2 * g_IoRingBatchSize);
  if (g_IoRingQueueSize < 256) g_IoRingQueueSize = 256;
  if (g_IoRingQueueSize > caps.MaxSubmissionQueueSize)
    g_IoRingQueueSize = caps.MaxSubmissionQueueSize;
  /* 加载一次，避免 CopySmallFilesBatchIoRing 每批都 GetProcAddress */
  if (!g_pCreateIoRing) {
    g_pCreateIoRing = (CreateIoRingFn)GetProcAddress(hKernel, "CreateIoRing");
    g_pBuildIoRingReadFile =
        (BuildIoRingReadFileFn)GetProcAddress(hKernel, "BuildIoRingReadFile");
    g_pBuildIoRingWriteFile =
        (BuildIoRingWriteFileFn)GetProcAddress(hKernel, "BuildIoRingWriteFile");
    g_pSubmitIoRing = (SubmitIoRingFn)GetProcAddress(hKernel, "SubmitIoRing");
    g_pPopIoRingCompletion =
        (PopIoRingCompletionFn)GetProcAddress(hKernel, "PopIoRingCompletion");
    g_pCloseIoRing = (CloseIoRingFn)GetProcAddress(hKernel, "CloseIoRing");
    g_pBuildIoRingRegisterBuffers =
        (BuildIoRingRegisterBuffersFn)GetProcAddress(hKernel, "BuildIoRingRegisterBuffers");
    g_pBuildIoRingRegisterFileHandles =
        (BuildIoRingRegisterFileHandlesFn)GetProcAddress(hKernel, "BuildIoRingRegisterFileHandles");
  }
  if (!(g_pCreateIoRing && g_pBuildIoRingReadFile && g_pBuildIoRingWriteFile &&
        g_pSubmitIoRing && g_pPopIoRingCompletion && g_pCloseIoRing))
    return FALSE;
  /* AIMD 自适应：CreateIoRing 失败时降级 batch，避免非分页池耗尽 */
  {
    void *hTest = NULL;
    int origBatch = g_IoRingBatchSize;
    while (g_IoRingBatchSize >= 64 && g_pCreateIoRing) {
      UINT32 qs = (UINT32)(2 * g_IoRingBatchSize);
      if (qs < 256) qs = 256;
      IORING_CREATE_FLAGS flags = {0, 0};
      if (SUCCEEDED(g_pCreateIoRing(1, flags, qs, qs, &hTest))) {
        g_pCloseIoRing(hTest);
        break;
      }
      g_IoRingBatchSize = g_IoRingBatchSize / 2;
      if (g_IoRingBatchSize < 64) g_IoRingBatchSize = 64;
      g_IoRingQueueSize = (UINT32)(2 * g_IoRingBatchSize);
      if (g_IoRingQueueSize < 256) g_IoRingQueueSize = 256;
    }
    if (g_IoRingBatchSize < origBatch)
      wprintf(L"[INFO] IoRing batch AIMD: %d -> %d (insufficient resources)\n", origBatch, g_IoRingBatchSize);
  }
  return TRUE;
}


/* IoRing 批处理复制：需 !CompareContent、文件 < IORING_MAX_FILE_SIZE。返回成功数量
 * 信任宏观并发：64 个 CopierThread 各自串行打开批次，宏观已 4096 级并发，无需每批创建线程 */
static int CopySmallFilesBatchIoRing(CopyTask *const *tasks, int count,
                                     CopierParam *param) {
  memset(param->IoRingBatchOk, 0, sizeof(BOOL) * (size_t)count);
  if (count <= 0 || !param->hIoRing || !g_pBuildIoRingReadFile || !g_pBuildIoRingWriteFile ||
      !g_pSubmitIoRing || !g_pPopIoRingCompletion)
    return 0;

  LONGLONG totalBytes = 0;
  int i;
  for (i = 0; i < count; i++)
    totalBytes += tasks[i]->FileSize;
  AcquireBandwidthTokens(totalBytes);

  void *hRing = param->hIoRing;
  HANDLE *hSrc = param->IoRingHandleSrc;
  HANDLE *hDst = param->IoRingHandleDst;
  BYTE **bufs = param->IoRingBufs;
  BOOL *readOk = param->IoRingReadOk;
  BOOL *writeOk = param->IoRingWriteOk;
  memset(readOk, 0, sizeof(BOOL) * (size_t)count);
  memset(writeOk, 0, sizeof(BOOL) * (size_t)count);

  for (i = 0; i < count; i++) {
    DWORD srcFlags = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OVERLAPPED;
    DWORD dstFlags = FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED;
    /* PB：Src 相对打开（失败回退全路径） */
    hSrc[i] = OpenSrcFileWithNtApi(param, tasks[i]->SrcPath, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, srcFlags);
    hDst[i] = OpenDstFileWithNtApi(param, tasks[i]->DstPath, GENERIC_WRITE, 0, CREATE_ALWAYS,
        dstFlags, tasks[i]->FileSize);
    if (hSrc[i] == INVALID_HANDLE_VALUE || hDst[i] == INVALID_HANDLE_VALUE) {
      if (hSrc[i] != INVALID_HANDLE_VALUE) CloseHandle(hSrc[i]);
      if (hDst[i] != INVALID_HANDLE_VALUE) CloseHandle(hDst[i]);
      hSrc[i] = INVALID_HANDLE_VALUE;
      hDst[i] = INVALID_HANDLE_VALUE;
      continue;
    }
    /* 0 字节：无 Read/Write SQE，创建成功即视为完成 */
    if (tasks[i]->FileSize == 0) {
      readOk[i] = TRUE;
      writeOk[i] = TRUE;
    }
  }

  {
    size_t currentOffset = 0;
    for (i = 0; i < count; i++) {
      bufs[i] = param->IoRingBuffer + currentOffset;
      currentOffset += (size_t)tasks[i]->FileSize;
    }
  }

  int validNonZero = 0;
  for (i = 0; i < count; i++)
    if (hSrc[i] != INVALID_HANDLE_VALUE && tasks[i]->FileSize > 0)
      validNonZero++;

  const BOOL useRegisteredHandles = FALSE;
  struct {
    UINT32 Kind;
    union {
      HANDLE Handle;
      UINT32 Index;
    } u;
  } href;
  struct {
    UINT32 Kind;
    union {
      void *Address;
      struct {
        UINT32 BufferIndex;
        UINT32 Offset;
      } io;
    } u;
  } bref;
  href.Kind = IORING_REF_RAW;
  bref.Kind = param->IoRingBuffersRegistered ? 1 : 0;

  int buildCount = 0;
  size_t bufOffset = 0;
  for (i = 0; i < count; i++) {
    if (hSrc[i] == INVALID_HANDLE_VALUE || tasks[i]->FileSize == 0) {
      bufOffset += (size_t)tasks[i]->FileSize;
      continue;
    }
    href.u.Handle = hSrc[i];
    if (param->IoRingBuffersRegistered) {
      bref.u.io.BufferIndex = 0;
      bref.u.io.Offset = (UINT32)bufOffset;
    } else {
      bref.u.Address = bufs[i];
    }
    bufOffset += (size_t)tasks[i]->FileSize;
    DWORD sz = (DWORD)tasks[i]->FileSize;
    if (FAILED(g_pBuildIoRingReadFile(hRing, &href, &bref, sz, 0, (UINT_PTR)i, 0))) {
      CloseHandle(hSrc[i]);
      CloseHandle(hDst[i]);
      hSrc[i] = hDst[i] = INVALID_HANDLE_VALUE;
      continue;
    }
    buildCount++;
  }

  if (buildCount == 0 && validNonZero == 0) {
    /* 全是 0 字节或全失败：直接收尾 */
    goto ioring_finish;
  }
  if (buildCount == 0)
    goto ioring_finish;

  UINT32 sub1 = 0;
  if (FAILED(g_pSubmitIoRing(hRing, buildCount, 60000, &sub1))) {
    struct { UINT_PTR UserData; HRESULT ResultCode; ULONG_PTR Information; } cqe;
    for (UINT32 k = 0; k < sub1; k++) {
      int spin = 0;
      while (g_pPopIoRingCompletion(hRing, &cqe) != S_OK) {
        if (spin < 100) SwitchToThread(); else Sleep(1);
        spin++;
      }
    }
    for (i = 0; i < count; i++) {
      if (hSrc[i] != INVALID_HANDLE_VALUE) {
        CloseHandle(hSrc[i]);
        CloseHandle(hDst[i]);
        hSrc[i] = hDst[i] = INVALID_HANDLE_VALUE;
      }
    }
    if (g_pCloseIoRing && param->hIoRing) {
      g_pCloseIoRing(param->hIoRing);
      param->hIoRing = NULL;
      param->IoRingBuffersRegistered = FALSE;
    }
    return 0;
  }

  {
    struct { UINT_PTR UserData; HRESULT ResultCode; ULONG_PTR Information; } cqe;
    for (i = 0; i < buildCount; i++) {
      HRESULT hr = g_pPopIoRingCompletion(hRing, &cqe);
      if (hr != S_OK) break;
      if (SUCCEEDED(cqe.ResultCode) && cqe.UserData < (UINT_PTR)count) {
        UINT_PTR idx = cqe.UserData;
        if (cqe.Information == (ULONG_PTR)tasks[idx]->FileSize)
          readOk[idx] = TRUE;
      }
    }
  }

  /* -J -D：读成功后对缓冲做 XXH3 */
  if (g_Config.CompareContent && g_Config.UseXxh3 && param->IoRingSrcHashes) {
    for (i = 0; i < count; i++) {
      if (!readOk[i] || tasks[i]->FileSize <= 0) continue;
      XXH64_hash_t h = XXH3_64bits(bufs[i], (size_t)tasks[i]->FileSize);
      memcpy(param->IoRingSrcHashes + (size_t)i * 8, &h, 8);
    }
  }

  int writeSubmits = 0;
  bufOffset = 0;
  for (i = 0; i < count; i++) {
    if (!readOk[i] || tasks[i]->FileSize == 0) {
      bufOffset += (size_t)tasks[i]->FileSize;
      continue;
    }
    href.u.Handle = hDst[i];
    if (param->IoRingBuffersRegistered) {
      bref.u.io.BufferIndex = 0;
      bref.u.io.Offset = (UINT32)bufOffset;
    } else {
      bref.u.Address = bufs[i];
    }
    bufOffset += (size_t)tasks[i]->FileSize;
    DWORD sz = (DWORD)tasks[i]->FileSize;
    if (FAILED(g_pBuildIoRingWriteFile(hRing, &href, &bref, sz, 0, 0, (UINT_PTR)(i + 0x10000), 0))) {
      CloseHandle(hSrc[i]);
      CloseHandle(hDst[i]);
      hSrc[i] = hDst[i] = INVALID_HANDLE_VALUE;
      readOk[i] = FALSE;
      continue;
    }
    writeSubmits++;
  }

  UINT32 submitted = 0;
  if (writeSubmits > 0 && FAILED(g_pSubmitIoRing(hRing, writeSubmits, 60000, &submitted))) {
    struct { UINT_PTR UserData; HRESULT ResultCode; ULONG_PTR Information; } cqeW;
    for (UINT32 k = 0; k < submitted; k++) {
      int spin = 0;
      while (g_pPopIoRingCompletion(hRing, &cqeW) != S_OK) {
        if (spin < 100) SwitchToThread(); else Sleep(1);
        spin++;
      }
    }
    for (i = 0; i < count; i++) {
      if (hSrc[i] != INVALID_HANDLE_VALUE) {
        CloseHandle(hSrc[i]);
        CloseHandle(hDst[i]);
        hSrc[i] = hDst[i] = INVALID_HANDLE_VALUE;
      }
    }
    if (g_pCloseIoRing && param->hIoRing) {
      g_pCloseIoRing(param->hIoRing);
      param->hIoRing = NULL;
      param->IoRingBuffersRegistered = FALSE;
    }
    return 0;
  }

  if (writeSubmits > 0) {
    struct { UINT_PTR UserData; HRESULT ResultCode; ULONG_PTR Information; } cqe;
    for (i = 0; i < writeSubmits; i++) {
      HRESULT hr = g_pPopIoRingCompletion(hRing, &cqe);
      if (hr != S_OK) break;
      if (SUCCEEDED(cqe.ResultCode) && cqe.UserData >= 0x10000) {
        UINT_PTR idx = cqe.UserData - 0x10000;
        if (idx < (UINT_PTR)count &&
            cqe.Information == (ULONG_PTR)tasks[idx]->FileSize)
          writeOk[idx] = TRUE;
      }
    }
  }

ioring_finish:
  /* Close 前写时间戳，避免 CopyFileSecurity 再开句柄 */
  for (i = 0; i < count; i++) {
    if (hDst[i] != INVALID_HANDLE_VALUE && writeOk[i] &&
        !(g_Config.FastMode && !g_Config.MetadataOnly)) {
      SetFileTime(hDst[i], &tasks[i]->CreationTime, &tasks[i]->LastAccessTime,
                  &tasks[i]->LastWriteTime);
    }
  }
  for (i = 0; i < count; i++) {
    if (hSrc[i] != INVALID_HANDLE_VALUE) CloseHandle(hSrc[i]);
    if (hDst[i] != INVALID_HANDLE_VALUE) CloseHandle(hDst[i]);
    hSrc[i] = hDst[i] = INVALID_HANDLE_VALUE;
  }

  int successCount = 0;
  for (i = 0; i < count; i++) {
    param->IoRingBatchOk[i] = writeOk[i];
    if (writeOk[i])
      successCount++;
  }

  for (i = 0; i < count; i++) {
    if (!writeOk[i]) continue;
    CopyFileSecurityAndAttributesEx(tasks[i]->SrcPath, tasks[i]->DstPath, tasks[i],
                                    TRUE, param);
    if (g_Config.CompareContent && g_Config.UseXxh3 && param->IoRingSrcHashes &&
        tasks[i]->FileSize > 0) {
      PostVerifyTaskExForRetry(tasks[i]->DstPath,
          param->IoRingSrcHashes + (size_t)i * 8, tasks[i]->FileSize,
          tasks[i]->SrcPath, tasks[i]->FileAttributes);
    }
    param->LocalCopied++;
    param->LocalBytes += tasks[i]->FileSize;
    param->LocalSmallFiles++;
  }
  (void)useRegisteredHandles;
  return successCount;
}

/* Round4 P2 Bug4：IoRing 降级错误码分类辅助宏
 * 永久性错误（Permanent）：重试无意义，直接计入失败，不进 DLQ。
 *   - ERROR_ACCESS_DENIED（属性清除后仍失败）、ERROR_FILE_NOT_FOUND、
 *     ERROR_PATH_NOT_FOUND、ERROR_INVALID_NAME：文件/路径问题，DLQ 重试同样会失败。
 * 瞬时性错误（Transient）：值得 DLQ 慢速重试（锁争用、网络抖动等）。
 *   - ERROR_SHARING_VIOLATION、ERROR_LOCK_VIOLATION 及其他未列举错误。*/
static BOOL IsPermanentIoError(DWORD err) {
  return err == ERROR_FILE_NOT_FOUND   ||
         err == ERROR_PATH_NOT_FOUND   ||
         err == ERROR_INVALID_NAME     ||
         err == ERROR_INVALID_PARAMETER ||
         err == ERROR_DISK_FULL;
  /* 注：ERROR_ACCESS_DENIED 在属性清除重试后才判定为永久性，见下方逻辑 */
}

/* 刷新 IoRing 批次：处理并释放当前批次中的任务
 * P4：连续失败熔断，同批 5 次兜底失败后剩余项直接打入 DLQ，避免 256 次同步 CopyFile2Ex 瘫痪流水线
 * Round4 P2 Bug4：错误码分类——永久性错误直接记失败，瞬时性错误进 DLQ 慢速重试 */
static void FlushIoRingBatch(CopierParam *param) {
  if (param->IoRingBatchCount == 0)
    return;
  int n = param->IoRingBatchCount;
  CopySmallFilesBatchIoRing(param->IoRingBatch, n, param);
  int fallbackFailCount = 0;
  for (int i = 0; i < n; i++) {
    if (!param->IoRingBatchOk[i]) {
      /* 【关键修复】：IoRing 失败时降级 CopyFile2（ODX/块克隆）或 CopyFileW 兜底；不重复扣费 */
      BOOL fallbackOk = FALSE;
      DWORD fallbackErr = 0;
      if (fallbackFailCount < 5) {
        fallbackOk = CopyFile2Ex(param->IoRingBatch[i]->SrcPath,
                                 param->IoRingBatch[i]->DstPath, g_Config.FastMode);
        fallbackErr = GetLastError();
        if (!fallbackOk && fallbackErr == ERROR_ACCESS_DENIED) {
          SetFileAttributesW(param->IoRingBatch[i]->DstPath, FILE_ATTRIBUTE_NORMAL);
          fallbackOk = CopyFile2Ex(param->IoRingBatch[i]->SrcPath,
                                  param->IoRingBatch[i]->DstPath, g_Config.FastMode);
          fallbackErr = GetLastError();
          /* 属性清除后仍 ACCESS_DENIED：权限问题，永久性错误，不进 DLQ */
          if (!fallbackOk && fallbackErr == ERROR_ACCESS_DENIED)
            fallbackErr = ERROR_ACCESS_DENIED;  /* 标记为永久性，下方处理 */
        }
        if (!fallbackOk) fallbackFailCount++;
        else fallbackFailCount = 0;
      } else {
        /* 熔断后：从批次首条记录一次最终错误码，用于分类路由 */
        fallbackErr = ERROR_SHARING_VIOLATION;  /* 假定为瞬时性，进 DLQ 重试 */
      }
      if (fallbackOk) {
        CopyFileSecurityAndAttributes(param->IoRingBatch[i]->SrcPath,
                                     param->IoRingBatch[i]->DstPath,
                                     param->IoRingBatch[i]);
        param->LocalCopied++;
        param->LocalBytes += param->IoRingBatch[i]->FileSize;
        param->LocalSmallFiles++;
      } else {
        /* 【遣返防线】：退还为该文件预支的令牌，避免 DLQ 二次重试时双重计费 */
        RefundBandwidthTokens((LONGLONG)param->IoRingBatch[i]->FileSize);
        /* Round4 P2 Bug4：错误码分类路由
         * 永久性错误（权限/路径/磁盘满）：DLQ 重试同样会失败，直接记失败、清理目标。
         * 瞬时性错误（锁争用/网络抖动）：进 DLQ 慢速重试，有望自愈。*/
        BOOL isPermanent = IsPermanentIoError(fallbackErr) ||
                           (fallbackErr == ERROR_ACCESS_DENIED);  /* 属性清除后仍失败 */
        if (!isPermanent && g_DeadLetterQueue && !g_NoDLQ) {
          CopyTask *bt = param->IoRingBatch[i];
          if (bt->DlqRoundCount >= MAX_DLQ_ROUND_TRIPS) {
            LogMessage(LOG_ERROR,
                L"[DLQ] Max round-trips exceeded (IoRing path), dropping task: %ls\n",
                bt->SrcPath ? bt->SrcPath : bt->ShortSrc);
            InterlockedIncrement(&g_TotalFailed);
            RequestAsyncCleanup(bt->DstPath);
            /* IoRing 批次项在入批时已被 Copier 按 KEY_COPY_TASK 扣过计数；此处仅释放。 */
            TLC_FreeCopyTask(param, bt);
            continue;
          }
          bt->DlqRoundCount++;
          /* 瞬时性：进 DLQ，每 200 次采样一次供诊断 */
          static volatile LONG s_IoRingSampleCnt = 0;
          if ((InterlockedIncrement(&s_IoRingSampleCnt) % 200) == 1)
            wprintf(L"\n[IORING-SAMPLE #%ld] Err:%lu (Transient->DLQ) -> %ls\n",
                    (long)READ_VOLATILE_32(&s_IoRingSampleCnt),
                    (unsigned long)fallbackErr, bt->SrcPath);
          InterlockedPushEntrySList(g_DeadLetterQueue, &bt->ItemEntry);
          continue;
        }
        /* 永久性：立即记错误并清理，不消耗 DLQ 重试配额 */
        LogMessageRaw(LOG_ERROR, fallbackErr, param->IoRingBatch[i]->SrcPath,
            param->IoRingBatch[i]->FileSize, 3);
        InterlockedIncrement(&g_TotalFailed);
        RequestAsyncCleanup(param->IoRingBatch[i]->DstPath);
      }
    }
    TLC_FreeCopyTask(param, param->IoRingBatch[i]);
  }
  param->IoRingBatchCount = 0;
  param->IoRingBatchTotalBytes = 0;
}

/* scratchBuf 可选：非 NULL 时复用，否则 malloc；scratchSize 为 0 时用 1MB；VFS 抽象打通 sftp */
static BOOL CalculateFileMd5Ex(const wchar_t *path, BYTE *out, BYTE *scratchBuf,
                               DWORD scratchSize) {
  const IO_BACKEND *back = VFS_GetBackend(path);
  if (!back)
    return FALSE;
  IO_HANDLE f = back->Open(path, IO_MODE_READ, FALSE);
  if (f == IO_HANDLE_INVALID)
    return FALSE;

  DWORD bufSize = (scratchSize > 0) ? scratchSize : (1024 * 1024);
  BOOL ownBuf = (scratchBuf == NULL);
  if (ownBuf) {
    scratchBuf = (BYTE *)malloc(bufSize);
    if (!scratchBuf) {
      bufSize = 32768;
      scratchBuf = (BYTE *)malloc(bufSize);
    }
  }
  if (!scratchBuf) {
    back->Close(f);
    return FALSE;
  }

  HCRYPTPROV p;
  HCRYPTHASH h;
  BOOL s = FALSE;
  if (CryptAcquireContextW(&p, NULL, NULL, PROV_RSA_FULL,
                           CRYPT_VERIFYCONTEXT)) {
    if (CryptCreateHash(p, CALG_MD5, 0, 0, &h)) {
      DWORD r;
      BOOL readSuccess = TRUE;
      while (TRUE) {
        if (!back->Read(f, scratchBuf, bufSize, &r)) {
          readSuccess = FALSE;
          break;
        }
        if (r == 0)
          break;
        CryptHashData(h, scratchBuf, r, 0);
      }
      DWORD len = 16;
      if (readSuccess && CryptGetHashParam(h, HP_HASHVAL, out, &len, 0))
        s = TRUE;
      CryptDestroyHash(h);
    }
    CryptReleaseContext(p, 0);
  }
  if (ownBuf)
    free(scratchBuf);
  back->Close(f);
  return s;
}

BOOL CalculateFileMd5(const wchar_t *path, BYTE *out) {
  return CalculateFileMd5Ex(path, out, NULL, 0);
}

/* scratchBuf 可选；reuseState 可选，非 NULL 时复用并 reset 后不 free；VFS 抽象打通 sftp */
static BOOL CalculateFileXxh3Ex(const wchar_t *path, BYTE *out, BYTE *scratchBuf,
                                DWORD scratchSize, XXH3_state_t *reuseState) {
  const IO_BACKEND *back = VFS_GetBackend(path);
  if (!back)
    return FALSE;
  IO_HANDLE f = back->Open(path, IO_MODE_READ, FALSE);
  if (f == IO_HANDLE_INVALID)
    return FALSE;

  XXH3_state_t *state = reuseState ? reuseState : XXH3_createState();
  BOOL ownState = (reuseState == NULL);
  if (!state) {
    back->Close(f);
    return FALSE;
  }
  if (XXH3_128bits_reset(state) != XXH_OK) {
    if (ownState) XXH3_freeState(state);
    back->Close(f);
    return FALSE;
  }

  DWORD bufSize = (scratchSize > 0) ? scratchSize : (1024 * 1024);
  BOOL ownBuf = (scratchBuf == NULL);
  if (ownBuf) {
    scratchBuf = (BYTE *)malloc(bufSize);
    if (!scratchBuf) {
      bufSize = 32768;
      scratchBuf = (BYTE *)malloc(bufSize);
    }
  }
  if (!scratchBuf) {
    if (ownState) XXH3_freeState(state);
    back->Close(f);
    return FALSE;
  }

  BOOL s = TRUE;
  DWORD r;
  while (s) {
    if (!back->Read(f, scratchBuf, bufSize, &r)) {
      s = FALSE;
      break;
    }
    if (r == 0)
      break;
    if (XXH3_128bits_update(state, scratchBuf, r) != XXH_OK) {
      s = FALSE;
      break;
    }
  }
  if (ownBuf)
    free(scratchBuf);

  if (s) {
    XXH128_hash_t h = XXH3_128bits_digest(state);
    memcpy(out, &h.low64, 8);
    memcpy(out + 8, &h.high64, 8);
  }
  if (ownState)
    XXH3_freeState(state);
  back->Close(f);
  return s;
}

BOOL CalculateFileXxh3(const wchar_t *path, BYTE *out) {
  return CalculateFileXxh3Ex(path, out, NULL, 0, NULL);
}

/* 根据 UseXxh3 选择 MD5 或 XXH3；param 非 NULL 时复用 HashBuffer/Xxh3State 实现零分配 */
static BOOL CalculateFileHash(const wchar_t *path, BYTE *out, CopierParam *param) {
  BYTE *buf = (param && param->HashBuffer) ? param->HashBuffer : NULL;
  DWORD bufSize = 1024 * 1024;
  XXH3_state_t *state = (param && param->Xxh3State) ? param->Xxh3State : NULL;
  if (g_Config.UseXxh3)
    return CalculateFileXxh3Ex(path, out, buf, bufSize, state);
  return CalculateFileMd5Ex(path, out, buf, bufSize);
}

/* 验证线程专用：传入 VerifyParam 实现零分配 */
static BOOL CalculateFileHashWithVerifyParam(const wchar_t *path, BYTE *out,
                                             VerifyParam *vp) {
  BYTE *buf = (vp && vp->HashBuffer) ? vp->HashBuffer : NULL;
  DWORD bufSize = 1024 * 1024;
  XXH3_state_t *state = (vp && vp->Xxh3State) ? vp->Xxh3State : NULL;
  if (g_Config.UseXxh3)
    return CalculateFileXxh3Ex(path, out, buf, bufSize, state);
  return CalculateFileMd5Ex(path, out, buf, bufSize);
}

static LONG CountRegularFilesRecursive(const wchar_t *rootPath) {
  if (!rootPath || !*rootPath) return 0;
  LONG total = 0;
  typedef struct _AuditDirNode {
    struct _AuditDirNode *Next;
    wchar_t *Path;
  } AuditDirNode;
  AuditDirNode *head = (AuditDirNode *)malloc(sizeof(AuditDirNode));
  if (!head) return 0;
  head->Next = NULL;
  head->Path = _wcsdup(rootPath);
  if (!head->Path) {
    free(head);
    return 0;
  }
  while (head) {
    AuditDirNode *cur = head;
    head = head->Next;
    HANDLE hDir = CreateFileW(cur->Path, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hDir == INVALID_HANDLE_VALUE) {
      free(cur->Path);
      free(cur);
      continue;
    }
    DWORD bufSize = 1024 * 1024;
    BYTE *buf = (BYTE *)malloc(bufSize);
    if (!buf) {
      CloseHandle(hDir);
      free(cur->Path);
      free(cur);
      continue;
    }
    for (;;) {
      if (!GetFileInformationByHandleEx(hDir, FileIdBothDirectoryInfo, buf, bufSize)) {
        DWORD err = GetLastError();
        if (err == ERROR_MORE_DATA && bufSize < 32 * 1024 * 1024) {
          DWORD newSize = bufSize * 2;
          BYTE *nb = (BYTE *)realloc(buf, newSize);
          if (!nb)
            break;
          buf = nb;
          bufSize = newSize;
          continue;
        }
        if (err == ERROR_NO_MORE_FILES) {
          break;
        }
        break;
      }
      FILE_ID_BOTH_DIR_INFO *p = (FILE_ID_BOTH_DIR_INFO *)buf;
      while (1) {
        DWORD nlen = p->FileNameLength / sizeof(wchar_t);
        wchar_t name[MAX_PATH];
        if (nlen >= MAX_PATH) nlen = MAX_PATH - 1;
        StringCchCopyNW(name, MAX_PATH, p->FileName, nlen);
        name[nlen] = L'\0';
        if (wcscmp(name, L".") != 0 && wcscmp(name, L"..") != 0) {
          if (p->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            AuditDirNode *st = (AuditDirNode *)malloc(sizeof(AuditDirNode));
            if (st) {
              wchar_t tmp[MAX_PATH_EXT];
              StringCchPrintfW(tmp, MAX_PATH_EXT, L"%ls\\%ls", cur->Path, name);
              st->Path = _wcsdup(tmp);
              if (st->Path) {
                st->Next = head;
                head = st;
              } else {
                free(st);
              }
            }
          } else {
            InterlockedIncrement(&total);
          }
        }
        if (p->NextEntryOffset == 0) break;
        p = (FILE_ID_BOTH_DIR_INFO *)((BYTE *)p + p->NextEntryOffset);
      }
    }
    free(buf);
    CloseHandle(hDir);
    free(cur->Path);
    free(cur);
  }
  return total;
}

#define SAMPLE_HEAD_TAIL_MB 10       /* Phase 20: 首尾各 10MB */
#define SAMPLE_MID_BLOCK_MB 10       /* Phase 20: 中间每块 10MB */
#define SAMPLE_DEFAULT_THRESHOLD_GB 5
#define SAMPLE_DEFAULT_RANDOM_BLOCKS 6
#define MAX_HASH_SAMPLES 36          /* V10: 栈化，2+32 中间块上限，零 malloc */

/* Phase 20: 可配置抽样阈值，0=默认 5GB */
static LONGLONG GetSampleThreshold(void) {
  int gb = g_Config.SampleThresholdGB;
  if (gb <= 0) gb = SAMPLE_DEFAULT_THRESHOLD_GB;
  return (LONGLONG)gb * 1024LL * 1024LL * 1024LL;
}

/* 大文件抽样 Hash：Phase 20 首尾各 10MB + 中间 N×10MB 均匀分布，可配置阈值
 * useVerifyParam: 0=CopierParam, 1=VerifyParam，用于 fallback 到全量 Hash */
static BOOL CalculateFileHashSampled(const wchar_t *path, BYTE *outHash,
                                     LONGLONG fileSize, void *paramOrVp,
                                     BOOL useVerifyParam) {
  LONGLONG threshold = GetSampleThreshold();
  if (fileSize < threshold || !g_Config.SampleLargeFiles) {
    if (useVerifyParam && paramOrVp)
      return CalculateFileHashWithVerifyParam(path, outHash, (VerifyParam *)paramOrVp);
    return CalculateFileHash(path, outHash, (CopierParam *)paramOrVp);
  }

  HANDLE h = CreateFileW(path, GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
      NULL);
  if (h == INVALID_HANDLE_VALUE)
    return FALSE;

  BYTE *buf = NULL;
  CopierParam *cp = useVerifyParam ? NULL : (CopierParam *)paramOrVp;
  VerifyParam *vp = useVerifyParam ? (VerifyParam *)paramOrVp : NULL;
  if (cp && cp->HashBuffer)
    buf = cp->HashBuffer;
  else if (vp && vp->HashBuffer)
    buf = vp->HashBuffer;
  else
    buf = (BYTE *)malloc(1024 * 1024);
  if (!buf) {
    CloseHandle(h);
    return FALSE;
  }

  LONGLONG headSize = (LONGLONG)SAMPLE_HEAD_TAIL_MB * 1024 * 1024;
  LONGLONG blockSize = (LONGLONG)SAMPLE_MID_BLOCK_MB * 1024 * 1024;
  int nMid = g_Config.SampleRandomBlocks;
  if (nMid <= 0) nMid = SAMPLE_DEFAULT_RANDOM_BLOCKS;
  LONGLONG midStart = headSize;
  LONGLONG midEnd = fileSize - headSize - blockSize;
  if (midEnd <= midStart) midEnd = midStart;

  /* V10 栈化：L1 极速分配，零 malloc 消灭堆锁争用与 Cache Miss */
  int numOffsets = 2 + nMid;
  if (numOffsets > MAX_HASH_SAMPLES) numOffsets = MAX_HASH_SAMPLES;
  LONGLONG offsets[MAX_HASH_SAMPLES];
  LONGLONG sizes[MAX_HASH_SAMPLES];
  offsets[0] = 0;
  for (int i = 0; i < nMid && (1 + i) < numOffsets; i++)
    offsets[1 + i] = midStart + (midEnd - midStart) * (i + 1) / (nMid + 1);
  offsets[numOffsets - 1] = fileSize - headSize;
  sizes[0] = headSize;
  for (int i = 1; i < numOffsets - 1; i++)
    sizes[i] = blockSize;
  sizes[numOffsets - 1] = headSize;

  /* Phase 20 P2: IoRing 离散读路径，仅 XXH3，区域数<=16 时启用 */
  if (useVerifyParam && vp && g_Config.UseIoRing && g_IoRingAvailable &&
      g_Config.UseXxh3 && numOffsets <= 16 &&
      g_pBuildIoRingReadFile && g_pSubmitIoRing && g_pPopIoRingCompletion &&
      g_pCloseIoRing) {
    size_t bufNeed = 0;
    for (int i = 0; i < numOffsets; i++)
      bufNeed += (size_t)sizes[i];
    if (!vp->hIoRingVerify && g_pCreateIoRing) {
      IORING_CREATE_FLAGS flags = {0, 0};
      if (SUCCEEDED(g_pCreateIoRing(1, flags, 64, 64, &vp->hIoRingVerify))) {
        vp->IoRingSampleBufSize = (size_t)(16 * SAMPLE_MID_BLOCK_MB * 1024 * 1024); /* 160MB 容纳 16 区 */
        vp->IoRingSampleBuf = (BYTE *)VirtualAlloc(NULL, vp->IoRingSampleBufSize, MEM_COMMIT, PAGE_READWRITE);
        if (!vp->IoRingSampleBuf) {
          g_pCloseIoRing(vp->hIoRingVerify);
          vp->hIoRingVerify = NULL;
        }
      }
    }
    if (vp->hIoRingVerify && vp->IoRingSampleBuf && vp->IoRingSampleBufSize >= bufNeed) {
      struct { UINT32 Kind; union { void *Handle; UINT32 Index; } u; } href;
      struct { UINT32 Kind; union { void *Address; struct { UINT32 BufferIndex; UINT32 Offset; } io; } u; } bref;
      href.Kind = 0; /* IORING_REF_RAW */
      href.u.Handle = h;
      bref.Kind = 0;
      size_t bufOff = 0;
      int buildCount = 0;
      for (int i = 0; i < numOffsets; i++) {
        bref.u.Address = vp->IoRingSampleBuf + bufOff;
        DWORD sz = (DWORD)sizes[i];
        if (FAILED(g_pBuildIoRingReadFile(vp->hIoRingVerify, &href, &bref, sz,
            (UINT64)offsets[i], (UINT_PTR)i, 0)))
          break;
        buildCount++;
        bufOff += (size_t)sizes[i];
      }
      if (buildCount == numOffsets) {
        UINT32 submitted = 0;
        if (SUCCEEDED(g_pSubmitIoRing(vp->hIoRingVerify, buildCount, 60000, &submitted)) &&
            submitted == (UINT32)buildCount) {
          BOOL readOk[16];
          memset(readOk, 0, sizeof(readOk));
          struct { UINT_PTR UserData; HRESULT ResultCode; ULONG_PTR Information; } cqe;
          for (int k = 0; k < buildCount; k++) {
            if (g_pPopIoRingCompletion(vp->hIoRingVerify, &cqe) != S_OK)
              break;
            if (SUCCEEDED(cqe.ResultCode) && cqe.UserData < (UINT_PTR)buildCount)
              readOk[cqe.UserData] = TRUE;
          }
          int allOk = 1;
          for (int k = 0; k < buildCount; k++)
            if (!readOk[k]) { allOk = 0; break; }
          if (allOk && vp->Xxh3State) {
            if (XXH3_128bits_reset(vp->Xxh3State) == XXH_OK) {
              bufOff = 0;
              for (int i = 0; i < numOffsets; i++) {
                XXH3_128bits_update(vp->Xxh3State, vp->IoRingSampleBuf + bufOff, (size_t)sizes[i]);
                bufOff += (size_t)sizes[i];
              }
              XXH128_hash_t hh = XXH3_128bits_digest(vp->Xxh3State);
              memcpy(outHash, &hh.low64, 8);
              memcpy(outHash + 8, &hh.high64, 8);
              CloseHandle(h);
              return TRUE;
            }
          }
        }
      }
    }
  }

  BOOL success = TRUE;

  if (g_Config.UseXxh3) {
    XXH3_state_t *state = (cp && cp->Xxh3State) ? cp->Xxh3State :
        (vp && vp->Xxh3State) ? vp->Xxh3State : XXH3_createState();
    BOOL ownState = !(cp && cp->Xxh3State) && !(vp && vp->Xxh3State);
    if (!state) {
      if (buf && !(cp && buf == cp->HashBuffer) && !(vp && buf == vp->HashBuffer))
        free(buf);
      CloseHandle(h);
      return FALSE;
    }
    if (XXH3_128bits_reset(state) != XXH_OK) {
      if (ownState) XXH3_freeState(state);
      if (buf && !(cp && buf == cp->HashBuffer) && !(vp && buf == vp->HashBuffer))
        free(buf);
      CloseHandle(h);
      return FALSE;
    }
    for (int i = 0; i < numOffsets && success; i++) {
      LARGE_INTEGER li;
      li.QuadPart = offsets[i];
      if (SetFilePointerEx(h, li, NULL, FILE_BEGIN) == 0) {
        success = FALSE;
        break;
      }
      LONGLONG toRead = sizes[i];
      while (toRead > 0 && success) {
        DWORD rd, toDo = (DWORD)min(toRead, 1024 * 1024);
        if (!ReadFile(h, buf, toDo, &rd, NULL) || rd == 0) {
          success = FALSE;
          break;
        }
        if (XXH3_128bits_update(state, buf, rd) != XXH_OK)
          success = FALSE;
        toRead -= rd;
      }
    }
    if (success) {
      XXH128_hash_t hh = XXH3_128bits_digest(state);
      memcpy(outHash, &hh.low64, 8);
      memcpy(outHash + 8, &hh.high64, 8);
    }
    if (ownState)
      XXH3_freeState(state);
  } else {
    HCRYPTPROV prov = 0;
    HCRYPTHASH hHash = 0;
    if (!CryptAcquireContextW(&prov, NULL, NULL, PROV_RSA_FULL,
                              CRYPT_VERIFYCONTEXT) ||
        !CryptCreateHash(prov, CALG_MD5, 0, 0, &hHash)) {
      success = FALSE;
    } else {
      for (int i = 0; i < numOffsets && success; i++) {
        LARGE_INTEGER li;
        li.QuadPart = offsets[i];
        if (SetFilePointerEx(h, li, NULL, FILE_BEGIN) == 0) {
          success = FALSE;
          break;
        }
        LONGLONG toRead = sizes[i];
        while (toRead > 0 && success) {
          DWORD rd, toDo = (DWORD)min(toRead, 1024 * 1024);
          if (!ReadFile(h, buf, toDo, &rd, NULL) || rd == 0) {
            success = FALSE;
            break;
          }
          if (!CryptHashData(hHash, buf, rd, 0))
            success = FALSE;
          toRead -= rd;
        }
      }
      if (success) {
        DWORD len = 16;
        CryptGetHashParam(hHash, HP_HASHVAL, outHash, &len, 0);
      }
      CryptDestroyHash(hHash);
    }
    if (prov) CryptReleaseContext(prov, 0);
  }

  if (buf && !(cp && buf == cp->HashBuffer) && !(vp && buf == vp->HashBuffer))
    free(buf);
  CloseHandle(h);
  return success;
}

#define PREALLOC_VERIFY_TASKS 30000 /* 与 g_MaxQueueDepth 对齐，抵御 NVMe 洪水 */
static unsigned __stdcall VerifyThread(void *pParam) {
  VerifyParam *vp = (VerifyParam *)pParam;
  ULONG_PTR key;
  LPOVERLAPPED ov;
  /* Phase 18 去抖动：首个 Verify 线程启用 MMCSS Pro-Audio */
  HANDLE hVerifyMmcss = NULL;
  if (g_VerifyParams && vp == g_VerifyParams[0]) {
    HMODULE hAvrt = LoadLibraryW(L"avrt.dll");
    if (hAvrt) {
      typedef HANDLE (WINAPI *PAvSet)(LPCWSTR, LPDWORD);
      typedef BOOL (WINAPI *PAvPrio)(HANDLE, int);
      PAvSet pSet = (PAvSet)GetProcAddress(hAvrt, "AvSetMmThreadCharacteristicsW");
      PAvPrio pPrio = (PAvPrio)GetProcAddress(hAvrt, "AvSetMmThreadPriority");
      if (pSet && pPrio) {
        DWORD ti = 0;
        hVerifyMmcss = pSet(L"Pro Audio", &ti);
        if (hVerifyMmcss) pPrio(hVerifyMmcss, 2);  /* AVRT_PRIO_CRITICAL */
      }
    }
  }
  while (g_VerifyThreadRunning) {
    OVERLAPPED_ENTRY vEntries[GQCSEx_BATCH_SIZE];
    ULONG numGot = 0;
    if (!GetQueuedCompletionStatusEx(g_hVerifyIocp, vEntries, GQCSEx_BATCH_SIZE, &numGot, 500, FALSE))
      continue;
    for (ULONG vi = 0; vi < numGot; vi++) {
      key = vEntries[vi].lpCompletionKey;
      ov = vEntries[vi].lpOverlapped;
      if (key == KEY_TERMINATE)
        continue; /* 批末统一退出，避免跳过同批 VERIFY 任务 */
      if (key == KEY_VERIFY && ov) {
      VerifyTask *vt = (VerifyTask *)ov;
      BYTE dstHash[16], srcHash[16];
      LONGLONG fsize = vt->FileSize;
      if (fsize <= 0) {
        WIN32_FILE_ATTRIBUTE_DATA fa;
        if (GetFileAttributesExW(vt->DstPath, GetFileExInfoStandard, &fa))
          fsize = ((LONGLONG)fa.nFileSizeHigh << 32) | fa.nFileSizeLow;
      }
      BOOL dstHashOk = (fsize >= GetSampleThreshold() && g_Config.SampleLargeFiles)
          ? CalculateFileHashSampled(vt->DstPath, dstHash, fsize, vp, TRUE)
          : CalculateFileHashWithVerifyParam(vt->DstPath, dstHash, vp);
      BOOL verifyPass = FALSE;
      if (g_Config.PerfectVerify && vt->SrcPath && dstHashOk) {
        /* P2: 完美校验，Src+Dest 双读，检测临时错误 */
        BOOL srcHashOk = (fsize >= GetSampleThreshold() && g_Config.SampleLargeFiles)
            ? CalculateFileHashSampled(vt->SrcPath, srcHash, fsize, vp, TRUE)
            : CalculateFileHashWithVerifyParam(vt->SrcPath, srcHash, vp);
        verifyPass = srcHashOk && (memcmp(srcHash, dstHash, 16) == 0);
      } else {
        verifyPass = dstHashOk && (memcmp(vt->ExpectedHash, dstHash, 16) == 0);
      }
      if (verifyPass) {
        InterlockedIncrement(&g_Md5Success);
        /* P3: fc_verify 交换数据流，记录校验信息供后续无声损坏检测 */
        if (g_Config.AddVerifyInfo && vt->DstPath) {
          wchar_t streamPath[MAX_PATH_EXT];
          if (wcslen(vt->DstPath) + 16 < MAX_PATH_EXT) {
            StringCchPrintfW(streamPath, MAX_PATH_EXT, L"%ls:fc_verify", vt->DstPath);
            SYSTEMTIME st;
            GetLocalTime(&st);
            char hashHex[33];
            for (int hi = 0; hi < 16; hi++)
              snprintf(hashHex + hi * 2, 3, "%02x", (unsigned char)(g_Config.PerfectVerify && vt->SrcPath ? srcHash[hi] : vt->ExpectedHash[hi]));
            hashHex[32] = '\0';
            char info[256];
            snprintf(info, sizeof(info), "{done=%04d-%02d-%02d %02d:%02d:%02d,size=%lld,xxHash=%s}",
                (int)st.wYear, (int)st.wMonth, (int)st.wDay,
                (int)st.wHour, (int)st.wMinute, (int)st.wSecond,
                (long long)fsize, hashHex);
            HANDLE hStream = CreateFileW(streamPath, GENERIC_WRITE, 0, NULL,
                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hStream != INVALID_HANDLE_VALUE) {
              DWORD wr;
              WriteFile(hStream, info, (DWORD)strlen(info), &wr, NULL);
              CloseHandle(hStream);
            }
          }
        }
      } else {
        InterlockedIncrement(&g_Md5Fail);
        BOOL hashOk = dstHashOk;
        if (!hashOk)
          LogMessage(LOG_WARNING, L"[VERIFY] Hash calc failed (I/O): %ls\n", vt->DstPath);
        else
          LogMessage(LOG_ERROR, L"[VERIFY FAIL] Corruption detected: %ls\n", vt->DstPath);
        /* P2: 校验错误时重命名为 .fc_verify_err */
        if (hashOk && g_Config.VerifyErrRename && vt->DstPath) {
          wchar_t errPath[MAX_PATH_EXT];
          if (wcslen(vt->DstPath) + 20 < MAX_PATH_EXT) {
            StringCchPrintfW(errPath, MAX_PATH_EXT, L"%ls.fc_verify_err", vt->DstPath);
            MoveFileExW(vt->DstPath, errPath, MOVEFILE_REPLACE_EXISTING);
          }
        }
        if (hashOk && vt->SrcPath && g_DeadLetterQueue &&
            !g_Config.IsFtpDest && !g_NoDLQ) {
          DeleteFileW(vt->DstPath);
          CopyTask *retryTask = AllocCopyTask();
          if (retryTask) {
            size_t lenS = wcslen(vt->SrcPath), lenD = wcslen(vt->DstPath);
            if (lenS < MAX_PATH && lenD < MAX_PATH) {
              StringCchCopyW(retryTask->ShortSrc, MAX_PATH, vt->SrcPath);
              StringCchCopyW(retryTask->ShortDst, MAX_PATH, vt->DstPath);
              retryTask->SrcPath = retryTask->ShortSrc;
              retryTask->DstPath = retryTask->ShortDst;
              retryTask->pathFlags = TASK_PATH_FLAG_SRC_SHORT | TASK_PATH_FLAG_DST_SHORT;
            } else {
              retryTask->SrcPath = _wcsdup(vt->SrcPath);
              retryTask->DstPath = _wcsdup(vt->DstPath);
              retryTask->pathFlags = 0; /* malloc 路径，FreeAllPools 时 free */
              if (!retryTask->SrcPath || !retryTask->DstPath) {
                if (retryTask->SrcPath) free(retryTask->SrcPath);
                if (retryTask->DstPath) free(retryTask->DstPath);
                FreeCopyTask(retryTask);
                retryTask = NULL;
              }
            }
            if (retryTask) {
              retryTask->FileSize = (LONG64)fsize;
              retryTask->FileAttributes = vt->FileAttributes;
              retryTask->pSrcBackend = VFS_GetBackend(retryTask->SrcPath);
              retryTask->pDstBackend = VFS_GetBackend(retryTask->DstPath);
              InterlockedPushEntrySList(g_DeadLetterQueue, &retryTask->ItemEntry);
            }
          }
        }
      }
      if (vt->SrcPath && vt->SrcPath != vt->ShortSrc)
        free(vt->SrcPath);
      vt->SrcPath = NULL;
      if (vt->DstPath && vt->DstPath != vt->ShortDst)
        free(vt->DstPath);
      vt->DstPath = NULL;
      if (g_VerifyTaskPool)
        InterlockedPushEntrySList(g_VerifyTaskPool, (PSLIST_ENTRY)vt);
      else
        PB_ALIGNED_FREE(vt);
      InterlockedDecrement(&g_PendingVerify);
    }
    }
    for (ULONG vi = 0; vi < numGot; vi++) {
      if (vEntries[vi].lpCompletionKey == KEY_TERMINATE)
        goto verify_exit;
    }
  }
verify_exit:
  if (hVerifyMmcss) {
    HMODULE hAvrt = GetModuleHandleW(L"avrt.dll");
    if (hAvrt) {
      typedef BOOL (WINAPI *PAvRevert)(HANDLE);
      PAvRevert pRevert = (PAvRevert)GetProcAddress(hAvrt, "AvRevertMmThreadCharacteristics");
      if (pRevert) pRevert(hVerifyMmcss);
    }
  }
  return 0;
}

static void PostVerifyTask(const wchar_t *dst, const BYTE *expectedHash) {
  PostVerifyTaskEx(dst, expectedHash, 0);
}
static void PostVerifyTaskEx(const wchar_t *dst, const BYTE *expectedHash,
                             LONGLONG fileSize) {
  PostVerifyTaskExForRetry(dst, expectedHash, fileSize, NULL, 0);
}
static void PostVerifyTaskExForRetry(const wchar_t *dst, const BYTE *expectedHash,
    LONGLONG fileSize, const wchar_t *src, DWORD fileAttributes) {
  if (!g_hVerifyIocp)
    return;
  if (IsCanceling())
    return;
  while (g_PendingVerify >= g_MaxQueueDepth && !IsCanceling())
    Sleep(1); /* 防洪堤：验证队列积压时挂起拷贝线程，防止内存池击穿 */
  VerifyTask *vt = NULL;
  while (!vt) {
    if (g_VerifyTaskPool) {
      PSLIST_ENTRY e = InterlockedPopEntrySList(g_VerifyTaskPool);
      vt = e ? (VerifyTask *)e : NULL;
    }
    if (!vt)
      vt = (VerifyTask *)_aligned_malloc(sizeof(VerifyTask), 16);
    if (!vt)
      Sleep(10); /* 绝不静默放弃：内存枯竭时退让，死等直到分配成功 */
  }
  vt->SrcPath = NULL;
  vt->FileAttributes = 0;
  if (wcslen(dst) < MAX_PATH) {
    StringCchCopyW(vt->ShortDst, MAX_PATH, dst);
    vt->DstPath = vt->ShortDst;
  } else {
    vt->DstPath = _wcsdup(dst);
    if (!vt->DstPath) {
      if (!g_VerifyTaskPool)
        PB_ALIGNED_FREE(vt);
      else
        InterlockedPushEntrySList(g_VerifyTaskPool, (PSLIST_ENTRY)vt);
      return;
    }
  }
  if (src && src[0]) {
    if (wcslen(src) < MAX_PATH) {
      StringCchCopyW(vt->ShortSrc, MAX_PATH, src);
      vt->SrcPath = vt->ShortSrc;
    } else {
      vt->SrcPath = _wcsdup(src);
      if (!vt->SrcPath) {
        if (vt->DstPath != vt->ShortDst) free((void *)vt->DstPath);
        if (!g_VerifyTaskPool) PB_ALIGNED_FREE(vt);
        else InterlockedPushEntrySList(g_VerifyTaskPool, (PSLIST_ENTRY)vt);
        return;
      }
    }
    vt->FileAttributes = fileAttributes;
  }
  memcpy(vt->ExpectedHash, expectedHash, 16);
  vt->FileSize = fileSize;
  InterlockedIncrement(&g_PendingVerify);
  PostQueuedCompletionStatus(g_hVerifyIocp, 0, KEY_VERIFY, (LPOVERLAPPED)vt);
}

BOOL CheckIncrementalSync(const CopyTask *task, CopierParam *param) {
  if (!g_Config.CompareMTime && !g_Config.CompareSize &&
      !g_Config.CompareContent)
    return FALSE;
  WIN32_FILE_ATTRIBUTE_DATA d;
  if (!GetFileAttributesExW(task->DstPath, GetFileExInfoStandard, &d)) {
    InterlockedIncrement(&g_StateLonely);
    return FALSE;
  }
  LONG64 dstSize = ((LONG64)d.nFileSizeHigh << 32) | d.nFileSizeLow;
  /* 尺寸铁律：无论任何增量模式，大小不同则数据必不同，绝对不能跳过 */
  if (task->FileSize != dstSize) {
    InterlockedIncrement(&g_StateOlder);
    return FALSE;
  }
  if (g_Config.CompareMTime) {
    int cmp = CompareFileTime(&task->LastWriteTime, &d.ftLastWriteTime);
    if (cmp != 0 && g_Config.TimeAllowMs > 0) {
      /* P1: 时间戳容差，NAS/FAT 等精度不足时视为相同 */
      ULARGE_INTEGER u1, u2;
      u1.LowPart = task->LastWriteTime.dwLowDateTime;
      u1.HighPart = task->LastWriteTime.dwHighDateTime;
      u2.LowPart = d.ftLastWriteTime.dwLowDateTime;
      u2.HighPart = d.ftLastWriteTime.dwHighDateTime;
      LONGLONG diff = (LONGLONG)(u1.QuadPart - u2.QuadPart);
      if (diff < 0) diff = -diff;
      if (diff > (LONGLONG)g_Config.TimeAllowMs * 10000) {  /* 100ns 单位，1ms=10000 */
        InterlockedIncrement(&g_StateOlder);
        return FALSE;
      }
    } else if (cmp != 0) {
      InterlockedIncrement(&g_StateOlder);
      return FALSE;
    }
  }
  if (g_Config.CompareContent) {
    /* 【逻辑短路】：差异传输+大文件时跳过全量哈希，交给 CopyBigFileDelta 块级对比
     * 否则 500GB 文件会读 2 遍（CheckIncrementalSync 1 遍 + Delta 1 遍）= 2TB 流量 */
    if (g_Config.UseDeltaTransfer && task->FileSize >= SPLIT_THRESHOLD) {
      InterlockedIncrement(&g_StateOlder);
      return FALSE;
    }
    /* 【致命修复】增量判定必须 100% 全量哈希，绝对禁止抽样！ */
    BYTE hS[16], hD[16];
    if (!CalculateFileHash(task->SrcPath, hS, param) ||
        !CalculateFileHash(task->DstPath, hD, param) ||
        memcmp(hS, hD, 16) != 0) {
      InterlockedIncrement(&g_StateOlder);
      return FALSE;
    }
    InterlockedIncrement(&g_Md5Success);
  }
  return TRUE;
}

/* 启动时一次性判定同卷，支持 hard link 需要此判断 */
static BOOL IsVolumeBlockCloneSupported(const wchar_t *path);
void InitSameVolumeCache(const wchar_t *src, const wchar_t *dst) {
  wchar_t volSrc[MAX_PATH_EXT], volDst[MAX_PATH_EXT];
  g_IsSameVolume = FALSE;
  g_BlockCloneProbed = FALSE;
  g_CanBlockClone = FALSE;
  g_BlockCloneAlignSize = 4096;
  g_BlockCloneVolSerial = 0;
  if (!GetVolumePathNameW(src, volSrc, MAX_PATH_EXT) ||
      !GetVolumePathNameW(dst, volDst, MAX_PATH_EXT))
    return;
  g_IsSameVolume = (_wcsicmp(volSrc, volDst) == 0);
  
  /* V123: 物理磁盘索引探测，处理同一 HDD 多分区争抢问题 */
  g_Config.SrcDriveIndex = GetPhysicalDiskIndex(src);
  g_Config.DstDriveIndex = GetPhysicalDiskIndex(dst);
  g_Config.IsSamePhysicalHDD = FALSE;
  
  if (g_Config.SrcDriveIndex >= 0 && g_Config.SrcDriveIndex == g_Config.DstDriveIndex) {
    /* 同一物理磁盘，如果是 HDD 则标记为 SamePhysicalHDD */
    if (!g_Config.IsSSD) {
      g_Config.IsSamePhysicalHDD = TRUE;
    }
  }
  /* advice1 P2: 同卷时一次探测 BlockClone 能力/簇对齐/序列号 */
  if (g_IsSameVolume && !IsUncPath(src) && !IsUncPath(dst)) {
    DWORD serS = 0, serD = 0;
    BOOL okS = IsVolumeBlockCloneSupported(src);
    BOOL okD = IsVolumeBlockCloneSupported(dst);
    BOOL serOk = GetVolumeSerialNumberFromPath(src, &serS) &&
                 GetVolumeSerialNumberFromPath(dst, &serD) && serS == serD;
    DWORD csS = ProbeClusterSizeEx(src);
    DWORD csD = ProbeClusterSizeEx(dst);
    DWORD align = (csS >= csD) ? csS : csD;
    if (align < 512) align = 512;
    g_CanBlockClone = (okS && okD && serOk) ? TRUE : FALSE;
    g_BlockCloneAlignSize = align;
    g_BlockCloneVolSerial = serS;
    g_BlockCloneProbed = TRUE;
  } else {
    g_BlockCloneProbed = TRUE;
    g_CanBlockClone = FALSE;
  }
}

/* 尝试硬链接（同卷时零拷贝）；-i 时用临时路径+原子覆盖，不删占位符 */
static BOOL TryCreateHardLink(const wchar_t *src, const wchar_t *dst) {
  if (!g_IsSameVolume)
    return FALSE;
  wchar_t tempDst[MAX_PATH_EXT];
  if (wcslen(dst) + 6 >= MAX_PATH_EXT)
    return FALSE;
  StringCchPrintfW(tempDst, MAX_PATH_EXT, L"%ls.hlnk", dst);
  if (!CreateHardLinkW(tempDst, src, NULL))
    return FALSE;
  if (MoveFileExW(tempDst, dst, MOVEFILE_REPLACE_EXISTING))
    return TRUE;
  DeleteFileW(tempDst);
  return FALSE;
}

/* 按需创建目标文件的父目录；支持 UNC (\\server\share) 与盘符路径
 * 目标目录无锁缓存：同目录百万文件时跳过重复 GetFileAttributesW
 * parentLen>0 时透传父目录长度省 wcsrchr，0 则内部计算 */
void EnsureParentDirExistsEx(const wchar_t *filePath, size_t parentLen) {
  wchar_t path[MAX_PATH_EXT];
  if (parentLen == 0) {
    StringCchCopyW(path, MAX_PATH_EXT, filePath);
    wchar_t *lastSlash = wcsrchr(path, L'\\');
    if (!lastSlash || lastSlash <= path)
      return;
    *lastSlash = L'\0';
    parentLen = wcslen(path);
  } else {
    if (parentLen >= MAX_PATH_EXT)
      return;
    StringCchCopyNW(path, MAX_PATH_EXT, filePath, parentLen);
    path[parentLen] = L'\0';
  }
  size_t pathLen = parentLen;
  /* 快路径 parentLen = fullDstLen - nameLen - 1 对「\\?\D:\foo」会得到「\\?\D:」少一字节反斜杠；
   * CreateDirectoryW(\\?\D:) 失败 (常见 error 5)，根目录下大量子项时日志洪峰并可能拖垮后续 I/O。 */
  if (pathLen == 6 && wcsncmp(path, L"\\\\?\\", 4) == 0 && path[4] && path[5] == L':' &&
      path[6] == L'\0' && pathLen + 1 < MAX_PATH_EXT) {
    path[6] = L'\\';
    path[7] = L'\0';
    pathLen = 7;
  }
  if (CheckDstDirCacheEx(path, pathLen))
    return;
  if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) {
    AddDstDirCacheEx(path, pathLen);
    return;
  }
  int skipSlashes = 0;
  if (IsUncPath(path)) {
    if (wcsncmp(path, L"\\\\?\\UNC\\", 8) == 0)
      skipSlashes = 6; /* 跳过 \\?\UNC\Server\Share 的 6 个基础斜杠 */
    else
      skipSlashes = 4; /* 跳过 \\Server\Share 的 4 个基础斜杠 */
  } else if (wcsncmp(path, L"\\\\?\\", 4) == 0 && path[4] && path[5] == L':') {
    skipSlashes = 4; /* 本地长路径 \\?\C:\ 跳过前 4 个斜杠，避免无效 CreateDirectoryW */
  }
  int slashCount = 0;
  for (wchar_t *p = path; *p; p++) {
    if (*p != L'\\')
      continue;
    slashCount++;
    if (slashCount <= skipSlashes)
      continue;
    if (p > path && *(p - 1) == L':')
      continue;
    *p = L'\0';
    if (!CreateDirectoryW(path, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
      LogMessage(LOG_WARNING, L"[EnsureParentDirExists] CreateDirectoryW failed: "
                              L"%ls (error %lu)\n", path, (unsigned long)GetLastError());
    else
      AddDstDirCacheEx(path, (size_t)(p - path));
    *p = L'\\';
  }
  if (!CreateDirectoryW(path, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
    LogMessage(LOG_WARNING, L"[EnsureParentDirExists] CreateDirectoryW failed: "
                            L"%ls (error %lu)\n", path, (unsigned long)GetLastError());
  AddDstDirCacheEx(path, pathLen);
}
#define EnsureParentDirExists(path) EnsureParentDirExistsEx((path), 0)

/* 扁平化模式下，用 CREATE_NEW 原子抢占路径；CREATE_NEW 内核级原子，无需锁 */
static void ReserveUniqueFlatPath(CopyTask *task) {
  if (!g_Config.FlattenDir || !task->DstPath)
    return;
  wchar_t candidate[MAX_PATH_EXT];
  const wchar_t *base = task->DstPath;
  wchar_t *slash = wcsrchr(base, L'\\');
  wchar_t *fname = slash ? (slash + 1) : (wchar_t *)base;
  wchar_t *dot = wcsrchr(fname, L'.');
  for (int n = 0; n < 10000; n++) {
    if (n == 0)
      StringCchCopyW(candidate, MAX_PATH_EXT, base);
    else if (dot && dot > fname) {
      StringCchPrintfW(candidate, MAX_PATH_EXT, L"%.*ls(%d)%ls",
                       (int)(dot - base), base, n, dot);
    } else
      StringCchPrintfW(candidate, MAX_PATH_EXT, L"%ls(%d)", base, n);
    HANDLE h = CreateFileW(candidate, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                          FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (h != INVALID_HANDLE_VALUE) {
      CloseHandle(h);
      if (n > 0) {
        if (task->DstPath != task->ShortDst)
          free((void *)task->DstPath);
        task->DstPath = _wcsdup(candidate);
      }
      return;
    }
    DWORD err = GetLastError();
    if (err != ERROR_ALREADY_EXISTS && err != ERROR_SHARING_VIOLATION)
      break;
  }
}

static void CopyAlternateDataStreams(const wchar_t *src, const wchar_t *dst) {
  if ((g_Config.FastMode && !g_Config.MetadataOnly) || g_Config.IsFtpSource || g_Config.IsFtpDest)
    return;
  /* 99.999% 目录无 ADS，跳过百万次无效 FindFirstStreamW，消除关机卡顿 */
  DWORD attr = GetFileAttributesW(src);
  if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
    return;
  typedef HANDLE(WINAPI *FindFirstStreamWFn)(LPCWSTR, STREAM_INFO_LEVELS, LPVOID, DWORD);
  typedef BOOL(WINAPI *FindNextStreamWFn)(HANDLE, LPVOID);
  static FindFirstStreamWFn pFindFirst = NULL;
  static FindNextStreamWFn pFindNext = NULL;
  if (!pFindFirst) {
    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    pFindFirst = (FindFirstStreamWFn)GetProcAddress(hK32, "FindFirstStreamW");
    pFindNext = (FindNextStreamWFn)GetProcAddress(hK32, "FindNextStreamW");
  }
  if (!pFindFirst || !pFindNext)
    return;
  WIN32_FIND_STREAM_DATA fsd;
  HANDLE hFind = pFindFirst(src, FindStreamInfoStandard, &fsd, 0);
  if (hFind == INVALID_HANDLE_VALUE)
    return;
  BYTE buf[8192]; /* 栈分配，ADS 多为 Zone.Identifier(26B)，8KB 足矣，消除百万次堆争用 */
  do {
    if (wcscmp(fsd.cStreamName, L"::$DATA") == 0)
      continue;
    wchar_t srcStream[MAX_PATH_EXT], dstStream[MAX_PATH_EXT];
    if (wcslen(src) + wcslen(fsd.cStreamName) >= MAX_PATH_EXT ||
        wcslen(dst) + wcslen(fsd.cStreamName) >= MAX_PATH_EXT)
      continue;
    StringCchPrintfW(srcStream, MAX_PATH_EXT, L"%ls%ls", src, fsd.cStreamName);
    StringCchPrintfW(dstStream, MAX_PATH_EXT, L"%ls%ls", dst, fsd.cStreamName);
    HANDLE hSrc = CreateFileW(srcStream, GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hSrc == INVALID_HANDLE_VALUE)
      continue;
    HANDLE hDst = CreateFileW(dstStream, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY |
                             FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hDst == INVALID_HANDLE_VALUE) {
      CloseHandle(hSrc);
      continue;
    }
    LONGLONG rem = fsd.StreamSize.QuadPart;
    while (rem > 0) {
      DWORD toRead = (DWORD)min(rem, 8192);
      DWORD rd, wr;
      if (!ReadFile(hSrc, buf, toRead, &rd, NULL) || rd == 0)
        break;
      if (!WriteFile(hDst, buf, rd, &wr, NULL) || wr != rd)
        break;
      rem -= rd;
    }
    CloseHandle(hSrc);
    CloseHandle(hDst);
  } while (pFindNext(hFind, &fsd));
  FindClose(hFind);
}

/* advice1 P0: Close 前一次 FileBasicInfo，折叠再开 SetFileTime IRP */
static void ApplyFileBasicInfoBeforeClose(HANDLE hDst, const CopyTask *task, CopierParam *param) {
  if (!task || hDst == INVALID_HANDLE_VALUE || hDst == NULL)
    return;
  if (g_Config.FastMode && !g_Config.MetadataOnly)
    return;
  FILE_BASIC_INFO bi;
  memset(&bi, 0, sizeof(bi));
  bi.CreationTime.LowPart = task->CreationTime.dwLowDateTime;
  bi.CreationTime.HighPart = (LONG)task->CreationTime.dwHighDateTime;
  bi.LastAccessTime.LowPart = task->LastAccessTime.dwLowDateTime;
  bi.LastAccessTime.HighPart = (LONG)task->LastAccessTime.dwHighDateTime;
  bi.LastWriteTime.LowPart = task->LastWriteTime.dwLowDateTime;
  bi.LastWriteTime.HighPart = (LONG)task->LastWriteTime.dwHighDateTime;
  bi.ChangeTime = bi.LastWriteTime;
  DWORD attrs = task->FileAttributes;
  if (attrs == 0)
    attrs = FILE_ATTRIBUTE_NORMAL;
  attrs &= ~(FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT);
  if (attrs == 0)
    attrs = FILE_ATTRIBUTE_NORMAL;
  bi.FileAttributes = attrs;
  if (SetFileInformationByHandle(hDst, FileBasicInfo, &bi, sizeof(bi))) {
    if (param)
      param->TimestampsAlreadySet = TRUE;
  }
}

static void CopyFileSecurityAndAttributesEx(const wchar_t *src, const wchar_t *dst,
    const CopyTask *task, BOOL timestampsAlreadySet, CopierParam *param) {
  /* -F 时跳过元数据以提速；但 -M 模式的本职就是写 ACL/时间戳/属性，绝不能被 -F 短路 */
  if (g_Config.FastMode && !g_Config.MetadataOnly)
    return;
  if (!g_Config.SkipAds)
    CopyAlternateDataStreams(src, dst);
  SetFileAttributesW(dst, FILE_ATTRIBUTE_NORMAL);
  if (!timestampsAlreadySet) {
    DWORD access = GENERIC_WRITE;
    if (g_Config.CopyAcl)
      access |= WRITE_DAC;
    if (g_Config.CopyAllSecurity)
      access |= WRITE_OWNER;
    HANDLE h = CreateFileW(dst, access, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (h != INVALID_HANDLE_VALUE) {
      if (!SetFileTime(h, &task->CreationTime, &task->LastAccessTime, &task->LastWriteTime))
        LogMessage(LOG_WARNING, L"[CopyFileSecurityAndAttributes] SetFileTime failed: %ls (err=%lu)\n",
                   dst, (unsigned long)GetLastError());
      CloseHandle(h);
    }
  }
  if (g_Config.CopyAcl) {
    DWORD req = g_Config.CopyAllSecurity
        ? (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
           DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION)
        : DACL_SECURITY_INFORMATION;
    const wchar_t *srcSlash = wcsrchr(src, L'\\');
    size_t srcParentLen = (srcSlash && srcSlash > src) ? (size_t)(srcSlash - src) : 0;
    if (param && param->SdCacheValid && param->SdCacheBlob && srcParentLen > 0 &&
        srcParentLen == param->SdCacheSrcParentLen && srcParentLen < MAX_PATH &&
        wcsncmp(param->SdCacheSrcParent, src, srcParentLen) == 0) {
      if (!SetFileSecurityW(dst, req, param->SdCacheBlob))
        LogMessage(LOG_WARNING, L"[CopyFileSecurityAndAttributes] SetFileSecurityW failed: %ls (err=%lu)\n",
                   dst, (unsigned long)GetLastError());
    } else {
      DWORD l = 0;
      if (!GetFileSecurityW(src, req, NULL, 0, &l) &&
          GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        ;
      else if (l > 0) {
        PSECURITY_DESCRIPTOR p = (PSECURITY_DESCRIPTOR)malloc(l);
        if (p && GetFileSecurityW(src, req, p, l, &l)) {
          if (!SetFileSecurityW(dst, req, p))
            LogMessage(LOG_WARNING, L"[CopyFileSecurityAndAttributes] SetFileSecurityW failed: %ls (err=%lu)\n",
                       dst, (unsigned long)GetLastError());
          if (param && srcParentLen > 0 && srcParentLen < MAX_PATH) {
            if (param->SdCacheBlob) free(param->SdCacheBlob);
            param->SdCacheBlob = p;
            param->SdCacheLen = l;
            param->SdCacheHash = XXH3_64bits(p, l);
            param->SdCacheValid = TRUE;
            memcpy(param->SdCacheSrcParent, src, srcParentLen * sizeof(wchar_t));
            param->SdCacheSrcParent[srcParentLen] = L'\0';
            param->SdCacheSrcParentLen = srcParentLen;
            p = NULL;
          }
        }
        if (p) free(p);
      }
    }
  }
  if (!SetFileAttributesW(dst, task->FileAttributes))
    LogMessage(LOG_WARNING, L"[CopyFileSecurityAndAttributes] SetFileAttributesW failed: %ls (err=%lu)\n",
               dst, (unsigned long)GetLastError());
}

void CopyFileSecurityAndAttributes(const wchar_t *src, const wchar_t *dst,
                                   const CopyTask *task) {
  CopyFileSecurityAndAttributesEx(src, dst, task, FALSE, NULL);
}

/* DirMeta 收尾：必须先处理深层目录再处理祖先。多线程扫描时 SLIST 入栈顺序不确定，若先 SetFileTime
 * 父目录再处理子目录，NTFS 上子项元数据更新可能刷新父目录 mtime，导致“文件时间对、文件夹时间不对”。 */
static int CompareDirMetaTaskByDstDepthDesc(const void *a, const void *b) {
  const DirMetaTask *const *pa = (const DirMetaTask *const *)a;
  const DirMetaTask *const *pb = (const DirMetaTask *const *)b;
  uint32_t la = (*pa)->DstLen;
  uint32_t lb = (*pb)->DstLen;
  if (la != lb)
    return (la > lb) ? -1 : 1;
  if ((*pa)->DstPath && (*pb)->DstPath)
    return wcscmp((*pa)->DstPath, (*pb)->DstPath);
  return 0;
}

#define DELTA_BLOCK_SIZE (1024 * 1024) /* 1MB 块，XXH3 差异判定 */
#define MMF_WINDOW_SIZE (256 * 1024 * 1024) /* OPT-06: 256MB 滑动窗口，消除 1MB 级 Map/Unmap TLB 颠簸 */
/* 差异块传输：异步 OVERLAPPED 双缓冲预读，src 读与 dst 比较/写并行流水
 * 流水线：等待 src[N] 完成时，同时 dst[N] 同步读 + 启动 src[N+1] 异步预读
 * 相比纯同步版，NVMe 下可削减 ~50% 延迟等待，1GB/s+ 网络备份受益最大 */
static BOOL CopyBigFileDelta(const wchar_t *src, const wchar_t *dst,
                             LONGLONG fileSize, CopierParam *param,
                             DWORD fileAttributes) {
  BOOL success = TRUE;
  /* OPT-02: src 可加 FILE_FLAG_NO_BUFFERING；若扇区几何未 IOCTL 证实则保守用缓冲读 */
  DWORD srcOpenFlags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED;
  if (g_BigFileUseDirectIo)
    srcOpenFlags |= FILE_FLAG_NO_BUFFERING;
  HANDLE hSrc = CreateFileW(src, GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      NULL, OPEN_EXISTING, srcOpenFlags, NULL);
  /* dst 保留缓冲 I/O：仅差异块写入，访问模式非纯顺序，无需 NO_BUFFERING */
  HANDLE hDst = CreateFileW(dst, GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hSrc == INVALID_HANDLE_VALUE || hDst == INVALID_HANDLE_VALUE) {
    if (hSrc != INVALID_HANDLE_VALUE) CloseHandle(hSrc);
    if (hDst != INVALID_HANDLE_VALUE) CloseHandle(hDst);
    return FALSE;
  }
  if (g_BigFileUseDirectIo)
    TryEnableBypassIO(hSrc);  /* Phase 17：Win11+ NVMe 直通，剥离 Filter Driver */
  LARGE_INTEGER liSize;
  if (!GetFileSizeEx(hDst, &liSize) || liSize.QuadPart != fileSize) {
    CloseHandle(hSrc);
    CloseHandle(hDst);
    return FALSE;
  }
  /* OPT-04: dst 用内存映射替代同步 ReadFile，利用 OS 缺页预读，避免 HDD 目标端阻塞流水线 */
  HANDLE hDstMap = CreateFileMappingW(hDst, NULL, PAGE_READONLY,
      (DWORD)(fileSize >> 32), (DWORD)(fileSize & 0xFFFFFFFF), NULL);
  BOOL useMapView = (hDstMap != NULL && hDstMap != INVALID_HANDLE_VALUE);
  if (!useMapView && hDstMap) { CloseHandle(hDstMap); hDstMap = NULL; }
  /* OPT-02: 大页优先（≥2MB 用 MEM_LARGE_PAGES 降低 TLB 漫步），失败降级 VirtualAlloc
   * 3 槽：srcBuf[0]/srcBuf[1] ping-pong 双槽，dstBuf 单槽 */
  BigBufferObj *deltaBufObj = NULL;
  BYTE *buf = NULL;
  if (g_BigBufferPool && g_BigBufferSize >= (DWORD)(DELTA_BLOCK_SIZE * 3)) {
    PSLIST_ENTRY e = InterlockedPopEntrySList(g_BigBufferPool);
    if (e) {
      deltaBufObj = (BigBufferObj *)e;
      buf = deltaBufObj->Buffer;
    }
  }
  if (!buf)
    buf = (BYTE *)AllocBufferWithLargePagesFallback(DELTA_BLOCK_SIZE * 3);
  HANDLE hEvt[2] = { CreateEvent(NULL, TRUE, FALSE, NULL),
                     CreateEvent(NULL, TRUE, FALSE, NULL) };
  /* 仅在 CompareContent 开启时才分配 XXH3 状态，避免 -Y 不配合 -X 时的无效 malloc */
  BOOL doFullHash = g_Config.CompareContent;
  XXH3_state_t *fullState = doFullHash ? XXH3_createState() : NULL;
  if (!buf || !hEvt[0] || !hEvt[1] || (doFullHash && !fullState)) {
    success = FALSE;
    goto DeltaCleanup;
  }
  BYTE *srcBuf[2] = { buf, buf + DELTA_BLOCK_SIZE };
  BYTE *dstBuf = buf + DELTA_BLOCK_SIZE * 2;
  OVERLAPPED olSrc[2];
  memset(olSrc, 0, sizeof(olSrc));
  olSrc[0].hEvent = hEvt[0];
  olSrc[1].hEvent = hEvt[1];
  if (fullState) XXH3_128bits_reset(fullState);

  LONGLONG offset = 0;
  LONGLONG totalWritten = 0;
  int cur = 0, nxt = 1;
  BOOL hasUnprocessedRead = FALSE; /* olSrc[cur] 是否有已启动但未等待的读 */
  /* OPT-06: 256MB 滑动窗口，offset 超出当前窗口时 Unmap 并重新 Map，减少 Map/Unmap 次数 */
  LONGLONG mapWindowStart = -1;
  BYTE *pMapView = NULL;
  SIZE_T mapWindowLen = 0;

  /* OPT-02: NO_BUFFERING 要求读取长度为扇区倍数；最后一块可能非对齐，需向上取整 */
#define DELTA_ALIGN_UP(n) (((DWORD)(n) + g_SectorSize - 1) & ~((DWORD)(g_SectorSize - 1)))

  /* 启动首块异步读 */
  {
    DWORD first = (DWORD)min((LONGLONG)DELTA_BLOCK_SIZE, fileSize);
    DWORD firstAligned = DELTA_ALIGN_UP(first);
    olSrc[cur].Offset = 0;
    olSrc[cur].OffsetHigh = 0;
    ResetEvent(hEvt[cur]);
    BOOL ok = ReadFile(hSrc, srcBuf[cur], firstAligned, NULL, &olSrc[cur]);
    if (!ok && GetLastError() != ERROR_IO_PENDING) {
      success = FALSE;
      goto DeltaCleanup;
    }
    hasUnprocessedRead = TRUE;
  }

  while (offset < fileSize && success) {
    if (IsCanceling()) { success = FALSE; break; }
    LONGLONG toRead = min((LONGLONG)DELTA_BLOCK_SIZE, fileSize - offset);
    DWORD rd;

    /* 等待当前槽 src 异步读完成；rd >= toRead（末块可能多读了对齐填充字节） */
    if (!GetOverlappedResult(hSrc, &olSrc[cur], &rd, TRUE) || rd < (DWORD)toRead) {
      hasUnprocessedRead = FALSE;
      success = FALSE;
      break;
    }
    hasUnprocessedRead = FALSE;

    /* 立即启动下一块异步预读（流水线核心：与 dst 读/比较/写并行） */
    LONGLONG nextOff = offset + toRead;
    if (nextOff < fileSize && !IsCanceling()) {
      DWORD nextSz = (DWORD)min((LONGLONG)DELTA_BLOCK_SIZE, fileSize - nextOff);
      DWORD nextSzAligned = DELTA_ALIGN_UP(nextSz);
      olSrc[nxt].Offset = (DWORD)nextOff;
      olSrc[nxt].OffsetHigh = (DWORD)(nextOff >> 32);
      ResetEvent(hEvt[nxt]);
      BOOL ok = ReadFile(hSrc, srcBuf[nxt], nextSzAligned, NULL, &olSrc[nxt]);
      if (ok || GetLastError() == ERROR_IO_PENDING)
        hasUnprocessedRead = TRUE; /* nxt 槽有飞行中 I/O，循环末尾 swap 后变 cur */
    }

    /* 处理当前块：哈希 + 读 dst + 比较 + 按需写（与 nxt 预读并行）
     * 注意：NO_BUFFERING 末块 rd 可能大于 toRead（含零填充），哈希只能算真实文件字节 toRead
     * OPT-04: MapViewOfFile 利用缺页预读，避免同步 ReadFile 阻塞；网络盘等不支持时回退 ReadFile
     * MMF 高水位：限制同时映射总量≤2GB，防止千万碎文件耗尽虚拟地址空间 */
    AcquireBandwidthTokens(toRead);
    if (fullState) XXH3_128bits_update(fullState, srcBuf[cur], (size_t)toRead);
    XXH128_hash_t hashSrc = XXH3_128bits(srcBuf[cur], (size_t)toRead);

    LARGE_INTEGER li;
    li.QuadPart = offset;
    DWORD rdDst = (DWORD)toRead;
    if (useMapView) {
      LONGLONG alignedStart = (offset / MMF_WINDOW_SIZE) * MMF_WINDOW_SIZE;
      if (alignedStart != mapWindowStart || !pMapView) {
        if (pMapView) {
          UnmapViewOfFile(pMapView);
          pMapView = NULL;
          if (g_hMMFMapSemaphore && mapWindowLen > 0) {
            LONG rel = (LONG)((mapWindowLen + 1024 * 1024 - 1) / (1024 * 1024));
            if (rel > 0) ReleaseSemaphore(g_hMMFMapSemaphore, rel, NULL);
          }
        }
        mapWindowStart = alignedStart;
        mapWindowLen = (SIZE_T)min((LONGLONG)MMF_WINDOW_SIZE, fileSize - alignedStart);
        if (mapWindowLen > 0) {
          LONG mmfTokens = (LONG)((mapWindowLen + 1024 * 1024 - 1) / (1024 * 1024));
          if (g_hMMFMapSemaphore && mmfTokens > 0) {
            for (LONG i = 0; i < mmfTokens; i++)
              WaitForSingleObject(g_hMMFMapSemaphore, INFINITE);
          }
          pMapView = (BYTE *)MapViewOfFile(hDstMap, FILE_MAP_READ,
              (DWORD)(mapWindowStart >> 32), (DWORD)(mapWindowStart & 0xFFFFFFFF), mapWindowLen);
          if (pMapView && mapWindowLen > 0) {
            SIZE_T prefetchSz = (mapWindowLen < (SIZE_T)(4 * 1024 * 1024)) ? mapWindowLen : (SIZE_T)(4 * 1024 * 1024);
            WIN32_MEMORY_RANGE_ENTRY entry = { pMapView, prefetchSz };
            PrefetchVirtualMemory(GetCurrentProcess(), 1, &entry, 0);  /* Phase 8: 预取前 4MB 掩盖 HDD 延迟 */
          }
          if (!pMapView) {
            if (g_hMMFMapSemaphore && mmfTokens > 0)
              ReleaseSemaphore(g_hMMFMapSemaphore, mmfTokens, NULL);
            useMapView = FALSE;
          }
        }
      }
      if (pMapView && offset >= mapWindowStart && offset + toRead <= mapWindowStart + (LONGLONG)mapWindowLen) {
        BYTE *pMap = pMapView + (SIZE_T)(offset - mapWindowStart);
        memcpy(dstBuf, pMap, (size_t)toRead);
      } else if (!useMapView) {
        if (!SetFilePointerEx(hDst, li, NULL, FILE_BEGIN) ||
            !ReadFile(hDst, dstBuf, (DWORD)toRead, &rdDst, NULL) || rdDst != (DWORD)toRead) {
          success = FALSE; break;
        }
      } else {
        if (!SetFilePointerEx(hDst, li, NULL, FILE_BEGIN) ||
            !ReadFile(hDst, dstBuf, (DWORD)toRead, &rdDst, NULL) || rdDst != (DWORD)toRead) {
          success = FALSE; break;
        }
      }
    } else {
      if (!SetFilePointerEx(hDst, li, NULL, FILE_BEGIN)) {
        success = FALSE; break;
      }
      if (!ReadFile(hDst, dstBuf, (DWORD)toRead, &rdDst, NULL) || rdDst != (DWORD)toRead) {
        success = FALSE; break;
      }
    }
    XXH128_hash_t hashDst = XXH3_128bits(dstBuf, rdDst);
    if (hashSrc.low64 != hashDst.low64 || hashSrc.high64 != hashDst.high64) {
      if (!SetFilePointerEx(hDst, li, NULL, FILE_BEGIN)) { success = FALSE; break; }
      DWORD wr;
      if (!WriteFile(hDst, srcBuf[cur], (DWORD)toRead, &wr, NULL) || wr != (DWORD)toRead) {
        RefundBandwidthTokens(toRead); /* OPT-03: 差异块写入失败退还令牌 */
        success = FALSE; break;
      }
      ApplyIpGap(toRead);
      totalWritten += toRead;
    }
    offset += toRead;
    { int t = cur; cur = nxt; nxt = t; } /* ping-pong 交换：nxt 已预读的变为下次的 cur */
  }

DeltaCleanup:
  if (pMapView) {
    UnmapViewOfFile(pMapView);
    if (g_hMMFMapSemaphore && mapWindowLen > 0) {
      LONG rel = (LONG)((mapWindowLen + 1024 * 1024 - 1) / (1024 * 1024));
      if (rel > 0) ReleaseSemaphore(g_hMMFMapSemaphore, rel, NULL);
    }
  }
  if (hDstMap && hDstMap != INVALID_HANDLE_VALUE)
    CloseHandle(hDstMap);
  /* 必须等待飞行中的 OVERLAPPED I/O 完成，否则内核写入已释放缓冲区导致堆损坏 */
  if (hasUnprocessedRead) {
    CancelIoEx(hSrc, &olSrc[cur]);
    DWORD tmp;
    GetOverlappedResult(hSrc, &olSrc[cur], &tmp, TRUE);
  }
  if (hEvt[0]) CloseHandle(hEvt[0]);
  if (hEvt[1]) CloseHandle(hEvt[1]);
  if (deltaBufObj) InterlockedPushEntrySList(g_BigBufferPool, &deltaBufObj->ItemEntry);
  else if (buf) VirtualFree(buf, 0, MEM_RELEASE);
  CloseHandle(hSrc);
  CloseHandle(hDst);
  if (success && totalWritten > 0)
    AddBucketBytes(param, totalWritten);
  if (success && g_Config.CompareContent && g_hVerifyIocp && fullState) {
    XXH128_hash_t fullH = XXH3_128bits_digest(fullState);
    BYTE hOut[16];
    memcpy(hOut, &fullH.low64, 8);
    memcpy(hOut + 8, &fullH.high64, 8);
    PostVerifyTaskExForRetry(dst, hOut, fileSize, src, fileAttributes);
  }
  if (fullState) XXH3_freeState(fullState);
  return success;
}

#if defined(USE_AVX2_ZERO_CHECK)
/* AVX2 超标量零块检测：4x 展开 128B 步长，预取 + 非颞态加载，保护 L1/L2 缓存
 * D6 优化：对齐检查提到循环外，消除每次迭代的分支预测负担。
 * 调用方（CopyBigFileThin）的 buf 来自 AllocBufferWithLargePagesFallback（页对齐），
 * 因此 32 字节对齐始终满足，可直接走 stream_load 快路径。 */
static BOOL IsBlockAllZero_AVX2(const BYTE *p, size_t len) {
  const __m256i *ptr = (const __m256i *)p;
  size_t chunks128 = len / 128;
  /* D6：对齐检查提到循环外 — 页对齐缓冲区必然 32 字节对齐 */
  if (((uintptr_t)p & 31) == 0) {
    /* 快路径：stream_load（非颞态，不污染 Cache） */
    for (size_t i = 0; i < chunks128; i++) {
      _mm_prefetch((const char *)(ptr + 16), _MM_HINT_T0);  /* 提前 512B 抓入 L1 */
      __m256i v0 = _mm256_stream_load_si256(ptr);
      __m256i v1 = _mm256_stream_load_si256(ptr + 1);
      __m256i v2 = _mm256_stream_load_si256(ptr + 2);
      __m256i v3 = _mm256_stream_load_si256(ptr + 3);
      __m256i sum = _mm256_or_si256(_mm256_or_si256(v0, v1), _mm256_or_si256(v2, v3));
      if (!_mm256_testz_si256(sum, sum)) return FALSE;
      ptr += 4;
    }
  } else {
    /* 慢路径：unaligned load（仅在极少数非对齐场景）*/
    for (size_t i = 0; i < chunks128; i++) {
      __m256i v0 = _mm256_loadu_si256(ptr);
      __m256i v1 = _mm256_loadu_si256(ptr + 1);
      __m256i v2 = _mm256_loadu_si256(ptr + 2);
      __m256i v3 = _mm256_loadu_si256(ptr + 3);
      __m256i sum = _mm256_or_si256(_mm256_or_si256(v0, v1), _mm256_or_si256(v2, v3));
      if (!_mm256_testz_si256(sum, sum)) return FALSE;
      ptr += 4;
    }
  }
  p = (const BYTE *)ptr;
  len %= 128;
  /* 尾部 < 128B：复用已知对齐信息 */
  if (((uintptr_t)p & 31) == 0) {
    for (; len >= 32; p += 32, len -= 32) {
      if (!_mm256_testz_si256(_mm256_stream_load_si256((const __m256i *)p),
                              _mm256_stream_load_si256((const __m256i *)p)))
        return FALSE;
    }
  } else {
    for (; len >= 32; p += 32, len -= 32) {
      __m256i v = _mm256_loadu_si256((const __m256i *)p);
      if (!_mm256_testz_si256(v, v)) return FALSE;
    }
  }
  return (len == 0) || (memcmp(p, g_ZeroBuffer, len) == 0);
}
#endif

#if defined(USE_AVX512_ZERO_CHECK)
/* AVX-512 零块检测：64 字节步长，_mm512_test_epi64_mask 单周期判定，稀疏文件极致加速 */
static BOOL IsBlockAllZero_AVX512(const BYTE *p, size_t len) {
  for (; len >= 64; p += 64, len -= 64) {
    __m512i v = _mm512_loadu_si512((const __m512i *)p);
    if (_mm512_test_epi64_mask(v, v) != 0)
      return FALSE;
  }
  if (len >= 32) {
    __m256i v = _mm256_loadu_si256((const __m256i *)p);
    if (!_mm256_testz_si256(v, v))
      return FALSE;
    p += 32;
    len -= 32;
  }
  return (len == 0) || (memcmp(p, g_ZeroBuffer, len) == 0);
}
#endif

static void ProbeAVX2(void) {
  int cpuInfo[4] = {0};
  __cpuidex(cpuInfo, 7, 0);
  g_HasAVX2 = (cpuInfo[1] & (1 << 5)) != 0;   /* EBX bit 5 = AVX2 */
#if defined(USE_AVX512_ZERO_CHECK)
  g_HasAVX512 = (cpuInfo[1] & (1 << 16)) != 0;  /* EBX bit 16 = AVX-512F */
#endif
}

/* P/E-Core 拓扑探测：Win10 20H1+ EfficiencyClass，高=P-Core 低=E-Core，12 代+ 异构核收益显著 */
static void ProbePECoreTopology(void) {
  typedef BOOL (WINAPI * PFN_GLPIEx)(LOGICAL_PROCESSOR_RELATIONSHIP, PVOID, PDWORD);
  PFN_GLPIEx pGlpiEx = (PFN_GLPIEx)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),
      "GetLogicalProcessorInformationEx");
  if (!pGlpiEx) return;
  DWORD len = 0;
  if (pGlpiEx(RelationProcessorCore, NULL, &len) || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    return;
  char *buf = (char *)malloc(len);
  if (!buf) return;
  if (!pGlpiEx(RelationProcessorCore, buf, &len)) {
    free(buf);
    return;
  }
  /* 第一遍：找最大 EfficiencyClass（P-Core） */
  BYTE maxEff = 0;
  char *p = buf;
  while (p < buf + len) {
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *info = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)p;
    if (info->Relationship == RelationProcessorCore && info->Processor.EfficiencyClass > maxEff)
      maxEff = info->Processor.EfficiencyClass;
    p += info->Size;
  }
  if (maxEff == 0) { free(buf); return; }  /* 同构核，无 P/E 区分 */
  /* 第二遍：仅收集 EfficiencyClass==maxEff 的 P-Core，Group 0 */
  g_NumPCores = 0;
  p = buf;
  while (p < buf + len && g_NumPCores < MAX_PCORE_MASKS) {
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *info = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)p;
    if (info->Relationship != RelationProcessorCore || info->Processor.EfficiencyClass != maxEff) {
      p += info->Size;
      continue;
    }
    PROCESSOR_RELATIONSHIP *pr = &info->Processor;
    for (WORD g = 0; g < pr->GroupCount && g_NumPCores < MAX_PCORE_MASKS; g++) {
      if (pr->GroupMask[g].Group != 0) continue;
      KAFFINITY m = pr->GroupMask[g].Mask;
      if (m != 0)
        g_PCoreMasks[g_NumPCores++] = (DWORD_PTR)m;
    }
    p += info->Size;
  }
  free(buf);
}

/* 瘦分配优化：全零块用 FSCTL_SET_ZERO_DATA 打空洞，避免传输 490GB 零数据
 * OVERLAPPED 双缓冲：读 N+1 与处理 N 重叠，压榨 NVMe 队列深度 */
static BOOL CopyBigFileThin(const wchar_t *src, const wchar_t *dst,
                            LONGLONG fileSize, CopierParam *param,
                            const CopyTask *task) {
  HANDLE hSrc = CreateFileW(src, GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_BACKUP_SEMANTICS, NULL);
  if (hSrc == INVALID_HANDLE_VALUE) return FALSE;
  HANDLE hDst = OpenDstFileWithNtApi(param, dst, GENERIC_WRITE, 0, CREATE_ALWAYS,
      FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_BACKUP_SEMANTICS, 0);
  if (hDst == INVALID_HANDLE_VALUE) {
    CloseHandle(hSrc);
    return FALSE;
  }
  DWORD dummy;
  DeviceIoControl(hDst, FSCTL_SET_SPARSE, NULL, 0, NULL, 0, &dummy, NULL);
  DWORD bufSize = 1024 * 1024; /* 1MB 块，SIMD 友好 */
  BYTE *bufBase = NULL;  /* 2MB 大页块，buf[0]=base, buf[1]=base+1MB */
  BYTE *buf[2];
  OVERLAPPED ov[2];
  HANDLE evt[2];
  BigBufferObj *thinBufObj = NULL;
  if (g_BigBufferPool && g_BigBufferSize >= bufSize * 2) {
    PSLIST_ENTRY e = InterlockedPopEntrySList(g_BigBufferPool);
    if (e) {
      thinBufObj = (BigBufferObj *)e;
      bufBase = thinBufObj->Buffer;
    }
  }
  if (!bufBase)
    bufBase = (BYTE *)AllocBufferWithLargePagesFallback(bufSize * 2);
  if (bufBase) {
    buf[0] = bufBase;
    buf[1] = bufBase + bufSize;
  } else {
    buf[0] = buf[1] = NULL;
  }
  evt[0] = CreateEvent(NULL, TRUE, FALSE, NULL);
  evt[1] = CreateEvent(NULL, TRUE, FALSE, NULL);
  if (!buf[0] || !buf[1] || !evt[0] || !evt[1]) {
    if (thinBufObj) InterlockedPushEntrySList(g_BigBufferPool, &thinBufObj->ItemEntry);
    else if (bufBase) VirtualFree(bufBase, 0, MEM_RELEASE);
    if (evt[0]) CloseHandle(evt[0]);
    if (evt[1]) CloseHandle(evt[1]);
    CloseHandle(hSrc);
    CloseHandle(hDst);
    return FALSE;
  }
  memset(ov, 0, sizeof(ov));
  ov[0].hEvent = evt[0];
  ov[1].hEvent = evt[1];
  BOOL success = TRUE;
  LONGLONG pos = 0;
  int cur = 0;
  DWORD rdCur = 0;
  LONGLONG blockStart = 0;
  BOOL hasPending = FALSE;
  while (pos < fileSize && !IsCanceling()) {
    if (hasPending) {
      if (!GetOverlappedResult(hSrc, &ov[cur], &rdCur, TRUE)) {
        success = FALSE;
        break;
      }
      hasPending = FALSE;
      if (rdCur == 0) break;
      blockStart = ov[cur].Offset + ((LONGLONG)ov[cur].OffsetHigh << 32);
      /* 重叠：先启动下一块读，再处理当前块（读 N+1 与处理 N 并行） */
      if (pos < fileSize) {
        DWORD toRead = (DWORD)min((LONGLONG)bufSize, fileSize - pos);
        int next = 1 - cur;
        ov[next].Offset = (DWORD)(pos & 0xFFFFFFFF);
        ov[next].OffsetHigh = (DWORD)(pos >> 32);
        ResetEvent(evt[next]);
        if (ReadFile(hSrc, buf[next], toRead, NULL, &ov[next]) || GetLastError() == ERROR_IO_PENDING) {
          hasPending = TRUE;
          pos += toRead;
        }
      }
    } else {
      DWORD toRead = (DWORD)min((LONGLONG)bufSize, fileSize - pos);
      if (toRead == 0) break;
      ov[cur].Offset = (DWORD)(pos & 0xFFFFFFFF);
      ov[cur].OffsetHigh = (DWORD)(pos >> 32);
      ResetEvent(evt[cur]);
      if (!ReadFile(hSrc, buf[cur], toRead, NULL, &ov[cur])) {
        if (GetLastError() != ERROR_IO_PENDING) { success = FALSE; break; }
      }
      hasPending = TRUE;
      pos += toRead;
      continue;  /* 首次：启动读后下一轮再等 */
    }
    BOOL isZero = FALSE;
#if defined(USE_AVX512_ZERO_CHECK)
    if (g_HasAVX512)
      isZero = IsBlockAllZero_AVX512(buf[cur], (size_t)rdCur);
    else
#endif
#if defined(USE_AVX2_ZERO_CHECK)
    if (g_HasAVX2)
      isZero = IsBlockAllZero_AVX2(buf[cur], (size_t)rdCur);
    else
#endif
      isZero = (memcmp(buf[cur], g_ZeroBuffer, rdCur) == 0);
    if (isZero) {
      FILE_ZERO_DATA_INFORMATION zdi = {0};
      zdi.FileOffset.QuadPart = blockStart;  /* blockStart 在启动读时已保存 */
      zdi.BeyondFinalZero.QuadPart = blockStart + rdCur;
      if (!DeviceIoControl(hDst, FSCTL_SET_ZERO_DATA, &zdi, sizeof(zdi), NULL, 0, &dummy, NULL)) {
        DWORD wr;
        LARGE_INTEGER lip;
        lip.QuadPart = blockStart;
        SetFilePointerEx(hDst, lip, NULL, FILE_BEGIN);
        if (!WriteFile(hDst, buf[cur], rdCur, &wr, NULL) || wr != rdCur)
          success = FALSE;
        else
          ApplyIpGap((LONGLONG)wr);
      }
      AcquireBandwidthTokens((LONGLONG)rdCur);
    } else {
      AcquireBandwidthTokens((LONGLONG)rdCur);
      LARGE_INTEGER lip;
      lip.QuadPart = blockStart;
      SetFilePointerEx(hDst, lip, NULL, FILE_BEGIN);
      DWORD wr;
      if (!WriteFile(hDst, buf[cur], rdCur, &wr, NULL) || wr != rdCur) {
        RefundBandwidthTokens((LONGLONG)rdCur);
        success = FALSE;
        break;
      }
      ApplyIpGap((LONGLONG)wr);
    }
    AddBucketBytes(param, rdCur);
    cur = 1 - cur;  /* 下一轮等待的是 buf[next] 的读 */
  }
  if (success) {
    LARGE_INTEGER li;
    li.QuadPart = fileSize;
    SetFilePointerEx(hDst, li, NULL, FILE_BEGIN);
    SetEndOfFile(hDst);
  }
  if (success && task)
    ApplyFileBasicInfoBeforeClose(hDst, task, param);
  if (thinBufObj) InterlockedPushEntrySList(g_BigBufferPool, &thinBufObj->ItemEntry);
  else if (bufBase) VirtualFree(bufBase, 0, MEM_RELEASE);
  CloseHandle(evt[0]);
  CloseHandle(evt[1]);
  CloseHandle(hSrc);
  CloseHandle(hDst);
  if (success && task)
    CopyFileSecurityAndAttributesEx(src, dst, task, TRUE, param);
  return success;
}

/* Buffered 大文件：仅源端哈希；磁盘校验交给 Verify IOCP（避免 Page Cache 假阳性回读） */
static BOOL CopyBigFileBuffered(const wchar_t *src, const wchar_t *dst,
                                LONGLONG fileSize, CopierParam *param,
                                const CopyTask *task) {
  HANDLE hSrc = CreateFileW(src, GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_BACKUP_SEMANTICS, NULL);
  if (hSrc == INVALID_HANDLE_VALUE) return FALSE;
  HANDLE hDst = OpenDstFileWithNtApi(param, dst, GENERIC_WRITE, 0, CREATE_ALWAYS,
      FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_SEQUENTIAL_SCAN |
      FILE_FLAG_BACKUP_SEMANTICS, fileSize);
  if (hDst == INVALID_HANDLE_VALUE) {
    CloseHandle(hSrc);
    return FALSE;
  }
  DWORD bufSize = 4 * 1024 * 1024;
  BigBufferObj *bufObj = NULL;
  BYTE *buf = NULL;
  if (g_BigBufferPool) {
    PSLIST_ENTRY e = InterlockedPopEntrySList(g_BigBufferPool);
    if (e) {
      bufObj = (BigBufferObj *)e;
      buf = bufObj->Buffer;
      if (g_BigBufferSize < bufSize)
        bufSize = g_BigBufferSize;
    }
  }
  if (!buf)
    buf = (BYTE *)AllocBufferWithLargePagesFallback(bufSize);
  if (!buf) {
    CloseHandle(hSrc);
    CloseHandle(hDst);
    return FALSE;
  }
  XXH3_state_t *hashSrc = NULL;
  BOOL doHash = (g_Config.CompareContent && param && g_Config.UseXxh3 && param->Xxh3State);
  BYTE srcHash[8] = {0};
  if (doHash) {
    hashSrc = param->Xxh3State;
    if (XXH3_64bits_reset(hashSrc) != XXH_OK)
      doHash = FALSE;
  }
  BOOL success = TRUE;
  LONGLONG remaining = fileSize;
  while (remaining > 0 && !IsCanceling()) {
    DWORD toRead = (DWORD)min((LONGLONG)bufSize, remaining);
    DWORD rd, wr;
    if (!ReadFile(hSrc, buf, toRead, &rd, NULL) || rd != toRead) {
      success = FALSE;
      break;
    }
    AcquireBandwidthTokens((LONGLONG)rd);
    if (doHash)
      XXH3_64bits_update(hashSrc, buf, rd);
    if (!WriteFile(hDst, buf, rd, &wr, NULL) || wr != rd) {
      RefundBandwidthTokens((LONGLONG)rd);
      success = FALSE;
      break;
    }
    ApplyIpGap((LONGLONG)wr);
    remaining -= rd;
  }
  if (doHash && success) {
    XXH64_hash_t h = XXH3_64bits_digest(hashSrc);
    memcpy(srcHash, &h, sizeof(h));
  }
  if (success && task)
    ApplyFileBasicInfoBeforeClose(hDst, task, param);
  if (bufObj)
    InterlockedPushEntrySList(g_BigBufferPool, &bufObj->ItemEntry);
  else if (buf)
    VirtualFree(buf, 0, MEM_RELEASE);
  CloseHandle(hSrc);
  CloseHandle(hDst);
  if (success && doHash)
    PostVerifyTaskExForRetry(dst, srcHash, fileSize, src,
        task ? task->FileAttributes : 0);
  if (success && task)
    CopyFileSecurityAndAttributesEx(src, dst, task, TRUE, param);
  return success;
}

/* Phase 9 热冷分离：错误处理抽离为 noinline，核心循环驻留 L1i Cache */
#ifdef _MSC_VER
__declspec(noinline)
#else
__attribute__((noinline))
#endif
static void HandleBigFileReadError(LONGLONG bytesToRefund) {
  RefundBandwidthTokens(bytesToRefund);
}

BOOL CopyBigFileHighSpeed(const wchar_t *src, const wchar_t *dst,
                          LONGLONG fileSize, CopierParam *param,
                          DWORD fileAttributesForRetry) {
  BOOL success = TRUE;
  HANDLE hFileIocp = NULL;
  LONGLONG totalWrittenLocally = 0;
  LONGLONG totalFlushedToGlobal = 0; /* BUG-05: 失败时回滚已计入的 progressive 字节 */
  BOOL bUsedValidData = FALSE; /* 安全标记：SetFileValidData 已调用，失败时必须截断防止脏数据 */
  /* Google 策略：大文件(>512MB)增加并行块数，提升吞吐
   * P2 X-Flow Same HDD：同盘 HDD 时降低 QD 减少磁头寻道竞争
   * 动态 QD：滑动窗口监控 I/O 延迟，avg<2ms 试探性提升，avg>15ms 退避收缩 */
  LONG bias = InterlockedAdd((volatile LONG *)&g_AdaptiveQDBias, 0);
  int actualQD = g_BigFileQD + (int)bias;
  if (g_IsSameVolume && !g_Config.IsSSD && actualQD > 4)
    actualQD = 4;
  if (fileSize > 512 * 1024 * 1024 && actualQD < 16)
    actualQD = (actualQD < 8) ? 8 : 16;
  if (actualQD < 2)
    actualQD = 2;
  if (actualQD > BIGFILE_QUEUE_DEPTH_MAX)
    actualQD = BIGFILE_QUEUE_DEPTH_MAX;
  IoBlock *blocks = (IoBlock *)calloc(actualQD, sizeof(IoBlock));
  if (!blocks)
    return FALSE;
  int numBlocks = 0;
  int spinWait = 0;
  /* 【打破死锁】：凑不齐 2 块时归还已占块，退让 CPU，避免多线程抱死 */
  while (numBlocks < 2 && !IsCanceling()) {
    for (; numBlocks < actualQD; numBlocks++) {
      PSLIST_ENTRY e = InterlockedPopEntrySList(g_BigBufferPool);
      if (!e)
        break;
      blocks[numBlocks].bufObj = (BigBufferObj *)e;
      blocks[numBlocks].state = BUF_FREE;
      blocks[numBlocks].ov.hEvent = NULL;
    }
    if (numBlocks < 2) {
      for (int i = 0; i < numBlocks; i++)
        InterlockedPushEntrySList(g_BigBufferPool, &blocks[i].bufObj->ItemEntry);
      numBlocks = 0;
      Sleep(10 * (++spinWait));
    }
  }
  if (numBlocks < 2) {
    success = FALSE;
    goto Cleanup_Alloc;
  }

  HANDLE hSrc = INVALID_HANDLE_VALUE, hDst = INVALID_HANDLE_VALUE;
  /* No_Buffering 扇区对齐预分配大小，提前算好供 NtCreateFile AllocationSize 一次 Syscall 完成 */
  LONGLONG alignedSizeInit = (fileSize / g_SectorSize) * g_SectorSize;
  LONGLONG allocSize = alignedSizeInit + (fileSize > alignedSizeInit ? g_SectorSize : 0);
  /* 预分配 + 完成序；写穿仅当 -write_through（吞吐与持久化权衡，见策略补充说明） */
  DWORD flags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING |
                FILE_FLAG_OVERLAPPED | FILE_FLAG_BACKUP_SEMANTICS;
  if (g_Config.WriteThroughBigFiles)
    flags |= FILE_FLAG_WRITE_THROUGH;
  BOOL wtEnabled = (flags & FILE_FLAG_WRITE_THROUGH) ? TRUE : FALSE;
  hSrc = CreateFileW(src, GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, flags, NULL);
  hDst = OpenDstFileWithNtApi(param, dst, GENERIC_WRITE, 0, CREATE_ALWAYS,
                    flags | FILE_ATTRIBUTE_TEMPORARY, allocSize);
  if (hSrc == INVALID_HANDLE_VALUE || hDst == INVALID_HANDLE_VALUE) {
    success = FALSE;
    goto Cleanup;
  }
  TryEnableBypassIO(hSrc);  /* Phase 17：Win11+ NVMe 直通，剥离 Filter Driver */

  /* No_Buffering 铁律：SetFilePointerEx/SetEndOfFile 偏移必须扇区对齐
   * NTAPI 路径已通过 AllocationSize 一次完成预分配；CreateFileW 回退需 SetFileInformationByHandle */
  LARGE_INTEGER liSize;
  liSize.QuadPart = allocSize;
  if (liSize.QuadPart > 0) {
    BOOL preallocOk = FALSE;
    if (!IsUncPath(src) && !IsUncPath(dst)) {
      FILE_ALLOCATION_INFO allocInfo = {0};
      allocInfo.AllocationSize.QuadPart = liSize.QuadPart;
      preallocOk = SetFileInformationByHandle(hDst, FileAllocationInfo,
                                              &allocInfo, sizeof(allocInfo));
    }
    /* 预分配成功或 NTAPI 已分配：均需 SetFilePointerEx+SetEndOfFile 设置 EOF 供写入 */
    SetFilePointerEx(hDst, liSize, NULL, FILE_BEGIN);
    SetEndOfFile(hDst);
    /* Round4 P2 架构3：SetFileValidData 须明确传入 -unsafe_fast_alloc 方可启用。
     * 默认关闭原因：断电/BSOD 后目标文件暴露旧磁盘扇区历史数据（Data Leakage），
     *              金融、医疗、政务 IT 合规环境不可接受，需明确知情才启用。
     * 启用时需要 SE_MANAGE_VOLUME_PRIVILEGE；普通权限调用直接失败，bUsedValidData 不置位。*/
    if (g_Config.UnsafeFastAlloc) {
      if (SetFileValidData(hDst, liSize.QuadPart)) {
        bUsedValidData = TRUE;
        /* 审计警告：让运维人员知道存在断电导致脏扇区的合规风险窗口 */
        LogMessage(LOG_WARNING,
          L"[COMPLIANCE] SetFileValidData used for: %ls  "
          L"-- Power loss before write completes may expose stale disk data!\n", dst);
      }
    }
  }
  SetFilePointerEx(hDst, (LARGE_INTEGER){0}, NULL, FILE_BEGIN);

  /* advice1 P1: 复用线程私有 hFileIocp，消除每大文件 Create/Close KQUEUE */
  if (param && param->hFileIocp)
    hFileIocp = param->hFileIocp;
  else {
    hFileIocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (hFileIocp && param)
      param->hFileIocp = hFileIocp;
  }
  if (!hFileIocp) {
    success = FALSE;
    goto Cleanup;
  }
  if (!CreateIoCompletionPort(hSrc, hFileIocp, KEY_BIGFILE_READ, 0) ||
      !CreateIoCompletionPort(hDst, hFileIocp, KEY_BIGFILE_WRITE, 0)) {
    success = FALSE;
    goto Cleanup;
  }

  HCRYPTPROV hProv = 0;
  HCRYPTHASH hHash = 0;
  XXH3_state_t *xxh3State = NULL;
  BOOL doHash = g_Config.CompareContent;
  BOOL ownXxh3State = FALSE;
  if (doHash) {
    if (g_Config.UseXxh3) {
      xxh3State = (param && param->Xxh3State) ? param->Xxh3State : XXH3_createState();
      ownXxh3State = (!param || !param->Xxh3State || param->Xxh3State != xxh3State);
      if (!xxh3State || XXH3_128bits_reset(xxh3State) != XXH_OK)
        doHash = FALSE;
    } else {
      if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL,
                                CRYPT_VERIFYCONTEXT) ||
          !CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
        doHash = FALSE;
    }
  }

  LONGLONG alignedSize = (fileSize / g_SectorSize) * g_SectorSize;
  LONGLONG readOffset = 0, writeOffset = 0;
  LONGLONG nextHashOffset = 0; /* 滑动哈希窗口：强制按序算 Hash */
  int pendingCount = 0;

  while (success && (writeOffset < alignedSize || pendingCount > 0)) {
    if (UNLIKELY(IsCanceling())) {
      success = FALSE;
      break;
    }
    /* 发起阶段：BUF_FREE 且 readOffset 未耗尽则发起 ReadFile */
    for (int i = 0; i < numBlocks && readOffset < alignedSize; i++) {
      if (blocks[i].state != BUF_FREE)
        continue;
      /* Phase 14 NTA：大块数据预取不污染 L3，保护 MFT/索引等热数据 */
      _mm_prefetch((const char *)blocks[i].bufObj->Buffer, _MM_HINT_NTA);
      DWORD toRead =
          (DWORD)min(g_BigBufferSize, alignedSize - readOffset);
      AcquireBandwidthTokens((LONGLONG)toRead);
      blocks[i].offset = readOffset;
      blocks[i].length = toRead;
      blocks[i].ov.Offset = (DWORD)readOffset;
      blocks[i].ov.OffsetHigh = (DWORD)(readOffset >> 32);
      if (!ReadFile(hSrc, blocks[i].bufObj->Buffer, toRead, NULL,
                    &blocks[i].ov) && GetLastError() != ERROR_IO_PENDING) {
        HandleBigFileReadError((LONGLONG)toRead);
        success = FALSE;
        break;
      }
      blocks[i].state = BUF_READING;
      readOffset += toRead;
      pendingCount++;
    }
    if (!success)
      break;

    /* P1 收割阶段：GetQueuedCompletionStatusEx 批处理，一次系统调用取多完成包 */
    OVERLAPPED_ENTRY entries[GQCSEx_BATCH_SIZE];
    ULONG numGot = 0;
    ULONGLONG t0 = GetTickCount64();
    if (!GetQueuedCompletionStatusEx(hFileIocp, entries, GQCSEx_BATCH_SIZE, &numGot, INFINITE, FALSE) || numGot == 0) {
      success = FALSE;
      break;
    }
    LONGLONG dt = (LONGLONG)(GetTickCount64() - t0);
    LONGLONG dtPer = (numGot > 0) ? (dt / (LONGLONG)numGot) : dt;
    /* 批处理时仅记录一次有效延迟，避免单次批量淹没采样窗口 */
    if (param && param->IoLatencyCount < ADAPTIVE_QD_SAMPLES) {
      param->IoLatencySamples[param->IoLatencyCount] = dtPer;
      param->IoLatencySum += dtPer;
      param->IoLatencyCount++;
    } else if (param) {
      int idx = param->IoLatencyCount % ADAPTIVE_QD_SAMPLES;
      param->IoLatencySum -= param->IoLatencySamples[idx];
      param->IoLatencySamples[idx] = dtPer;
      param->IoLatencySum += dtPer;
      param->IoLatencyCount++;
    }

    for (ULONG ei = 0; ei < numGot && success; ei++) {
      DWORD bytes = entries[ei].dwNumberOfBytesTransferred;
      ULONG_PTR key = entries[ei].lpCompletionKey;
      LPOVERLAPPED lpOv = entries[ei].lpOverlapped;
      if (!lpOv) { success = FALSE; break; }
      IoBlock *blk = (IoBlock *)lpOv;
      pendingCount--;

      if (key == KEY_BIGFILE_READ) {
      /* Cache-Hot Hashing：读完成瞬间数据在 L1/L2 最热，立即算 Hash 再发起 Write，零时差校验 */
      if (doHash && blk->offset == nextHashOffset) {
        if (g_Config.UseXxh3)
          XXH3_128bits_update(xxh3State, blk->bufObj->Buffer, blk->length);
        else
          CryptHashData(hHash, blk->bufObj->Buffer, (DWORD)blk->length, 0);
        nextHashOffset += blk->length;
      }
      blk->ov.Offset = (DWORD)blk->offset;
      blk->ov.OffsetHigh = (DWORD)(blk->offset >> 32);
      if (!WriteFile(hDst, blk->bufObj->Buffer, bytes, NULL, &blk->ov) &&
          GetLastError() != ERROR_IO_PENDING) {
        RefundBandwidthTokens((LONGLONG)bytes); /* OPT-03: 写入失败退还已扣令牌 */
        success = FALSE;
        break;
      }
      blk->state = BUF_WRITING;
      pendingCount++;
    } else {
      writeOffset += bytes;
      totalWrittenLocally += bytes;
      if (doHash) {
        if (blk->offset < nextHashOffset)
          blk->state = BUF_FREE;  /* 已在 READ 路径 Cache-Hot 时算过 */
        else if (blk->offset == nextHashOffset) {
          if (g_Config.UseXxh3)
            XXH3_128bits_update(xxh3State, blk->bufObj->Buffer, blk->length);
          else
            CryptHashData(hHash, blk->bufObj->Buffer, (DWORD)blk->length, 0);
          nextHashOffset += blk->length;
          blk->state = BUF_FREE;
        } else {
          blk->state = BUF_FREE_WAIT_HASH;
        }
      } else {
        blk->state = BUF_FREE;
      }
      if (totalWrittenLocally >= PROGRESSIVE_FLUSH_MB * (1024 * 1024)) {
        LONGLONG toFlush =
            (totalWrittenLocally / (PROGRESSIVE_FLUSH_MB * 1024 * 1024)) *
            (PROGRESSIVE_FLUSH_MB * 1024 * 1024);
        if (toFlush > 0) {
          AddBucketBytes(param, toFlush);
          totalFlushedToGlobal += toFlush;
          totalWrittenLocally -= toFlush;
        }
      }
      /* 【滑动哈希窗口】：按序释放 BUF_FREE_WAIT_HASH 的块 */
      if (doHash && success) {
        BOOL hashedAny;
        do {
          hashedAny = FALSE;
          for (int i = 0; i < numBlocks; i++) {
            if (blocks[i].state == BUF_FREE_WAIT_HASH &&
                blocks[i].offset == nextHashOffset) {
              if (g_Config.UseXxh3)
                XXH3_128bits_update(xxh3State, blocks[i].bufObj->Buffer,
                                   blocks[i].length);
              else
                CryptHashData(hHash, blocks[i].bufObj->Buffer,
                             (DWORD)blocks[i].length, 0);
              nextHashOffset += blocks[i].length;
              blocks[i].state = BUF_FREE;
              hashedAny = TRUE;
              break;
            }
          }
        } while (hashedAny);
      }
    }
    }  /* for ei (GQCSEx batch) */
  }

  /* PID 自适应 I/O 调节器：目标 5ms 延迟，P 比例/I 积分/D 微分急刹车 */
  if (param && param->IoLatencyCount >= ADAPTIVE_QD_MIN_SAMPLES) {
    int n = (param->IoLatencyCount > ADAPTIVE_QD_SAMPLES) ? ADAPTIVE_QD_SAMPLES : param->IoLatencyCount;
    LONGLONG avg = param->IoLatencySum / n;
    LONGLONG error = avg - PID_LATENCY_SETPOINT_MS;
    EnterCriticalSection(&g_PidCs);
    double dt = (GetTickCount() - g_PidLastTick) / 1000.0;
    if (dt <= 0) dt = 0.1;
    g_PidIntegral += (double)error * dt;
    if (g_PidIntegral > PID_MAX_INTEGRAL) g_PidIntegral = PID_MAX_INTEGRAL;
    else if (g_PidIntegral < -PID_MAX_INTEGRAL) g_PidIntegral = -PID_MAX_INTEGRAL;
    double derivative = (double)(error - g_PidLastError) / dt;
    g_PidLastError = error;
    g_PidLastTick = GetTickCount();
    double out = -PID_KP * (double)error - PID_KI * g_PidIntegral - PID_KD * derivative;
    if (out > 16) out = 16;
    if (out < -16) out = -16;
    InterlockedExchange((volatile LONG *)&g_AdaptiveQDBias, (LONG)(out + 0.5));
    LeaveCriticalSection(&g_PidCs);
  }
  if (param) {
    param->IoLatencyCount = 0;
    param->IoLatencySum = 0;
  }

  // 尾部处理
  BOOL bTailReadStarted = FALSE, bTailWriteStarted = FALSE;
  OVERLAPPED olTailRead = {0}, olTailWrite = {0};
  HANDLE hTailEventR = NULL, hTailEventW = NULL;
  if (IsCanceling())
    success = FALSE;
  else if (success && fileSize > alignedSize) {
    hTailEventR = CreateEvent(NULL, TRUE, FALSE, NULL);
    hTailEventW = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!hTailEventR || !hTailEventW) {
      if (hTailEventR) CloseHandle(hTailEventR);
      if (hTailEventW) CloseHandle(hTailEventW);
      hTailEventR = hTailEventW = NULL;
      success = FALSE;
    } else {
    olTailRead.hEvent = (HANDLE)((ULONG_PTR)hTailEventR | 1); /* 屏蔽 IOCP 幽灵投递 */
    olTailWrite.hEvent = (HANDLE)((ULONG_PTR)hTailEventW | 1);
    DWORD tailSize = (DWORD)(fileSize - alignedSize);
    DWORD sectorsToProcess =
        ((tailSize + g_SectorSize - 1) / g_SectorSize) * g_SectorSize;
    olTailRead.Offset = (DWORD)alignedSize;
    olTailRead.OffsetHigh = (DWORD)(alignedSize >> 32);
    DWORD rBytes = 0, wBytes = 0;
    if (ReadFile(hSrc, blocks[0].bufObj->Buffer, sectorsToProcess, NULL, &olTailRead) ||
        GetLastError() == ERROR_IO_PENDING) {
      bTailReadStarted = TRUE;
      if (GetOverlappedResult(hSrc, &olTailRead, &rBytes, TRUE)) {
        if (rBytes > tailSize)
          memset(blocks[0].bufObj->Buffer + tailSize, 0, rBytes - tailSize);
        if (doHash) {
          if (g_Config.UseXxh3)
            XXH3_128bits_update(xxh3State, blocks[0].bufObj->Buffer, tailSize);
          else
            CryptHashData(hHash, blocks[0].bufObj->Buffer, tailSize, 0);
        }
        olTailWrite.Offset = olTailRead.Offset;
        olTailWrite.OffsetHigh = olTailRead.OffsetHigh;
        if (WriteFile(hDst, blocks[0].bufObj->Buffer, sectorsToProcess, NULL,
                      &olTailWrite) ||
            GetLastError() == ERROR_IO_PENDING) {
          bTailWriteStarted = TRUE;
          if (GetOverlappedResult(hDst, &olTailWrite, &wBytes, TRUE)) {
            totalWrittenLocally += tailSize;
            /* 尾部写入为扇区对齐块，文件膨胀；精确截断需用缓冲句柄，见下方 Reopen-Truncate */
          } else
            success = FALSE;
        } else
          success = FALSE;
      } else
        success = FALSE;
    } else
      success = FALSE;
    }
  }
  /* 当 fileSize <= alignedSize 时无尾部，success 保持主循环结果，不覆盖 */

  /* 补零齐缝法：尾部已用 0 填充至扇区对齐写入，此处精确截断。
   * 优先尝试同句柄 SetEndOfFile（避免 Reopen 打断连续写入流）；NO_BUFFERING 下非对齐偏移可能失败，回退 Reopen */
  if (success && fileSize > alignedSize) {
    if (hSrc != INVALID_HANDLE_VALUE) {
      CloseHandle(hSrc);
      hSrc = INVALID_HANDLE_VALUE;
    }
    BOOL truncated = FALSE;
    if (hDst != INVALID_HANDLE_VALUE) {
      if (success && !wtEnabled)
        FlushFileBuffers(hDst);
      LARGE_INTEGER exact;
      exact.QuadPart = fileSize;
      if (SetFilePointerEx(hDst, exact, NULL, FILE_BEGIN) && SetEndOfFile(hDst))
        truncated = TRUE;
      CloseHandle(hDst);
      hDst = INVALID_HANDLE_VALUE;
    }
    if (!truncated) {
      HANDLE hTrunc = OpenDstFileWithNtApi(param, dst, GENERIC_WRITE,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  OPEN_EXISTING,
                                  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, 0);
      if (hTrunc != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER exact;
        exact.QuadPart = fileSize;
        SetFilePointerEx(hTrunc, exact, NULL, FILE_BEGIN);
        SetEndOfFile(hTrunc);
        CloseHandle(hTrunc);
      } else {
        success = FALSE;
      }
    }
  }

  if (doHash) {
    BYTE srcHash[16];
    if (g_Config.UseXxh3 && xxh3State) {
      XXH128_hash_t h = XXH3_128bits_digest(xxh3State);
      memcpy(srcHash, &h.low64, 8);
      memcpy(srcHash + 8, &h.high64, 8);
      if (ownXxh3State)
        XXH3_freeState(xxh3State);
      xxh3State = NULL;
    } else if (hHash) {
      DWORD hLen = 16;
      CryptGetHashParam(hHash, HP_HASHVAL, srcHash, &hLen, 0);
      CryptDestroyHash(hHash);
      CryptReleaseContext(hProv, 0);
      hHash = 0;
      hProv = 0;
    }

    if (success) {
      if (hSrc != INVALID_HANDLE_VALUE) {
        CloseHandle(hSrc);
        hSrc = INVALID_HANDLE_VALUE;
      }
      if (hDst != INVALID_HANDLE_VALUE) {
        if (!wtEnabled)
          FlushFileBuffers(hDst);
        CloseHandle(hDst);
        hDst = INVALID_HANDLE_VALUE;
      }
      /* 抽样模式：全量 Hash 与抽样 Hash 不同，由 ProcessTask 用 CalculateFileHashSampled 投递 */
      if (!(g_Config.SampleLargeFiles && fileSize >= GetSampleThreshold()))
        PostVerifyTaskExForRetry(dst, srcHash, fileSize, src, fileAttributesForRetry);
    }
  }

  if (!success) {
    if (totalFlushedToGlobal > 0)
      AddBucketBytes(param, -totalFlushedToGlobal);
    if (hFileIocp) {
    /* Reopen-Truncate 路径可能已关闭句柄，CancelIo 前必须检查有效性 */
    if (hSrc != INVALID_HANDLE_VALUE) CancelIo(hSrc);
    if (hDst != INVALID_HANDLE_VALUE) CancelIo(hDst);
    /* 【终极修复】：必须死等直到所有 IRP 落地，否则内核写入已释放内存导致堆损坏/BSOD */
    DWORD d;
    ULONG_PTR k;
    LPOVERLAPPED ov;
    while (pendingCount > 0) {
      BOOL bRet = GetQueuedCompletionStatus(hFileIocp, &d, &k, &ov, INFINITE);
      /* 【关键修复】：CancelIo 强杀的 IRP 会返回 FALSE(ERROR_OPERATION_ABORTED)，
       * 只要有 ov 就代表一个 I/O 已终结，必须减 pendingCount，否则死锁 */
      if (bRet || ov != NULL)
        pendingCount--;
    }
    if (bTailReadStarted && hSrc != INVALID_HANDLE_VALUE)
      GetOverlappedResult(hSrc, &olTailRead, &d, TRUE);
    if (bTailWriteStarted && hDst != INVALID_HANDLE_VALUE)
      GetOverlappedResult(hDst, &olTailWrite, &d, TRUE);
    }
  } else if (totalWrittenLocally > 0) {
    AddBucketBytes(param, totalWrittenLocally);
  }
Cleanup:
  /* 先关闭无缓冲句柄，再用缓冲句柄重开截断，避免共享冲突/潜在死锁 */
  if (hSrc != INVALID_HANDLE_VALUE) {
    CloseHandle(hSrc);
    hSrc = INVALID_HANDLE_VALUE;
  }
  if (hDst != INVALID_HANDLE_VALUE) {
    if (success && !wtEnabled)
      FlushFileBuffers(hDst);
    CloseHandle(hDst);
    hDst = INVALID_HANDLE_VALUE;
  }
  if (!success && bUsedValidData) {
    /* 【安全合规】：SetFileValidData 后失败/Ctrl+C，未写入区域含旧磁盘数据（信息泄漏风险）
     * 用缓冲句柄截断到 0 字节：NO_BUFFERING 句柄无法对非扇区对齐偏移 SetEndOfFile */
    HANDLE hTrunc = OpenDstFileWithNtApi(param, dst, GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, 0);
    if (hTrunc != INVALID_HANDLE_VALUE) {
      LARGE_INTEGER zero = {0};
      SetFilePointerEx(hTrunc, zero, NULL, FILE_BEGIN);
      SetEndOfFile(hTrunc);
      CloseHandle(hTrunc);
    }
  }
  /* 持久化 IOCP 不在此 Close；仅失败路径已 CancelIo 排空 */
  hFileIocp = NULL;
  if (hTailEventR)
    CloseHandle(hTailEventR);
  if (hTailEventW)
    CloseHandle(hTailEventW);
Cleanup_Alloc:
  for (int i = 0; i < numBlocks; i++) {
    if (blocks[i].bufObj)
      InterlockedPushEntrySList(g_BigBufferPool, &(blocks[i].bufObj->ItemEntry));
  }
  if (blocks)
    free(blocks);
  return success;
}

/* 大文件路径：低于 -directio_threshold 或扇区 IOCTL 未双端证实 → 缓冲复制（避免 NO_BUFFERING 静默失败） */
static BOOL PickBigFileBuffered(LONGLONG fileSize) {
  if (g_Config.DirectIoThresholdMB > 0) {
    LONGLONG thresh = (LONGLONG)g_Config.DirectIoThresholdMB * 1024 * 1024;
    if (fileSize < thresh)
      return TRUE;
  }
  return !g_BigFileUseDirectIo;
}

/* 死信队列慢速挣扎：主流水线结束后，5s/10s/20s 指数退避最后一轮 */
static void RetryDeadLetterTask(CopyTask *task, CopierParam *param) {
  const wchar_t *src = task->SrcPath ? task->SrcPath : task->ShortSrc;
  const wchar_t *dst = task->DstPath ? task->DstPath : task->ShortDst;
  BOOL isBig = (task->FileSize >= SPLIT_THRESHOLD);
  BOOL isSparse = (task->FileAttributes & FILE_ATTRIBUTE_SPARSE_FILE) != 0;
  BOOL ret = FALSE;
  for (int i = 0; !ret && i < 3; i++) {
    if (i > 0)
      Sleep(5000 * (1 << (i - 1))); /* 5s, 10s, 20s */
    if (isBig) {
      if (isSparse)
        ret = CopySparseFile(src, dst, task->FileSize, param, NULL);
      if (!ret) {
        if (PickBigFileBuffered(task->FileSize)) {
          InterlockedIncrement64(&g_IoStrategyStats[IOSTRAT_BIG_BUFFERED]);
          ret = CopyBigFileBuffered(src, dst, task->FileSize, param, task);
        } else {
          InterlockedIncrement64(&g_IoStrategyStats[IOSTRAT_BIG_DIRECT_IO]);
          ret = CopyBigFileHighSpeed(src, dst, task->FileSize, param, task->FileAttributes);
        }
      }
    } else {
      ret = CopySmallFile(src, dst, task->FileSize, param, task->pSrcBackend, task->pDstBackend, task);
      if (!ret)
        ret = CopyFile2Ex(src, dst, g_Config.FastMode);
    }
    if (!ret && GetLastError() == ERROR_ACCESS_DENIED)
      SetFileAttributesW(dst, FILE_ATTRIBUTE_NORMAL);
  }
  if (ret) {
    CopyFileSecurityAndAttributesEx(src, dst, task, param->TimestampsAlreadySet, param);
    param->TimestampsAlreadySet = FALSE;
    AddBucketCopied(param, 1);
    /* BUG-05: 大文件 CopyBigFileHighSpeed/CopySparseFile 已计入 g_TotalBytes，不重复加 */
    if (!isBig)
      AddBucketBytes(param, task->FileSize);
  } else {
    DWORD err = GetLastError();
    LogMessageRaw(LOG_ERROR, err, src, task->FileSize, 1);
    InterlockedIncrement(&g_TotalFailed);
    if (!g_Config.IsFtpDest)
      RequestAsyncCleanup(dst);
  }
  FreeCopyTask(task);
}

/* BUG-01：DLQ 并发重试单次执行体——无 Sleep，用于 DLQWorkerThread */
static void RetryDeadLetterTaskFast(CopyTask *task, CopierParam *param) {
  if (IsCanceling()) {
    FreeCopyTask(task);
    return;
  }
  /* DLQ 入口守卫：目录误入 DLQ 时直接丢弃，不重试也不报错 */
  if (task->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
    FreeCopyTask(task);
    return;
  }
  const wchar_t *src = task->SrcPath ? task->SrcPath : task->ShortSrc;
  const wchar_t *dst = task->DstPath ? task->DstPath : task->ShortDst;
  BOOL isBig = (task->FileSize >= SPLIT_THRESHOLD);
  BOOL isSparse = (task->FileAttributes & FILE_ATTRIBUTE_SPARSE_FILE) != 0;
  BOOL ret = FALSE;
  if (isBig) {
    if (isSparse)
      ret = CopySparseFile(src, dst, task->FileSize, param, NULL);
    if (!ret) {
      if (PickBigFileBuffered(task->FileSize)) {
        InterlockedIncrement64(&g_IoStrategyStats[IOSTRAT_BIG_BUFFERED]);
        ret = CopyBigFileBuffered(src, dst, task->FileSize, param, task);
      } else {
        InterlockedIncrement64(&g_IoStrategyStats[IOSTRAT_BIG_DIRECT_IO]);
        ret = CopyBigFileHighSpeed(src, dst, task->FileSize, param, task->FileAttributes);
      }
    }
  } else {
    ret = CopySmallFile(src, dst, task->FileSize, param, task->pSrcBackend, task->pDstBackend, task);
    if (!ret && !IsCanceling())
      ret = CopyFile2Ex(src, dst, g_Config.FastMode);
  }
  /* ACCESS_DENIED：清只读标记后再试一次 */
  if (!ret && GetLastError() == ERROR_ACCESS_DENIED) {
    SetFileAttributesW(dst, FILE_ATTRIBUTE_NORMAL);
    if (isBig) {
      if (PickBigFileBuffered(task->FileSize)) {
        InterlockedIncrement64(&g_IoStrategyStats[IOSTRAT_BIG_BUFFERED]);
        ret = CopyBigFileBuffered(src, dst, task->FileSize, param, task);
      } else {
        InterlockedIncrement64(&g_IoStrategyStats[IOSTRAT_BIG_DIRECT_IO]);
        ret = CopyBigFileHighSpeed(src, dst, task->FileSize, param, task->FileAttributes);
      }
    }
    else {
      ret = CopySmallFile(src, dst, task->FileSize, param, task->pSrcBackend, task->pDstBackend, task);
      if (!ret && !IsCanceling())
        ret = CopyFile2Ex(src, dst, g_Config.FastMode);
    }
  }
  if (ret) {
    CopyFileSecurityAndAttributes(src, dst, task);
    AddBucketCopied(param, 1);
    if (!isBig)
      AddBucketBytes(param, task->FileSize);
  } else {
    DWORD err = GetLastError();
    LogMessageRaw(LOG_ERROR, err, src, task->FileSize, 2);
    InterlockedIncrement(&g_TotalFailed);
    if (!g_Config.IsFtpDest)
      RequestAsyncCleanup(dst);
  }
  FreeCopyTask(task);
}

/* BUG-01：DLQ 并发重试线程入口——从 g_DeadLetterQueue 抢占任务，收到 Ctrl+C 立刻退出 */
static unsigned __stdcall DLQWorkerThread(void *arg) {
  CopierParam *param = (CopierParam *)arg;
  PSLIST_ENTRY e;
  while (!IsCanceling() && (e = InterlockedPopEntrySList(g_DeadLetterQueue)) != NULL)
    RetryDeadLetterTaskFast((CopyTask *)e, param);
  return 0;
}

/* Phase 16 I-Cache 热路径：独立代码节 + 64B 对齐，减少 Cache Line 边界跨越 */
#if defined(_MSC_VER)
#pragma code_seg(push, ".text$hot")
#endif
/* 返回 0=已完成(含成功/失败)，1=已重排队列(勿减 g_PendingActive) */
int ProcessTask(CopyTask *task, CopierParam *param) {
  if (g_Config.Preflight) {
    TLC_FreeCopyTask(param, task);
    return 0; /* 预检模式：仅扫盘计数，不拷贝 */
  }
  if (IsCanceling()) {
    TLC_FreeCopyTask(param, task);
    return 0;
  }
  param->TimestampsAlreadySet = FALSE;
#if defined(_M_IX86) || defined(_M_X64) || defined(__i386__) || defined(__x86_64__)
  /* Phase 15：路径热字段预取，掩盖 L1 miss，与 GetFileAttributesW/CreateFileW 重叠 */
  if (task->SrcPath) _mm_prefetch((const char *)task->SrcPath, _MM_HINT_T0);
  if (task->DstPath) _mm_prefetch((const char *)task->DstPath, _MM_HINT_T0);
#endif
  /* advice1 P0: USN/MFT 未知大小，尽早 GetFileSizeEx 再分流大/小文件与 Audit */
  if (task->FileSize < 0 && !g_Config.IsFtpSource) {
    HANDLE hSz = CreateFileW(task->SrcPath, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hSz == INVALID_HANDLE_VALUE) {
      TLC_FreeCopyTask(param, task);
      return 0;
    }
    LARGE_INTEGER liSz;
    if (!GetFileSizeEx(hSz, &liSz)) {
      CloseHandle(hSz);
      TLC_FreeCopyTask(param, task);
      return 0;
    }
    CloseHandle(hSz);
    task->FileSize = liSz.QuadPart;
    if (!PassesDateSizeFilter(task->FileSize, &task->LastWriteTime)) {
      TLC_FreeCopyTask(param, task);
      return 0;
    }
    InterlockedAdd64(&g_TotalFoundBytes, task->FileSize);
  }
  /* 双重防御：ProcessScanTask 可能因 FileAttributes 元数据异常将目录项误判为文件。
   * Case A：task->FileAttributes 本身带 DIRECTORY 位 → 直接丢弃（零 syscall）。
   * Case B：FileAttributes 不含 DIRECTORY 但实际路径是目录 → GetFileAttributesW 确认。
   * 两种情况都可导致 CopyBigFileHighSpeed 以 FILE_FLAG_NO_BUFFERING 打开目录失败 (Err:5)。 */
  if (task->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
    TLC_FreeCopyTask(param, task);
    return 0;
  }
  if (!g_Config.IsFtpSource && !g_Config.IsFtpDest) {
    DWORD srcAttr = GetFileAttributesW(task->SrcPath);
    if (srcAttr != INVALID_FILE_ATTRIBUTES && (srcAttr & FILE_ATTRIBUTE_DIRECTORY)) {
      TLC_FreeCopyTask(param, task);
      return 0;
    }
  }

  if (g_Config.AuditOnly) {
    /* Phase2：仅比对基准哈希索引，不读文件、不建表（与 Phase1 剥离规则一致） */
    if (READ_VOLATILE_32(&g_AuditPhase) == 2) {
      wchar_t norm[MAX_PATH_EXT];
      if (AuditPeerAbsToNormRel(task->SrcPath, norm, MAX_PATH_EXT)) {
        if (!AuditPathHashExists(norm)) {
          InterlockedIncrement(&g_AuditExtra);
          AuditReportLine(
              L"[Extra on destination] File exists on target only (not in baseline index): %ls\n",
              task->SrcPath);
        }
      }
      TLC_FreeCopyTask(param, task);
      return 0;
    }
    /* CopyTask：SrcPath=基准侧文件，DstPath=对端路径（与 g_Config 物理源/目解耦） */
    AuditCollectBaselinePath(task->SrcPath);
    BYTE hS[16], hD[16];
    WIN32_FILE_ATTRIBUTE_DATA dfa;
    InterlockedIncrement(&g_AuditChecked);
    if (!GetFileAttributesExW(task->DstPath, GetFileExInfoStandard, &dfa)) {
      InterlockedIncrement(&g_AuditMissing);
      InterlockedIncrement(&g_TotalFailed);
      if (g_Config.AuditMode == AUDIT_MODE_DST)
        AuditReportLine(
            L"[Missing on source] Baseline on target exists; peer path on source not found → baseline=%ls | peer=%ls\n",
            task->SrcPath, task->DstPath);
      else
        AuditReportLine(
            L"[Missing on destination] Baseline on source exists; peer path on target not found → baseline=%ls | peer=%ls\n",
            task->SrcPath, task->DstPath);
      TLC_FreeCopyTask(param, task);
      return 0;
    }
    LONGLONG dstSize = ((LONGLONG)dfa.nFileSizeHigh << 32) | dfa.nFileSizeLow;
    if (dstSize != task->FileSize) {
      InterlockedIncrement(&g_AuditSizeMismatch);
      InterlockedIncrement(&g_TotalFailed);
      AuditReportLine(
          L"[Size mismatch] baseline=%ls | peer=%ls | baselineSize=%lld peerSize=%lld\n",
          task->SrcPath, task->DstPath, (long long)task->FileSize, (long long)dstSize);
      TLC_FreeCopyTask(param, task);
      return 0;
    }
    if (!AuditLastWriteTimeMatches(&task->LastWriteTime, &dfa.ftLastWriteTime)) {
      wchar_t tsSrc[48], tsDst[48];
      AuditFormatFileTimeLocal(&task->LastWriteTime, tsSrc, 48);
      AuditFormatFileTimeLocal(&dfa.ftLastWriteTime, tsDst, 48);
      InterlockedIncrement(&g_AuditTimeMismatch);
      InterlockedIncrement(&g_TotalFailed);
      AuditReportLine(
          L"[Time mismatch] baseline=%ls | peer=%ls | baselineMtime=%ls peerMtime=%ls\n",
          task->SrcPath, task->DstPath, tsSrc, tsDst);
      TLC_FreeCopyTask(param, task);
      return 0;
    }
    if (!CalculateFileHash(task->SrcPath, hS, param) ||
        !CalculateFileHash(task->DstPath, hD, param)) {
      InterlockedIncrement(&g_AuditHashError);
      InterlockedIncrement(&g_TotalFailed);
      InterlockedIncrement(&g_Md5Fail);
      AuditReportLine(L"[Hash error] baseline=%ls | peer=%ls\n", task->SrcPath, task->DstPath);
      TLC_FreeCopyTask(param, task);
      return 0;
    }
    if (memcmp(hS, hD, 16) != 0) {
      InterlockedIncrement(&g_AuditHashMismatch);
      InterlockedIncrement(&g_TotalFailed);
      InterlockedIncrement(&g_Md5Fail);
      AuditReportLine(L"[Hash mismatch] baseline=%ls | peer=%ls\n", task->SrcPath, task->DstPath);
      TLC_FreeCopyTask(param, task);
      return 0;
    }
    InterlockedIncrement(&g_Md5Success);
    param->LocalCopied++;
    param->LocalBytes += task->FileSize;
    FlushLocalCounters(param, FALSE);
    TLC_FreeCopyTask(param, task);
    return 0;
  }

  BOOL isBig = (task->FileSize >= SPLIT_THRESHOLD && !g_Config.IsFtpSource &&
                !g_Config.IsFtpDest);

  if (!g_Config.IsFtpSource && !g_Config.IsFtpDest &&
      CheckIncrementalSync(task, param)) {
    InterlockedIncrement(&g_StateSame);
    if (task->FileSize < 1024 * 1024)
      param->LocalSmallFiles++;
    else if (task->FileSize < 10 * 1024 * 1024)
      param->LocalMediumFiles++;
    else
      param->LocalLargeFiles++;
    param->LocalCopied++;
    param->LocalBytes += task->FileSize;
    FlushLocalCounters(param, FALSE);
    TLC_FreeCopyTask(param, task);
    return 0;
  }

  /* 元数据-only：仅修复 ACL/时间戳/属性，不碰数据（AD 域权限修复场景） */
  if (g_Config.MetadataOnly) {
    EnsureParentDirExists(task->DstPath);
    CopyFileSecurityAndAttributes(task->SrcPath, task->DstPath, task);
    InterlockedIncrement(&g_StateTweaked);
    param->LocalCopied++;
    FlushLocalCounters(param, FALSE);
    TLC_FreeCopyTask(param, task);
    return 0;
  }

  /* 【关键修复 1】：大文件用带超时的原地阻塞，不再 Requeue，根除统计爆炸与 Sleep(1) 泥潭 */
  if (isBig && g_hBigFileSemaphore) {
    while (WaitForSingleObject(g_hBigFileSemaphore, 100) == WAIT_TIMEOUT) {
      if (IsCanceling()) {
        TLC_FreeCopyTask(param, task);
        return 0;
      }
    }
  }

  EnsureParentDirExistsCached(param, task->DstPath);

  /* -move 同卷：O(1) MFT 更新，瞬间完成，无需拷贝数据 */
  if (g_Config.IsMoveMode && g_IsSameVolume && !g_Config.IsFtpSource && !g_Config.IsFtpDest) {
    if (MoveFileExW(task->SrcPath, task->DstPath,
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
      param->LocalCopied++;
      param->LocalBytes += task->FileSize;
      if (task->FileSize < 1024 * 1024)
        param->LocalSmallFiles++;
      else if (task->FileSize < 10 * 1024 * 1024)
        param->LocalMediumFiles++;
      else
        param->LocalLargeFiles++;
      FlushLocalCounters(param, FALSE);
      if (isBig && g_hBigFileSemaphore)
        ReleaseSemaphore(g_hBigFileSemaphore, 1, NULL);
      TLC_FreeCopyTask(param, task);
      return 0;
    }
    /* MoveFileEx 失败（如目标被占用）则回退到 Copy+Delete 流程 */
  }

  /* ReFS/NTFS 块克隆：同卷大文件秒传，零拷贝元数据级复制 */
  if (isBig && g_IsSameVolume && !g_Config.IsFtpSource && !g_Config.IsFtpDest) {
    if (TryBlockCloneCopy(task->SrcPath, task->DstPath, task->FileSize, task)) {
      InterlockedIncrement64(&g_IoStrategyStats[IOSTRAT_BLOCK_CLONE]);
      param->LocalCopied++;
      param->LocalBytes += task->FileSize;
      param->LocalLargeFiles++;
      FlushLocalCounters(param, FALSE);
      if (g_hBigFileSemaphore) ReleaseSemaphore(g_hBigFileSemaphore, 1, NULL);
      TLC_FreeCopyTask(param, task);
      return 0;
    }
  }

  /* 乐观 I/O：不预先 GetFileAttributesW，避免千万次 NAS 网络查询；仅遇 ERROR_ACCESS_DENIED 时剥离属性重试 */

  /* PB：允许 -J 与 -D 同开（批内 XXH3 + 异步 Verify）；MD5 校验仍走同步小文件路径 */
  BOOL canIoRing = (g_Config.UseIoRing && g_IoRingAvailable && !isBig &&
                    task->FileSize >= 0 && task->FileSize < IORING_MAX_FILE_SIZE &&
                    !g_Config.IsFtpSource && !g_Config.IsFtpDest &&
                    !(g_Config.CompareContent && !g_Config.UseXxh3));

  /* 非批处理任务（大文件/FTP）进入时才刷批：
   * 批次已达 1/4 满时立即刷，确保聚合效率；批次太少时延迟到超时自然刷（CopierThread 已有兜底）
   * 这样混合负载下大文件不会每次都打断只有 1~2 个文件的 IoRing 小批次 */
  if (!canIoRing && param->IoRingBatchCount > 0) {
    int minFlushThreshold = g_IoRingBatchSize / 4;
    if (minFlushThreshold < 1) minFlushThreshold = 1;
    if (param->IoRingBatchCount >= minFlushThreshold)
      FlushIoRingBatch(param);
  }
  BOOL isSparse = (task->FileAttributes & FILE_ATTRIBUTE_SPARSE_FILE) != 0;

  /* 【关键】：扁平化防撞必须先于硬链接，否则 -i 时同名文件会互相 DeleteFile 覆盖 */
  if (!g_Config.IsFtpSource && !g_Config.IsFtpDest)
    ReserveUniqueFlatPath(task);

  BOOL ret = FALSE;
  BOOL usedHardLink = FALSE;
  /* -move 模式禁用硬链接：需删除源，硬链接会保留源 */
  if (!g_Config.IsMoveMode && TryCreateHardLink(task->SrcPath, task->DstPath)) {
    ret = TRUE;
    usedHardLink = TRUE;
    InterlockedIncrement(&g_HardLinkCount);
    InterlockedAdd64(&g_HardLinkBytes, task->FileSize);
  }
  if (canIoRing && !usedHardLink && param->IoRingBatch && param->IoRingBatchOk) {
    if (param->IoRingBatchTotalBytes + (DWORD)task->FileSize > THREAD_IORING_BUFFER_SIZE)
      FlushIoRingBatch(param);
    param->IoRingBatch[param->IoRingBatchCount++] = task;
    param->IoRingBatchTotalBytes += (DWORD)task->FileSize;
    if (param->IoRingBatchCount >= g_IoRingBatchSize)
      FlushIoRingBatch(param);
    FlushLocalCounters(param, FALSE);
    if (++param->TasksSinceRatioUpdate >= RATIO_UPDATE_INTERVAL) {
      param->TasksSinceRatioUpdate = 0;
      UpdateSmallFileRatio();
    }
    return 0;
  }

  BYTE hS[16];
  DWORD lastErr = 0;  /* QA：保存最后一次错误，用于 ERR_SKIP 不入 DLQ 及 DISK_FULL 熔断 */
  for (int i = 0; !ret && i < MAX_RETRY_COUNT && !IsCanceling(); i++) {
    if (g_Config.IsFtpSource || g_Config.IsFtpDest) {
      ret = CopySmallFile(task->SrcPath, task->DstPath, task->FileSize, param, task->pSrcBackend, task->pDstBackend, task);
    } else if (isBig) {
      if (isSparse) {
        ret = CopySparseFile(task->SrcPath, task->DstPath, task->FileSize, param,
                             g_Config.CompareContent ? hS : NULL);
        if (!ret) {
          isSparse = FALSE;
          if (PickBigFileBuffered(task->FileSize)) {
            InterlockedIncrement64(&g_IoStrategyStats[IOSTRAT_BIG_BUFFERED]);
            ret = CopyBigFileBuffered(task->SrcPath, task->DstPath, task->FileSize, param, task);
          } else {
            InterlockedIncrement64(&g_IoStrategyStats[IOSTRAT_BIG_DIRECT_IO]);
            ret = CopyBigFileHighSpeed(task->SrcPath, task->DstPath,
                                       task->FileSize, param, task->FileAttributes);
          }
        }
      } else {
        if (g_Config.UseZeroSkip)
          ret = CopyBigFileThin(task->SrcPath, task->DstPath, task->FileSize, param, task);
        if (!ret && g_Config.UseDeltaTransfer && g_Config.UseXxh3) {
          ret = CopyBigFileDelta(task->SrcPath, task->DstPath, task->FileSize, param,
                                task->FileAttributes);
        }
        if (!ret) {
          if (PickBigFileBuffered(task->FileSize)) {
            InterlockedIncrement64(&g_IoStrategyStats[IOSTRAT_BIG_BUFFERED]);
            ret = CopyBigFileBuffered(task->SrcPath, task->DstPath, task->FileSize, param, task);
          } else {
            InterlockedIncrement64(&g_IoStrategyStats[IOSTRAT_BIG_DIRECT_IO]);
            ret = CopyBigFileHighSpeed(task->SrcPath, task->DstPath, task->FileSize,
                                       param, task->FileAttributes);
          }
        }
      }
    } else {
      /* 【终极防线】：-D 内容校验开启时，强制走 Hash 核心通道，拒绝任何捷径与兜底 */
      if (g_Config.CompareContent) {
        ret = CopySmallFile(task->SrcPath, task->DstPath, task->FileSize, param, task->pSrcBackend, task->pDstBackend, task);
      } else {
        /* P1 修复：所有小文件统一走 CopySmallFile（内含 FILE_ATTRIBUTE_TEMPORARY +
         * 自带 AcquireBandwidthTokens）；失败时 CopyFile2（ODX/块克隆）或 CopyFileW 兜底 */
        ret = CopySmallFile(task->SrcPath, task->DstPath, task->FileSize, param, task->pSrcBackend, task->pDstBackend, task);
        if (!ret && !IsCanceling()) {
          AcquireBandwidthTokens(task->FileSize);
          ret = CopyFile2Ex(task->SrcPath, task->DstPath, g_Config.FastMode);
        }
      }
    }
    if (ret)
      break;
    DWORD err = GetLastError();
    lastErr = err;
    ErrorClass ec = ERR_RETRY;
    if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND ||
        err == ERROR_DISK_FULL || err == ERROR_INVALID_NAME ||
        err == ERROR_INVALID_PARAMETER || err == ERROR_DEVICE_NOT_CONNECTED)
      ec = ERR_SKIP;
    else if (err == ERROR_SHARING_VIOLATION || err == ERROR_LOCK_VIOLATION)
      ec = ERR_TRANSIENT;
    else if (err == 59 || err == 64 || err == 121 || err == 1231 || err == 1236)
      ec = ERR_NETWORK_DROP; /* 59=UNEXP_NET_ERR, 64=NETNAME_DELETED, 121=SEM_TIMEOUT, 1231=NETWORK_UNREACHABLE, 1236=CONNECTION_ABORTED */

    /* 【关键修复 2】：ACCESS_DENIED 剥离只读后仅允许再试 1 次，否则判 ERR_SKIP 避免指数退避黑洞 */
    if (err == ERROR_ACCESS_DENIED) {
      SetFileAttributesW(task->DstPath, FILE_ATTRIBUTE_NORMAL);
      if (i > 0)
        ec = ERR_SKIP;
    }

    if (ec == ERR_SKIP)
      break;
    /* P0 修复：SHARING_VIOLATION/LOCK_VIOLATION 是毫秒级 NTFS 目录锁冲突，
     * 快速重试 1ms/5ms/20ms，第 3 次仍失败直接进 DLQ，不再用秒级等待白白阻塞线程 */
    if (ec == ERR_TRANSIENT) {
      if (i >= 2) break; /* 3 次快速重试耗尽，转入 DLQ 并发挣扎 */
      static const DWORD kTransientMs[] = {1, 5};
      Sleep(kTransientMs[i]);
      continue;
    }
    /* 网络瞬断/SMB 故障：NAS 主备切换或链路抖动需数秒～十几秒恢复，长跳避让，3 次后进 DLQ */
    if (ec == ERR_NETWORK_DROP) {
      if (i >= 3) break; /* 15s+30s+60s 共 3 次耗尽，转入 DLQ */
      static const DWORD kNetworkSec[] = {15, 30, 60};
      DWORD sec = kNetworkSec[i];
      if (i > 0)
        wprintf(L"\n[NET] Retry %d: network drop (Err:%lu), sleeping %lu s...\n", i + 1, (unsigned long)err, sec);
      Sleep(sec * 1000);
      continue;
    }
    DWORD delay;
    delay = RETRY_BASE_DELAY_MS * (1 << i);
    if (delay > RETRY_MAX_DELAY_MS)
      delay = RETRY_MAX_DELAY_MS;
    int jitter = (int)(rand() % 41) - 20; /* ±20% 防惊群 */
    delay = (DWORD)((LONGLONG)delay * (100 + jitter) / 100);
    Sleep(delay);
  }

  /* 大文件校验：抽样模式用头/中/尾 300MB，常规模式用边拷边算 hS 或 CopyBigFileHighSpeed 内部 */
  if (ret && g_Config.CompareContent && isBig) {
    if (g_Config.SampleLargeFiles && task->FileSize >= GetSampleThreshold()) {
      BYTE sampledSrc[16];
      if (CalculateFileHashSampled(task->SrcPath, sampledSrc, task->FileSize, param, FALSE))
        PostVerifyTaskExForRetry(task->DstPath, sampledSrc, task->FileSize,
            task->SrcPath, task->FileAttributes);
    } else if (isSparse) {
      PostVerifyTaskExForRetry(task->DstPath, hS, task->FileSize,
          task->SrcPath, task->FileAttributes);
    }
  }

  if (ret) {
    /* -move 跨卷：拷贝成功后删除源文件 */
    if (g_Config.IsMoveMode && !g_IsSameVolume && !g_Config.IsFtpSource && !g_Config.IsFtpDest) {
      SetFileAttributesW(task->SrcPath, FILE_ATTRIBUTE_NORMAL);
      DeleteFileW(task->SrcPath);
    }
    if (!usedHardLink && !g_Config.IsFtpSource && !g_Config.IsFtpDest)
      CopyFileSecurityAndAttributesEx(task->SrcPath, task->DstPath, task,
                                      param->TimestampsAlreadySet, param);
    param->TimestampsAlreadySet = FALSE;
    param->LocalCopied++;
    /* 硬链接虽零 I/O，但宏观已完成，必须算入进度，否则 ETA 永久冰结 */
    if (!isBig || usedHardLink)
      param->LocalBytes += task->FileSize;

    /* 只有真正成功的任务才计入大小分类，避免失败/重试/IoRing 双重统计 */
    if (task->FileSize < 1024 * 1024)
      param->LocalSmallFiles++;
    else if (task->FileSize < 10 * 1024 * 1024)
      param->LocalMediumFiles++;
    else
      param->LocalLargeFiles++;
  } else {
    /* Ctrl+C：不计失败、不入 DLQ */
    if (IsCanceling()) {
      if (isBig && g_hBigFileSemaphore)
        ReleaseSemaphore(g_hBigFileSemaphore, 1, NULL);
      TLC_FreeCopyTask(param, task);
      return 0;
    }
    /* QA 熔断：ERROR_DISK_FULL 立即全局停止，ERR_SKIP 不入 DLQ 避免百万次无意义重试 */
    if (lastErr == ERROR_DISK_FULL) {
      InterlockedExchange(&g_InsufficientSpace, 1);
      InterlockedExchange(&g_IsCanceling, 1);
      wprintf(L"\n[FATAL] Disk full (Err:112)! Stopping. Free space and retry.\n");
    }
    if (lastErr == ERROR_FILE_NOT_FOUND || lastErr == ERROR_PATH_NOT_FOUND ||
        lastErr == ERROR_DISK_FULL || lastErr == ERROR_INVALID_NAME ||
        lastErr == ERROR_INVALID_PARAMETER || lastErr == ERROR_DEVICE_NOT_CONNECTED) {
#if HAS_VSS
      if (g_Config.UseVss && (lastErr == ERROR_DEVICE_NOT_CONNECTED || lastErr == ERROR_FILE_NOT_FOUND))
        wprintf(L"\n[VSS] Snapshot may have been dropped; device/path not found (Err:%lu).\n", (unsigned long)lastErr);
#endif
      LogMessageRaw(LOG_ERROR, lastErr, task->SrcPath, task->FileSize, 0);
      InterlockedIncrement(&g_TotalFailed);
      if (!g_Config.IsFtpDest)
        RequestAsyncCleanup(task->DstPath);
      FlushLocalCounters(param, FALSE);
      if (++param->TasksSinceRatioUpdate >= RATIO_UPDATE_INTERVAL) {
        param->TasksSinceRatioUpdate = 0;
        UpdateSmallFileRatio();
      }
      if (isBig && g_hBigFileSemaphore)
        ReleaseSemaphore(g_hBigFileSemaphore, 1, NULL);
      TLC_FreeCopyTask(param, task);
      return 0;
    }
    /* 死信队列：重试耗尽不入队报错，主流水线结束后并发挣扎 */
    if (g_DeadLetterQueue && !g_NoDLQ) {
      if (task->DlqRoundCount >= MAX_DLQ_ROUND_TRIPS) {
        LogMessage(LOG_ERROR,
            L"[DLQ] Max round-trips exceeded (ProcessTask path), giving up: %ls\n",
            task->SrcPath ? task->SrcPath : task->ShortSrc);
        InterlockedIncrement(&g_TotalFailed);
        if (!g_Config.IsFtpDest)
          RequestAsyncCleanup(task->DstPath);
        FlushLocalCounters(param, FALSE);
        if (++param->TasksSinceRatioUpdate >= RATIO_UPDATE_INTERVAL) {
          param->TasksSinceRatioUpdate = 0;
          UpdateSmallFileRatio();
        }
        if (isBig && g_hBigFileSemaphore)
          ReleaseSemaphore(g_hBigFileSemaphore, 1, NULL);
        /* CopierThread 对 ProcessTask 返回 0 会统一扣减 g_PendingActive/g_PendingCopyTasks；此处禁再 Decrement。
         * CopyTask 无 DirCtrl 字段；若日后引入目录并发控制，须在放弃路径与 TLC_FreeCopyTask 对齐。 */
        TLC_FreeCopyTask(param, task);
        return 0;
      }
      task->DlqRoundCount++;
      /* P0 诊断：每 500 次 DLQ 入队在屏幕上采样一次错误码，确认失败根因（不刷屏） */
      static volatile LONG s_DlqSampleCnt = 0;
      DWORD dlqErr = GetLastError();
      if ((InterlockedIncrement(&s_DlqSampleCnt) % 500) == 1)
        wprintf(L"\n[DLQ-SAMPLE #%ld] Err:%lu -> %ls\n",
                (long)READ_VOLATILE_32(&s_DlqSampleCnt),
                (unsigned long)dlqErr, task->SrcPath);
      InterlockedPushEntrySList(g_DeadLetterQueue, &task->ItemEntry);
      if (isBig && g_hBigFileSemaphore)
        ReleaseSemaphore(g_hBigFileSemaphore, 1, NULL);
      FlushLocalCounters(param, FALSE);
      if (++param->TasksSinceRatioUpdate >= RATIO_UPDATE_INTERVAL) {
        param->TasksSinceRatioUpdate = 0;
        UpdateSmallFileRatio();
      }
      return 0; /* 不释放 task，已入 DLQ */
    }
    DWORD err = GetLastError();
    LogMessageRaw(LOG_ERROR, err, task->SrcPath, task->FileSize, 0);
    InterlockedIncrement(&g_TotalFailed);
    if (!g_Config.IsFtpDest)
      RequestAsyncCleanup(task->DstPath);
  }
  FlushLocalCounters(param, FALSE);
  if (++param->TasksSinceRatioUpdate >= RATIO_UPDATE_INTERVAL) {
    param->TasksSinceRatioUpdate = 0;
    UpdateSmallFileRatio();
  }
  if (isBig && g_hBigFileSemaphore)
    ReleaseSemaphore(g_hBigFileSemaphore, 1, NULL);
  TLC_FreeCopyTask(param, task);
  return 0;
}
#if defined(_MSC_VER)
#pragma code_seg(pop)
#endif

/* 递归删除路径（文件或目录及其内容）；镜像模式孤儿清理用
 * 【栈安全】：pattern/child 用堆分配，避免深层目录 130KB×N 击穿 1MB 线程栈 */
static void DeletePathRecursive(const wchar_t *path) {
  DWORD attr = GetFileAttributesW(path);
  if (attr == INVALID_FILE_ATTRIBUTES)
    return;
  if (attr & FILE_ATTRIBUTE_DIRECTORY) {
    if (wcslen(path) + 4 >= MAX_PATH_EXT)
      return;
    wchar_t *pattern = (wchar_t *)malloc(MAX_PATH_EXT * sizeof(wchar_t));
    wchar_t *child = (wchar_t *)malloc(MAX_PATH_EXT * sizeof(wchar_t));
    if (!pattern || !child) {
      if (pattern) free(pattern);
      if (child) free(child);
      return;
    }
    StringCchPrintfW(pattern, MAX_PATH_EXT, L"%ls\\*", path);
    WIN32_FIND_DATAW fd;
    /* P0: FindFirstFileExW + LARGE_FETCH 提升大目录遍历速度（X-Flow 实践） */
#ifndef FIND_FIRST_EX_LARGE_FETCH
#define FIND_FIRST_EX_LARGE_FETCH 0x00000001
#endif
    DWORD findFlags = FIND_FIRST_EX_LARGE_FETCH;
    HANDLE hFind = FindFirstFileExW(pattern, FindExInfoBasic, &fd,
        FindExSearchNameMatch, NULL, findFlags);
    if (hFind == INVALID_HANDLE_VALUE && findFlags != 0) {
      hFind = FindFirstFileW(pattern, &fd);  /* 回退：旧系统无 LARGE_FETCH */
    }
    if (hFind != INVALID_HANDLE_VALUE) {
      do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
          continue;
        if (FAILED(StringCchPrintfW(child, MAX_PATH_EXT, L"%ls\\%ls", path, fd.cFileName))) {
          LogMessage(LOG_WARNING, L"[DelScan] Path truncated, skipping: %ls\\%ls\n", path, fd.cFileName);
          continue;
        }
        DeletePathRecursive(child);
      } while (FindNextFileW(hFind, &fd));
      FindClose(hFind);
    }
    free(pattern);
    free(child);
    RemoveDirectoryW(path);
  } else {
    SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);
    DeleteFileW(path);
  }
}

/* -delete 极速删除：流式 LIFO，O(深度) 堆栈，千万碎文件无内存炸弹
 * 文件见光死：发现即压入 SLIST，工作线程立即 DeleteFileW
 * 目录 LIFO 栈：DFS 进入时压栈，Pop 顺序天然自底向上
 * 迭代 DFS 避免递归栈溢出（node_modules 等超深树） */
typedef struct { SLIST_ENTRY ItemEntry; wchar_t *Path; } DelFileEntry;
typedef struct { SLIST_ENTRY ItemEntry; wchar_t *Path; } DelDirEntry;
typedef struct { wchar_t *path; HANDLE hFind; int hasFirst; WIN32_FIND_DATAW fd; } DelDfsFrame;
#define DEL_FILE_QUEUE_MAX 10000
#define DEL_DFS_STACK_INIT 2048

static PSLIST_HEADER g_DelFileQueue = NULL;
static PSLIST_HEADER g_DelDirStack = NULL;
static volatile LONG g_DelFileCount = 0;
static volatile LONG g_DelDirCount = 0;
static volatile LONG g_DelScannerDone = 0;
static HANDLE g_hDelSem = NULL;  /* 文件入队时 +1，工作线程空队列时 Wait，替代 5ms 轮询 */
static volatile LONG g_DelScanIter = 0;  /* 崩溃定位：当前迭代序号 */
static DWORD g_DelStartTick = 0;         /* -delete 进度行统一起始时间 */

/* -delete 实时进度：与 GUI 约定标签 [File]/[Dirs]/PROGRESS，便于单行替换显示 */
static void PrintDeleteStatsLine(DWORD startTick, int force) {
  static DWORD s_lastTick = 0;
  DWORD now = GetTickCount();
  DWORD interval = (DWORD)(g_Config.RefreshInterval > 0 ? g_Config.RefreshInterval : 200);
  if (!force && (now - s_lastTick < interval))
    return;
  s_lastTick = now;

  LONG files = READ_VOLATILE_32(&g_DelFileCount);
  LONG dirs = READ_VOLATILE_32(&g_DelDirCount);
  LONG q = g_DelFileQueue ? (LONG)QueryDepthSList(g_DelFileQueue) : 0;
  LONG scannerDone = READ_VOLATILE_32(&g_DelScannerDone);
  double elapsed = (double)(now - startTick) / 1000.0;
  if (elapsed < 0.001) elapsed = 0.001;
  LONG avg = (LONG)((double)files / elapsed + 0.5);
  /* 已删文件 / (已删 + 队列中待删) = 当前可见删除进度；扫描未结束时磁盘仍有未枚举项，故封顶 95% */
  double progress = 0.0;
  {
    LONG denom = files + q;
    if (denom > 0)
      progress = (double)files * 100.0 / (double)denom;
    if (progress > 100.0)
      progress = 100.0;
    if (!scannerDone && progress > 95.0)
      progress = 95.0;
  }
  int sec = (int)elapsed;
  int h = sec / 3600, m = (sec % 3600) / 60, s = sec % 60;

  wchar_t line[512];
  StringCchPrintfW(line, 512,
      L"\r[File] %-8ld | [Dirs] %-8ld | Q:%-6ld | Scanner:%c | Avg: %ld/s | PROGRESS: %.1f%% | Elapsed %02d:%02d:%02d   ",
      (long)files, (long)dirs, (long)q, scannerDone ? L'Y' : L'N', (long)avg, progress, h, m, s);
  ConsoleWriteRunStatusLine(line);
}

static void DelScanIterative(const wchar_t *rootPath) {
  /* SList 节点必须 16 字节对齐：cmpxchg16b 要求，malloc 仅保证 8 字节，MinGW 下易 0xC0000005 */
  DelDirEntry *deRoot = (DelDirEntry *)_aligned_malloc(sizeof(DelDirEntry), 16);
  if (deRoot) {
    deRoot->Path = _wcsdup(rootPath);
    InterlockedPushEntrySList(g_DelDirStack, &deRoot->ItemEntry);
    InterlockedIncrement(&g_DelDirCount);
  }
  size_t stack_capacity = DEL_DFS_STACK_INIT;
  DelDfsFrame *stack = (DelDfsFrame *)malloc(stack_capacity * sizeof(DelDfsFrame));
  if (!stack) return;
  int top = 0;
  stack[0].path = _wcsdup(rootPath);
  if (!stack[0].path) { free(stack); return; }
  wchar_t *pattern = (wchar_t *)malloc(MAX_PATH_EXT * sizeof(wchar_t));
  if (!pattern) { free(stack[0].path); free(stack); return; }
  StringCchPrintfW(pattern, MAX_PATH_EXT, L"%ls\\*", rootPath);
  /* FindExInfoBasic：8.3 短名计算可省。LARGE_FETCH 在 11000+ 迭代时可能触发 ntdll 0xC0000005，暂禁用 */
  stack[0].hFind = FindFirstFileExW(pattern, FindExInfoBasic, &stack[0].fd, FindExSearchNameMatch, NULL, 0);
  if (stack[0].hFind == INVALID_HANDLE_VALUE) stack[0].hFind = FindFirstFileW(pattern, &stack[0].fd);
  if (stack[0].hFind == INVALID_HANDLE_VALUE) {
    free(stack[0].path);
    free(pattern);
    free(stack);
    return;  /* 空目录，根已入栈 */
  }
  stack[0].hasFirst = 1;
  top = 1;
  /* 优化1：child 移出循环，500 万文件时避免 500 万次 malloc/free 的 Syscall 风暴 */
  wchar_t *child = (wchar_t *)malloc(MAX_PATH_EXT * sizeof(wchar_t));
  if (!child) { free(stack[0].path); free(pattern); free(stack); return; }
  { static volatile LONG _diag = 0; }
  while (top > 0) {
    /* 扫描阶段也要持续刷新进度，避免用户看到“无输出”误以为卡死 */
    PrintDeleteStatsLine(g_DelStartTick, 0);
  delscan_top:
    DelDfsFrame *f = &stack[top - 1];
    WIN32_FIND_DATAW *fd = &f->fd;
    if (!f->path) { free(child); free(pattern); free(stack); return; }
    if (!f->hasFirst) {
      for (;;) {
        if (FindNextFileW(f->hFind, fd))
          break;
        DWORD e2 = GetLastError();
        if (e2 == ERROR_NO_MORE_FILES) {
          FindClose(f->hFind);
          free(f->path);
          top--;
          if (top > 0)
            goto delscan_top;
          break;
        }
        if (e2 == ERROR_ACCESS_DENIED || e2 == ERROR_SHARING_VIOLATION) {
          LogMessage(LOG_WARNING,
                     L"[DelScan] FindNextFile: access denied/sharing, continuing: %ls err=%lu\n",
                     f->path, (unsigned long)e2);
          continue;
        }
        FindClose(f->hFind);
        free(f->path);
        top--;
        if (top > 0)
          goto delscan_top;
        break;
      }
    }
    f->hasFirst = 0;
    if (wcscmp(fd->cFileName, L".") == 0 || wcscmp(fd->cFileName, L"..") == 0) continue;
    { static volatile LONG _diag2 = 0;
      LONG v = InterlockedIncrement(&_diag2);
      g_DelScanIter = v;
     }
    if (FAILED(StringCchPrintfW(child, MAX_PATH_EXT, L"%ls\\%ls", f->path, fd->cFileName))) {
      LogMessage(LOG_WARNING, L"[DelScan] Path truncated, skipping: %ls\\%ls\n", f->path, fd->cFileName);
      continue;
    }
    /* 崩溃定位：11000-11100 区间每项写入路径，便于定位问题文件 */
    { LONG v = g_DelScanIter;
      if (v >= 11000 && v < 11100) {
        char buf[512];
        int n = WideCharToMultiByte(CP_UTF8, 0, child, -1, buf, sizeof(buf), NULL, NULL);
        if (n > 0) {
          buf[n-1] = '\n'; buf[n] = '\0';
        }
      }
    }
    if (fd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      /* 动态扩容栈：消灭 node_modules 等超深树深度限制 */
      if ((size_t)top >= stack_capacity) {
        size_t new_cap = stack_capacity * 2;
        DelDfsFrame *new_stack = (DelDfsFrame *)realloc(stack, new_cap * sizeof(DelDfsFrame));
        if (!new_stack) {
          LogMessage(LOG_WARNING, L"[DelScan] realloc failed at depth %d, aborting subtree\n", top);
          /* 优化2：realloc 失败时必须关闭所有栈帧的 Find 句柄，否则 NTFS 目录死锁 */
          for (int i = 0; i < top; i++) {
            if (stack[i].hFind != INVALID_HANDLE_VALUE) FindClose(stack[i].hFind);
            if (stack[i].path) { free(stack[i].path); stack[i].path = NULL; }
          }
          free(child);
          free(pattern);
          free(stack);
          return;
        }
        stack = new_stack;
        stack_capacity = new_cap;
      }
      StringCchPrintfW(pattern, MAX_PATH_EXT, L"%ls\\*", child);
      HANDLE hSub = FindFirstFileExW(pattern, FindExInfoBasic, &stack[top].fd, FindExSearchNameMatch, NULL, 0);
      if (hSub == INVALID_HANDLE_VALUE) hSub = FindFirstFileW(pattern, &stack[top].fd);
      if (hSub != INVALID_HANDLE_VALUE) {
        DelDirEntry *de = (DelDirEntry *)_aligned_malloc(sizeof(DelDirEntry), 16);
        if (de) {
          de->Path = _wcsdup(child);
          if (de->Path) { InterlockedPushEntrySList(g_DelDirStack, &de->ItemEntry); InterlockedIncrement(&g_DelDirCount); }
          else { _aligned_free(de); }
        }
        stack[top].path = _wcsdup(child);
        if (!stack[top].path) {
          FindClose(hSub);
          continue;  /* _wcsdup 失败时跳过该子树，避免后续 f->path 解引用 NULL 导致 0xC0000005 */
        }
        stack[top].hFind = hSub;
        stack[top].hasFirst = 1;
        top++;
      }
    } else {
      while ((LONG)QueryDepthSList(g_DelFileQueue) >= DEL_FILE_QUEUE_MAX) SwitchToThread();
      DelFileEntry *fe = (DelFileEntry *)_aligned_malloc(sizeof(DelFileEntry), 16);
      if (fe) {
        fe->Path = _wcsdup(child);
        if (fe->Path) {
          InterlockedPushEntrySList(g_DelFileQueue, &fe->ItemEntry);
          if (g_hDelSem) ReleaseSemaphore(g_hDelSem, 1, NULL);  /* 优化3：信号量唤醒工作线程 */
        } else { _aligned_free(fe); }
      }
    }
  }
  free(child);
  free(pattern);
  free(stack);
}

/* 修复短路求值陷阱：必须先原子取任务再判断，避免 !g_DelScannerDone 短路导致 e 未初始化 */
static unsigned __stdcall DelFileWorker(void *arg) {
  (void)arg;
  while (1) {
    PSLIST_ENTRY e = InterlockedPopEntrySList(g_DelFileQueue);
    if (!e) {
      if (READ_VOLATILE_32(&g_DelScannerDone)) break;  /* 扫描已完成且队列已空，安全退出 */
      if (g_hDelSem)
        WaitForSingleObject(g_hDelSem, 100);
      else
        SwitchToThread();
      continue;
    }
    DelFileEntry *ent = (DelFileEntry *)e;
    if (!ent->Path) { _aligned_free(ent); continue; }
    SetFileAttributesW(ent->Path, FILE_ATTRIBUTE_NORMAL);
    if (!DeleteFileW(ent->Path)) {
      Sleep(5);
      DeleteFileW(ent->Path);
    }
    InterlockedIncrement(&g_DelFileCount);
    free(ent->Path);
    _aligned_free(ent);
  }
  return 0;
}

static int RunFastDeleteMode(void) {
  wprintf(L"[FastDelete] Mode: Starting delete on %ls\n", g_Config.SrcPath);
  DWORD delStartTick = GetTickCount();
  g_DelStartTick = delStartTick;
  wchar_t root[MAX_PATH_EXT];
  NormalizePath(g_Config.SrcPath, root, MAX_PATH_EXT);
  if (wcsncmp(root, L"\\\\?\\", 4) != 0 && wcslen(root) >= LONG_PATH_THRESHOLD) {
    if (root[0] && root[1] == L':')
      StringCchPrintfW(root, MAX_PATH_EXT, L"\\\\?\\%c:\\%ls", root[0], root[2] ? root + 3 : L"");
    else if (root[0] == L'\\' && root[1] == L'\\')
      StringCchPrintfW(root, MAX_PATH_EXT, L"\\\\?\\UNC\\%ls", root + 2);
    else
      StringCchPrintfW(root, MAX_PATH_EXT, L"\\\\?\\%ls", root);
  }
  g_DelFileQueue = (PSLIST_HEADER)_aligned_malloc(sizeof(SLIST_HEADER), 16);
  g_DelDirStack = (PSLIST_HEADER)_aligned_malloc(sizeof(SLIST_HEADER), 16);
  if (!g_DelFileQueue || !g_DelDirStack) {
    if (g_DelFileQueue) PB_ALIGNED_FREE(g_DelFileQueue);
    if (g_DelDirStack) PB_ALIGNED_FREE(g_DelDirStack);
    wprintf(L"Fatal: malloc failed for FastDelete queues\n");
    return 1;
  }
  InitializeSListHead(g_DelFileQueue);
  InitializeSListHead(g_DelDirStack);
  g_DelFileCount = 0;
  g_DelDirCount = 0;
  g_DelScannerDone = 0;
  g_hDelSem = CreateSemaphoreW(NULL, 0, 0x7FFFFFFF, NULL);  /* 优化3：文件入队时 +1 */

  DWORD rootAttr = GetFileAttributesW(root);
  if (rootAttr == INVALID_FILE_ATTRIBUTES) {
    wprintf(L"Error: Path does not exist: %ls\n", root);
    if (g_hDelSem) { CloseHandle(g_hDelSem); g_hDelSem = NULL; }
    PB_ALIGNED_FREE(g_DelFileQueue);
    PB_ALIGNED_FREE(g_DelDirStack);
    return 1;
  }
  if (!(rootAttr & FILE_ATTRIBUTE_DIRECTORY)) {
    SetFileAttributesW(root, FILE_ATTRIBUTE_NORMAL);
    if (DeleteFileW(root))
      wprintf(L"[FastDelete] Removed 1 file\n");
    else
      wprintf(L"Error: DeleteFile failed: %ls\n", root);
    if (g_hDelSem) { CloseHandle(g_hDelSem); g_hDelSem = NULL; }
    PB_ALIGNED_FREE(g_DelFileQueue);
    PB_ALIGNED_FREE(g_DelDirStack);
    return 0;
  }

  int nWorkers = g_Config.ThreadCountNormal;
  if (nWorkers > 64) nWorkers = 64;
  if (nWorkers < 1) nWorkers = 1;
  HANDLE *hWorkers = (HANDLE *)malloc((size_t)nWorkers * sizeof(HANDLE));
  if (!hWorkers) {
    if (g_hDelSem) { CloseHandle(g_hDelSem); g_hDelSem = NULL; }
    PB_ALIGNED_FREE(g_DelFileQueue);
    PB_ALIGNED_FREE(g_DelDirStack);
    return 1;
  }
  /* 关键修复：先启动消费者线程再扫描，否则 >10000 文件时 DelScanIterative 在队列满时永久死锁 */
  InterlockedExchange(&g_DelScannerDone, 0);
  for (int i = 0; i < nWorkers; i++)
    hWorkers[i] = (HANDLE)_beginthreadex(NULL, 0, DelFileWorker, NULL, 0, NULL);

  DelScanIterative(root);
  PrintDeleteStatsLine(delStartTick, 1);

  InterlockedExchange(&g_DelScannerDone, 1);
  if (g_pfnWakeByAddressAll) g_pfnWakeByAddressAll((void *)&g_DelScannerDone);
  if (g_hDelSem) ReleaseSemaphore(g_hDelSem, nWorkers, NULL);  /* 唤醒所有等待的工作线程收尾 */

  for (;;) {
    DWORD wr = WaitForMultipleObjects((DWORD)nWorkers, hWorkers, TRUE, 120);
    PrintDeleteStatsLine(delStartTick, 0);
    if (wr == WAIT_OBJECT_0)
      break;
  }
  for (int i = 0; i < nWorkers; i++) {
    if (hWorkers[i])
      CloseHandle(hWorkers[i]);
  }
  free(hWorkers);

  /* Windows DeleteFileW 为异步：文件标记删除后需等句柄关闭才真正移除。
   * 海量小文件时，立即 RemoveDirectoryW 易得 ERROR_DIR_NOT_EMPTY，需短暂休眠后重试。 */
  Sleep((g_DelFileCount > 10000) ? 300 : 150);

  while (1) {
    PSLIST_ENTRY e = InterlockedPopEntrySList(g_DelDirStack);
    if (!e) break;
    DelDirEntry *de = (DelDirEntry *)e;
    if (!de->Path) { _aligned_free(de); continue; }
    SetFileAttributesW(de->Path, FILE_ATTRIBUTE_NORMAL);
    for (int retry = 0; retry < 5; retry++) {
      if (RemoveDirectoryW(de->Path)) break;
      if (GetLastError() == ERROR_DIR_NOT_EMPTY) {
        Sleep(50 * (retry + 1));
        continue;
      }
      break;
    }
    free(de->Path);   /* _wcsdup 分配，用普通 free */
    _aligned_free(de);
  }
  /* 根目录已在 DelScanIterative 入栈，无需单独 RemoveDirectoryW */
  if (g_hDelSem) { CloseHandle(g_hDelSem); g_hDelSem = NULL; }
  PB_ALIGNED_FREE(g_DelFileQueue);
  PB_ALIGNED_FREE(g_DelDirStack);
  PrintDeleteStatsLine(delStartTick, 1);
  wprintf(L"\n");
  wprintf(L"[FastDelete] Removed %ld files, %ld dirs (streaming LIFO)\n", (long)g_DelFileCount, (long)g_DelDirCount);
  return 0;
}

/* -move 跨卷：收集源目录路径，主循环结束后自底向上删除 */
/* N10：带预缓存长度的排序键，qsort 比较函数零 wcslen（O(N log N) 次比较不再含 wcslen）*/
typedef struct { wchar_t *Path; size_t Len; } MoveSortKey;
static int MoveSortKeyCmp(const void *a, const void *b) {
  size_t la = ((const MoveSortKey *)a)->Len;
  size_t lb = ((const MoveSortKey *)b)->Len;
  if (la < lb) return 1;   /* 降序 */
  if (la > lb) return -1;
  return 0;
}
/* D9 旧比较函数保留为退回路径（内存分配失败时） */
static int MoveSourceDirCmp(const void *a, const void *b) {
  size_t la = wcslen(((const MoveSourceDirEntry *)a)->Path);
  size_t lb = wcslen(((const MoveSourceDirEntry *)b)->Path);
  if (la < lb) return 1;
  if (la > lb) return -1;
  return 0;
}

static void AddMoveSourceDir(const wchar_t *path) {
  if (!g_MoveSourceDirsList || !g_Config.IsMoveMode || g_IsSameVolume) return;
  MoveSourceDirEntry *e = (MoveSourceDirEntry *)malloc(sizeof(MoveSourceDirEntry));
  if (!e) return;
  e->Path = _wcsdup(path);
  if (!e->Path) { free(e); return; }
  EnterCriticalSection(&g_MoveSourceDirsCs);
  InterlockedPushEntrySList(g_MoveSourceDirsList, &e->ItemEntry);
  LeaveCriticalSection(&g_MoveSourceDirsCs);
}

/* MFT/USN 极速扫描：需管理员权限打开 \\\\.\\C:，FSCTL_ENUM_USN_DATA 秒级千万文件。
 * 非 NTFS/网络盘或非管理员时回退 GetFileInformationByHandleEx(FileIdBothDirectoryInfo)。
 * -A 启用，输出缓冲首 8 字节为 NextFileReferenceNumber，其后为 USN_RECORD_V2。 */

/* 检测当前进程是否以管理员身份运行 */
static BOOL IsUserAdmin(void) {
  BOOL ok = FALSE;
  PSID grp = NULL;
  SID_IDENTIFIER_AUTHORITY ntAuth = {SECURITY_NT_AUTHORITY};
  if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
      DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &grp)) {
    CheckTokenMembership(NULL, grp, &ok);
    FreeSid(grp);
  }
  return ok;
}

/* 检测卷是否为 NTFS */
static BOOL IsVolumeNTFS(const wchar_t *path) {
  wchar_t root[4] = {0};
  if (path[0] && path[1] == L':' && (path[2] == L'\\' || path[2] == L'/')) {
    root[0] = path[0];
    root[1] = L':';
    root[2] = L'\\';
    root[3] = L'\0';
  } else if (wcsncmp(path, L"\\\\?\\", 4) == 0 && path[4] && path[5] == L':') {
    root[0] = path[4];
    root[1] = L':';
    root[2] = L'\\';
    root[3] = L'\0';
  } else
    return FALSE;
  wchar_t fsName[MAX_PATH + 1];
  if (!GetVolumeInformationW(root, NULL, 0, NULL, NULL, NULL, fsName, MAX_PATH + 1))
    return FALSE;
  return _wcsicmp(fsName, L"NTFS") == 0;
}

/* 检测卷是否支持块克隆：优先 FILE_SUPPORTS_BLOCK_REFCOUNTING（运行时能力位），
 * 旧系统再回退 NTFS/ReFS 名称（实际 DeviceIoControl 仍可能失败，由 TryBlockCloneCopy 回退）。 */
static BOOL IsVolumeBlockCloneSupported(const wchar_t *path) {
  wchar_t root[4] = {0};
  if (path[0] && path[1] == L':' && (path[2] == L'\\' || path[2] == L'/')) {
    root[0] = path[0];
    root[1] = L':';
    root[2] = L'\\';
    root[3] = L'\0';
  } else if (wcsncmp(path, L"\\\\?\\", 4) == 0 && path[4] && path[5] == L':') {
    root[0] = path[4];
    root[1] = L':';
    root[2] = L'\\';
    root[3] = L'\0';
  } else
    return FALSE;
  wchar_t fsName[MAX_PATH + 1];
  DWORD fsFlags = 0;
  if (!GetVolumeInformationW(root, NULL, 0, NULL, NULL, &fsFlags, fsName, MAX_PATH + 1))
    return FALSE;
  if (fsFlags & FILE_SUPPORTS_BLOCK_REFCOUNTING)
    return TRUE;
  return (_wcsicmp(fsName, L"NTFS") == 0 || _wcsicmp(fsName, L"ReFS") == 0);
}

/* ReFS/NTFS 块克隆：同卷大文件秒传，零拷贝元数据级复制。失败时返回 FALSE 供上层回退 */
static BOOL TryBlockCloneCopy(const wchar_t *src, const wchar_t *dst,
    LONGLONG fileSize, const CopyTask *task) {
  if (fileSize <= 0 || !g_IsSameVolume || IsUncPath(src) || IsUncPath(dst))
    return FALSE;
  if (g_BlockCloneProbed) {
    if (!g_CanBlockClone)
      return FALSE;
  } else {
    if (!IsVolumeBlockCloneSupported(src) || !IsVolumeBlockCloneSupported(dst))
      return FALSE;
    DWORD serS = 0, serD = 0;
    if (!GetVolumeSerialNumberFromPath(src, &serS) || !GetVolumeSerialNumberFromPath(dst, &serD) ||
        serS != serD)
      return FALSE;
  }
  DWORD alignSize = g_BlockCloneProbed ? g_BlockCloneAlignSize : 0;
  if (alignSize < 512) {
    DWORD csS = ProbeClusterSizeEx(src);
    DWORD csD = ProbeClusterSizeEx(dst);
    alignSize = (csS >= csD) ? csS : csD;
    if (alignSize < 512) alignSize = 512;
  }
  LONGLONG alignedSize = (fileSize / alignSize) * alignSize;
  if (alignedSize <= 0)
    return FALSE;
  HANDLE hSrc = CreateFileW(src, GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_BACKUP_SEMANTICS, NULL);
  if (hSrc == INVALID_HANDLE_VALUE) return FALSE;
  HANDLE hDst = CreateFileW(dst, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, NULL);
  if (hDst == INVALID_HANDLE_VALUE) {
    CloseHandle(hSrc);
    return FALSE;
  }
  LARGE_INTEGER liSize;
  liSize.QuadPart = fileSize;
  SetFilePointerEx(hDst, liSize, NULL, FILE_BEGIN);
  SetEndOfFile(hDst);
  SetFilePointerEx(hDst, (LARGE_INTEGER){0}, NULL, FILE_BEGIN);
  DUPLICATE_EXTENTS_DATA dup = {0};
  dup.FileHandle = hSrc;
  dup.SourceFileOffset.QuadPart = 0;
  dup.TargetFileOffset.QuadPart = 0;
  dup.ByteCount.QuadPart = alignedSize;
  DWORD bytesReturned;
  BOOL ok = DeviceIoControl(hDst, FSCTL_DUPLICATE_EXTENTS_TO_FILE,
      &dup, sizeof(dup), NULL, 0, &bytesReturned, NULL);
  if (!ok) {
    DWORD e = GetLastError();
    LONG n = InterlockedIncrement(&g_BlockCloneFsctlFailLogCount);
    /* 仅写错误日志文件，不经过 LogMessage/控制台（企业内网与商业部署避免刷屏） */
    if (n <= 16 && g_fErrorLog) {
      EnterCriticalSection(&g_LogCs);
      fwprintf(g_fErrorLog,
               L"[BlockClone] DUPLICATE_EXTENTS failed err=%lu src=%ls dst=%ls (max 16 lines)\n",
               (unsigned long)e, src, dst);
      fflush(g_fErrorLog);
      LeaveCriticalSection(&g_LogCs);
    }
  }
  if (ok && alignedSize < fileSize) {
    LONGLONG tail = fileSize - alignedSize;
    BYTE buf[4096];
    LARGE_INTEGER lip;
    lip.QuadPart = alignedSize;
    SetFilePointerEx(hSrc, lip, NULL, FILE_BEGIN);
    SetFilePointerEx(hDst, lip, NULL, FILE_BEGIN);
    DWORD rd, wr;
    LONGLONG remain = tail;
    while (remain > 0 && ReadFile(hSrc, buf, (DWORD)min(remain, (LONGLONG)sizeof(buf)), &rd, NULL) && rd > 0) {
      if (!WriteFile(hDst, buf, rd, &wr, NULL) || wr != rd) {
        ok = FALSE;
        break;
      }
      remain -= rd;
    }
  }
  CloseHandle(hSrc);
  if (ok) {
    CloseHandle(hDst);
    if (task) CopyFileSecurityAndAttributes(src, dst, task);
    return TRUE;
  }
  CloseHandle(hDst);
  DeleteFileW(dst);
  return FALSE;
}

/* 获取卷句柄 \\\\.\\X:，需管理员权限 */
static HANDLE OpenVolumeHandle(wchar_t driveLetter) {
  wchar_t volPath[8];
  StringCchPrintfW(volPath, 8, L"\\\\.\\%c:", driveLetter >= L'a' && driveLetter <= L'z'
      ? (wchar_t)(driveLetter - 32) : (driveLetter >= L'A' && driveLetter <= L'Z' ? driveLetter : L'C'));
  return CreateFileW(volPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
}

/* Raw $MFT：打开卷用于裸盘读，FILE_SHARE_WRITE 避免与 OS 冲突。暂用缓冲 I/O 避免扇区对齐复杂度 */
static HANDLE OpenVolumeForRawMft(wchar_t driveLetter) {
  wchar_t volPath[8];
  wchar_t ch = (driveLetter >= L'a' && driveLetter <= L'z') ? (wchar_t)(driveLetter - 32) :
      (driveLetter >= L'A' && driveLetter <= L'Z' ? driveLetter : L'C');
  StringCchPrintfW(volPath, 8, L"\\\\.\\%c:", ch);
  return CreateFileW(volPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
}

/* 打开 $MFT 文件句柄，用于 FSCTL_GET_RETRIEVAL_POINTERS 获取碎片区间 */
static HANDLE OpenMftFile(wchar_t driveLetter) {
  wchar_t path[16];
  wchar_t ch = (driveLetter >= L'a' && driveLetter <= L'z') ? (wchar_t)(driveLetter - 32) :
      (driveLetter >= L'A' && driveLetter <= L'Z' ? driveLetter : L'C');
  StringCchPrintfW(path, 16, L"\\\\.\\%c:\\$MFT", ch);
  return CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
}

/* Arena Allocator：线性内存池，千万级小对象 O(1) 分配，任务结束 VirtualFree 整块释放，根除碎片
 * 注意：当前仅用于 MFT 扫描（MftFrnNode/path），非 Direct I/O 缓冲。若将来从 Arena 切分
 * NO_BUFFERING 缓冲，需 (ptr+4095)&~4095 掩码保证 4KB 对齐，避免 Direct I/O 回退 Buffered I/O */
#define ARENA_BLOCK_SIZE   (256ULL * 1024 * 1024)  /* 256MB */
#define ARENA_ALIGN        8
typedef struct {
  BYTE *base;
  size_t capacity;
  size_t used;
} Arena;

static Arena *ArenaCreate(void) {
  Arena *a = (Arena *)malloc(sizeof(Arena));
  if (!a) return NULL;
  a->base = (BYTE *)AllocBufferWithLargePagesFallback(ARENA_BLOCK_SIZE);
  if (!a->base) { free(a); return NULL; }
  a->capacity = ARENA_BLOCK_SIZE;
  a->used = 0;
  return a;
}

static void *ArenaAlloc(Arena *a, size_t size) {
  size = (size + ARENA_ALIGN - 1) & ~(ARENA_ALIGN - 1);
  if (a->used + size > a->capacity) return NULL;
  void *p = a->base + a->used;
  a->used += size;
  return p;
}

static void ArenaDestroy(Arena *a) {
  if (a && a->base) {
    VirtualFree(a->base, 0, MEM_RELEASE);
    a->base = NULL;
  }
  free(a);
}

/* FRN 节点：用于构建路径拓扑 */
#define CHECKPOINT_MAGIC    0x43504643  /* "CFPC" */
#define CHECKPOINT_VERSION 1
#define CHECKPOINT_FILENAME L"pb_xflow_resume.dat"

static HANDLE g_hCheckpointEvent = NULL;
static HANDLE g_hCheckpointStopEvent = NULL;
static HANDLE g_hCheckpointThread = NULL;
static BYTE g_CheckpointBuf[64];
static volatile LONG g_CheckpointPending = 0;

/* 后台线程：无锁双缓冲，主循环仅复制+信号，磁盘 I/O 不阻塞流水线 */
static unsigned __stdcall CheckpointWriterThread(void *arg) {
  (void)arg;
  HANDLE h[2] = { g_hCheckpointStopEvent, g_hCheckpointEvent };
  for (;;) {
    DWORD r = WaitForMultipleObjects(2, h, FALSE, 1000);
    if (r == WAIT_OBJECT_0) break;  /* Stop */
    if (r == WAIT_OBJECT_0 + 1 || r == WAIT_TIMEOUT) {
      if (InterlockedCompareExchange(&g_CheckpointPending, 0, 1) != 1) continue;
      wchar_t path[MAX_PATH];
      StringCchPrintfW(path, MAX_PATH, L"%ls\\%ls", g_Config.LogPath, CHECKPOINT_FILENAME);
      HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
          FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
      if (f != INVALID_HANDLE_VALUE) {
        DWORD wr;
        WriteFile(f, g_CheckpointBuf, sizeof(g_CheckpointBuf), &wr, NULL);
        CloseHandle(f);
      }
    }
  }
  return 0;
}

/* 同步写入（兼容旧路径，或线程未创建时） */
static void WriteCheckpointSync(void) {
  wchar_t path[MAX_PATH];
  StringCchPrintfW(path, MAX_PATH, L"%ls\\%ls", g_Config.LogPath, CHECKPOINT_FILENAME);
  HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
  if (h == INVALID_HANDLE_VALUE) return;
  BYTE buf[64];
  DWORD *p = (DWORD *)buf;
  p[0] = CHECKPOINT_MAGIC;
  p[1] = CHECKPOINT_VERSION;
  LONGLONG *lp = (LONGLONG *)(buf + 8);
  lp[0] = READ_VOLATILE_64(&g_TotalFoundBytes);
  lp[1] = g_NumThreadBuckets > 0 ? SumBucketBytes() : READ_VOLATILE_64(&g_TotalBytes);
  lp[2] = (LONGLONG)READ_VOLATILE_32(&g_TotalFound);
  lp[3] = (LONGLONG)time(NULL);
  DWORD written;
  WriteFile(h, buf, sizeof(buf), &written, NULL);
  CloseHandle(h);
}

#define MFT_FRN_HASH_SIZE  (1 << 20)  /* 1048576 桶 */
#define MFT_ROOT_FRN       5ULL
typedef struct MftFrnNode {
  DWORDLONG frn;
  DWORDLONG parentFrn;
  wchar_t *fileName;
  DWORD fileAttributes;
  LONGLONG fileSize;
  FILETIME creationTime, lastAccessTime, lastWriteTime;
  wchar_t *resolvedPath;   /* 缓存完整路径，递归解析时填充 */
  struct MftFrnNode *next; /* 链式哈希 */
} MftFrnNode;

static MftFrnNode *MftFindNode(MftFrnNode **hashTable, DWORDLONG frn) {
  for (MftFrnNode *n = hashTable[frn % MFT_FRN_HASH_SIZE]; n; n = n->next)
    if (n->frn == frn) return n;
  return NULL;
}

/* 递归解析节点完整路径，结果缓存于 node->resolvedPath，Arena 分配零碎片 */
static wchar_t *MftResolvePath(MftFrnNode **hashTable, MftFrnNode *node,
    const wchar_t *rootPath, Arena *arena) {
  if (node->resolvedPath) return node->resolvedPath;
  if (node->parentFrn == 0 || node->parentFrn == MFT_ROOT_FRN) {
    size_t len = wcslen(rootPath) + wcslen(node->fileName) + 2;
    node->resolvedPath = (wchar_t *)ArenaAlloc(arena, len * sizeof(wchar_t));
    if (node->resolvedPath)
      StringCchPrintfW(node->resolvedPath, len, L"%ls%ls", rootPath, node->fileName);
    return node->resolvedPath;
  }
  MftFrnNode *parent = MftFindNode(hashTable, node->parentFrn);
  if (!parent || !MftResolvePath(hashTable, parent, rootPath, arena) || !parent->resolvedPath)
    return NULL;
  size_t len = wcslen(parent->resolvedPath) + 1 + wcslen(node->fileName) + 1;
  node->resolvedPath = (wchar_t *)ArenaAlloc(arena, len * sizeof(wchar_t));
  if (node->resolvedPath)
    StringCchPrintfW(node->resolvedPath, len, L"%ls\\%ls", parent->resolvedPath, node->fileName);
  return node->resolvedPath;
}

/* USN/MFT 拼出的路径可能含 8.3 短名，与源前缀 wcsncmp 失败时，用 GetLongPathNameW 还原长名；
 * 匹配成功则把 node->resolvedPath 指到 Arena 中新串（供 CopyTask 使用长名）。路径须真实存在。 */
static BOOL MftMatchSourcePrefixOrLongPath(MftFrnNode *cur, Arena *arena,
    const wchar_t *srcForCmp, size_t srcPrefixLen) {
  const wchar_t *curPath = cur->resolvedPath;
  if (!curPath)
    return FALSE;
  const wchar_t *curPathForCmp = (wcsncmp(curPath, L"\\\\?\\", 4) == 0) ? curPath + 4 : curPath;
  if (wcsncmp(curPathForCmp, srcForCmp, srcPrefixLen) == 0) {
    if (srcPrefixLen > 0 && curPathForCmp[srcPrefixLen] != L'\0' && curPathForCmp[srcPrefixLen] != L'\\')
      return FALSE;
    return TRUE;
  }
  /* advice1 P0: 仅路径含 '~'（8.3 短名特征）时才 GetLongPathNameW，避免全盘无关节点灾难 */
  if (!wcschr(curPath, L'~'))
    return FALSE;
  wchar_t longBuf[MAX_PATH_EXT];
  DWORD n = GetLongPathNameW(curPath, longBuf, MAX_PATH_EXT);
  if (n == 0 || n >= MAX_PATH_EXT)
    return FALSE;
  const wchar_t *longCmp = (wcsncmp(longBuf, L"\\\\?\\", 4) == 0) ? longBuf + 4 : longBuf;
  if (wcsncmp(longCmp, srcForCmp, srcPrefixLen) != 0)
    return FALSE;
  if (srcPrefixLen > 0 && longCmp[srcPrefixLen] != L'\0' && longCmp[srcPrefixLen] != L'\\')
    return FALSE;
  size_t newLen = wcslen(longBuf);
  wchar_t *newPath = (wchar_t *)ArenaAlloc(arena, (newLen + 1) * sizeof(wchar_t));
  if (!newPath)
    return FALSE;
  StringCchCopyW(newPath, newLen + 1, longBuf);
  cur->resolvedPath = newPath;
  return TRUE;
}

/* Raw $MFT 裸盘直读：advice1 P0 流式 64MB 窗口读取 + 修复 >4GB DWORD 截断 */
static BOOL MftReadFully64(HANDLE h, BYTE *dst, LONGLONG bytes) {
  LONGLONG done = 0;
  while (done < bytes) {
    DWORD chunk = (DWORD)((bytes - done) > (64LL * 1024 * 1024) ? (64LL * 1024 * 1024) : (bytes - done));
    DWORD rd = 0;
    if (!ReadFile(h, dst + done, chunk, &rd, NULL) || rd == 0)
      return FALSE;
    done += rd;
  }
  return TRUE;
}

static void MftParseOneRecord(BYTE *recBytes, DWORD recordSize, LONGLONG recIndex,
    Arena *arena, MftFrnNode **hashTable) {
  MFT_RECORD_HEADER *rec = (MFT_RECORD_HEADER *)recBytes;
  if (rec->Magic != MFT_MAGIC_FILE || !(rec->Flags & MFT_FLAG_IN_USE))
    return;
  if (rec->UsaOffset > 0 && rec->UsaCount > 1 &&
      (DWORD)(rec->UsaOffset + rec->UsaCount * 2) <= recordSize) {
    uint16_t *usa = (uint16_t *)((char *)rec + rec->UsaOffset);
    uint16_t seqNum = usa[0];
    DWORD numSectors = recordSize / 512;
    BOOL fixupOk = TRUE;
    for (DWORD s = 1; s <= numSectors && s < (DWORD)rec->UsaCount; s++) {
      uint16_t *sectorEnd = (uint16_t *)((char *)rec + s * 512 - 2);
      if (*sectorEnd != seqNum) { fixupOk = FALSE; break; }
      *sectorEnd = usa[s];
    }
    if (!fixupOk) return;
  }
  char *attrPtr = (char *)rec + rec->AttrOffset;
  MftFrnNode *bestNode = NULL;
  uint8_t bestNamespace = 0xFF;
  LONGLONG dataSizeFromMft = -1;
  DWORDLONG baseFrn = (rec->BaseFileRecord != 0)
      ? (rec->BaseFileRecord & 0x0000FFFFFFFFFFFFULL)
      : (DWORDLONG)recIndex;
  while (1) {
    MFT_ATTR_HEADER *attr = (MFT_ATTR_HEADER *)attrPtr;
    if (attr->TypeCode == MFT_ATTR_END || attr->RecordLength == 0)
      break;
    if (attr->TypeCode == MFT_ATTR_DATA && attr->NameLength == 0) {
      if (attr->NonResident == 0) {
        uint32_t valueLen = *(uint32_t *)(attrPtr + 0x10);
        dataSizeFromMft = (LONGLONG)valueLen;
      } else {
        LONGLONG startingVcn = *(LONGLONG *)(attrPtr + 0x10);
        if (startingVcn == 0)
          dataSizeFromMft = *(LONGLONG *)(attrPtr + 0x30);
      }
    }
    if (attr->TypeCode == MFT_ATTR_FILE_NAME && attr->NonResident == 0) {
      uint16_t valueOffset = *(uint16_t *)(attrPtr + 20);
      char *val = attrPtr + valueOffset;
      uint8_t nameSpace = (uint8_t)val[0x41];
      DWORDLONG parentFrn = *(DWORDLONG *)val & 0x0000FFFFFFFFFFFFULL;
      uint8_t nameLen = (uint8_t)val[0x40];
      if (nameLen > 0 && nameLen < 256) {
        wchar_t *name = (wchar_t *)(val + 0x42);
        if (!(nameLen >= 1 && name[0] == L'.' && (nameLen == 1 || (nameLen == 2 && name[1] == L'.')))) {
          if (bestNode && nameSpace == 3 && bestNamespace != 3) {
            wchar_t *newName = (wchar_t *)ArenaAlloc(arena, (nameLen + 1) * sizeof(wchar_t));
            if (newName) {
              StringCchCopyNW(newName, nameLen + 1, name, nameLen);
              newName[nameLen] = L'\0';
              bestNode->fileName = newName;
              bestNamespace = 3;
            }
          } else if (!bestNode && (nameSpace == 3 || bestNamespace == 0xFF)) {
            MftFrnNode *n = (MftFrnNode *)ArenaAlloc(arena, sizeof(MftFrnNode));
            if (n) {
              n->frn = baseFrn;
              n->parentFrn = parentFrn;
              n->fileName = (wchar_t *)ArenaAlloc(arena, (nameLen + 1) * sizeof(wchar_t));
              if (n->fileName) {
                StringCchCopyNW(n->fileName, nameLen + 1, name, nameLen);
                n->fileName[nameLen] = L'\0';
                n->fileAttributes = *(DWORD *)(val + 0x38);
                n->fileSize = dataSizeFromMft;
                n->creationTime.dwLowDateTime = *(DWORD *)(val + 0x08);
                n->creationTime.dwHighDateTime = *(DWORD *)(val + 0x0C);
                n->lastAccessTime.dwLowDateTime = *(DWORD *)(val + 0x10);
                n->lastAccessTime.dwHighDateTime = *(DWORD *)(val + 0x14);
                n->lastWriteTime.dwLowDateTime = *(DWORD *)(val + 0x18);
                n->lastWriteTime.dwHighDateTime = *(DWORD *)(val + 0x1C);
                n->resolvedPath = NULL;
                n->next = hashTable[n->frn % MFT_FRN_HASH_SIZE];
                hashTable[n->frn % MFT_FRN_HASH_SIZE] = n;
                bestNode = n;
                bestNamespace = nameSpace;
              }
            }
          }
        }
      }
    }
    attrPtr += attr->RecordLength;
  }
  if (bestNode && dataSizeFromMft >= 0)
    bestNode->fileSize = dataSizeFromMft;
}

static int MftRawScanAndPostTasks(HANDLE hIocp, const wchar_t *srcPath, const wchar_t *dstPath,
    BOOL auditExtraEnumeration) {
  wchar_t driveLetter = 0;
  if (srcPath[0] && srcPath[1] == L':')
    driveLetter = srcPath[0];
  else if (wcsncmp(srcPath, L"\\\\?\\", 4) == 0 && srcPath[4] && srcPath[5] == L':')
    driveLetter = srcPath[4];
  if (!driveLetter || !((driveLetter >= L'a' && driveLetter <= L'z') || (driveLetter >= L'A' && driveLetter <= L'Z')))
    return -1;
  HANDLE hVol = OpenVolumeForRawMft(driveLetter);
  if (hVol == INVALID_HANDLE_VALUE)
    return -1;
  MFT_NTFS_VOLUME_DATA vData = {0};
  DWORD bytesRet = 0;
  if (!DeviceIoControl(hVol, FSCTL_GET_NTFS_VOLUME_DATA, NULL, 0, &vData, sizeof(vData), &bytesRet, NULL)) {
    CloseHandle(hVol);
    return -1;
  }
  DWORD recordSize = vData.BytesPerFileRecordSegment;
  DWORD clusterSize = vData.BytesPerCluster;
  LONGLONG mftSize = vData.MftValidDataLength.QuadPart;
  if (recordSize == 0 || clusterSize == 0 || mftSize <= 0) {
    CloseHandle(hVol);
    return -1;
  }

  HANDLE hMft = OpenMftFile(driveLetter);
  const LONGLONG WIN = 64LL * 1024 * 1024;
  BYTE *window = (BYTE *)VirtualAlloc(NULL, (SIZE_T)(WIN + (LONGLONG)recordSize), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  if (!window) {
    if (hMft != INVALID_HANDLE_VALUE) CloseHandle(hMft);
    CloseHandle(hVol);
    return -1;
  }
  Arena *arena = ArenaCreate();
  if (!arena) {
    VirtualFree(window, 0, MEM_RELEASE);
    if (hMft != INVALID_HANDLE_VALUE) CloseHandle(hMft);
    CloseHandle(hVol);
    return -1;
  }
  MftFrnNode **hashTable = (MftFrnNode **)calloc(MFT_FRN_HASH_SIZE, sizeof(MftFrnNode *));
  if (!hashTable) {
    ArenaDestroy(arena);
    VirtualFree(window, 0, MEM_RELEASE);
    if (hMft != INVALID_HANDLE_VALUE) CloseHandle(hMft);
    CloseHandle(hVol);
    return -1;
  }

  BOOL useMftFile = (hMft != INVALID_HANDLE_VALUE);
  LONGLONG mftOffset = (LONGLONG)vData.MftStartLcn.QuadPart * clusterSize;
  LONGLONG fileOff = 0;
  LONGLONG carry = 0;
  LONGLONG globalRec = 0;
  BOOL readOk = TRUE;

  while (fileOff < mftSize && !IsCanceling() && readOk) {
    LONGLONG room = WIN - carry;
    LONGLONG want = mftSize - fileOff;
    if (want > room) want = room;
    if (want <= 0) break;

    BYTE *readDst = window + carry;
    if (useMftFile) {
      LARGE_INTEGER seek;
      seek.QuadPart = fileOff;
      if (!SetFilePointerEx(hMft, seek, NULL, FILE_BEGIN) || !MftReadFully64(hMft, readDst, want))
        useMftFile = FALSE;
    }
    if (!useMftFile) {
      LARGE_INTEGER seek;
      seek.QuadPart = mftOffset + fileOff;
      if (!SetFilePointerEx(hVol, seek, NULL, FILE_BEGIN) || !MftReadFully64(hVol, readDst, want)) {
        readOk = FALSE;
        break;
      }
    }

    LONGLONG avail = carry + want;
    LONGLONG complete = (avail / recordSize) * recordSize;
    LONGLONG recCount = complete / recordSize;
    for (LONGLONG r = 0; r < recCount && !IsCanceling(); r++)
      MftParseOneRecord(window + r * recordSize, recordSize, globalRec + r, arena, hashTable);

    globalRec += recCount;
    carry = avail - complete;
    if (carry > 0)
      memmove(window, window + complete, (size_t)carry);
    fileOff += want;
  }

  if (hMft != INVALID_HANDLE_VALUE) CloseHandle(hMft);
  CloseHandle(hVol);
  VirtualFree(window, 0, MEM_RELEASE);

  if (!readOk && globalRec == 0) {
    ArenaDestroy(arena);
    free(hashTable);
    return -1;
  }

  wchar_t rootPath[16];
  StringCchPrintfW(rootPath, 16,  L"\\\\?\\%c:\\", (driveLetter >= L'a' && driveLetter <= L'z') ? (wchar_t)(driveLetter - 32) : driveLetter);
  const wchar_t *srcForCmp = (wcsncmp(srcPath, L"\\\\?\\", 4) == 0) ? srcPath + 4 : srcPath;
  size_t srcPrefixLen = wcslen(srcForCmp);
  if (srcPrefixLen > 0 && srcForCmp[srcPrefixLen - 1] == L'\\')
    srcPrefixLen--;
  int posted = 0;
  DWORD scanCount = 0;
  DWORD lastTick = GetTickCount();

  for (size_t hi = 0; hi < MFT_FRN_HASH_SIZE && !IsCanceling(); hi++) {
    for (MftFrnNode *cur = hashTable[hi]; cur; cur = cur->next) {
      if (IsCanceling()) break;
      scanCount++;
      if (scanCount % 5000 == 0 || (GetTickCount() - lastTick > 500)) {
         Sleep(1);
         lastTick = GetTickCount();
         PrintStats(0);
      }
      if (!MftResolvePath(hashTable, cur, rootPath, arena) || !cur->resolvedPath)
        continue;
      if (!MftMatchSourcePrefixOrLongPath(cur, arena, srcForCmp, srcPrefixLen))
        continue;
      const wchar_t *curPath = cur->resolvedPath;
      const wchar_t *curPathForCmp = (wcsncmp(curPath, L"\\\\?\\", 4) == 0) ? curPath + 4 : curPath;
      wchar_t workDst[MAX_PATH_EXT];
      const wchar_t *rel = curPathForCmp + (srcPrefixLen > 0 && curPathForCmp[srcPrefixLen] == L'\\' ? srcPrefixLen + 1 : srcPrefixLen);
      if (rel[0])
        StringCchPrintfW(workDst, MAX_PATH_EXT, L"%ls\\%ls", dstPath, rel);
      else
        StringCchCopyW(workDst, MAX_PATH_EXT, dstPath);
      if (cur->fileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        if (!g_Config.AuditOnly)
          EnsureParentDirExists(workDst);
        if (g_Config.IsMoveMode && g_IsSameVolume &&
            MoveFileExW(curPath, workDst, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
          posted++;
          continue;
        }
        if (g_Config.IsMoveMode && !g_IsSameVolume)
          AddMoveSourceDir(curPath);
        if (!g_Config.AuditOnly &&
            !CreateDirectoryW(workDst, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
          LogMessage(LOG_WARNING, L"[MFT Raw] CreateDirectory failed: %ls\n", workDst);
        if (!g_Config.AuditOnly && !g_Config.FastMode && g_DirMetaStack) {
          WIN32_FILE_ATTRIBUTE_DATA fad;
          if (GetFileAttributesExW(curPath, GetFileExInfoStandard, &fad)) {
            DirMetaTask *dmt = AllocDirMetaTask();
            if (dmt) {
              size_t curLen = wcslen(curPath);
              size_t workDstLen = wcslen(workDst);
              dmt->SrcPath = StrDupWithLen(NULL, g_StringArena, curPath, curLen);
              dmt->SrcLen = (uint32_t)curLen;
              dmt->DstPath = dmt->SrcPath ? StrDupWithLen(NULL, g_StringArena, workDst, workDstLen) : NULL;
              dmt->DstLen = (uint32_t)workDstLen;
              dmt->pathFlags = TASK_PATH_FLAG_SRC_ARENA | TASK_PATH_FLAG_DST_ARENA;
              if (dmt->SrcPath && dmt->DstPath) {
                dmt->CreationTime = fad.ftCreationTime;
                dmt->LastAccessTime = fad.ftLastAccessTime;
                dmt->LastWriteTime = fad.ftLastWriteTime;
                dmt->FileAttributes = fad.dwFileAttributes;
                InterlockedPushEntrySList(g_DirMetaStack, &dmt->ItemEntry);
              } else
                FreeDirMetaTask(dmt);
            }
          }
        }
        posted++;
      } else {
        if (PassesDateSizeFilter(cur->fileSize, &cur->lastWriteTime)) {
          CopyTask *ct = AllocCopyTask();
          if (ct) {
            size_t curLen = wcslen(curPath);
            size_t workDstLen = wcslen(workDst);
            ct->SrcLen = (uint32_t)curLen;
            ct->DstLen = (uint32_t)workDstLen;
            if (curLen < MAX_PATH && workDstLen < MAX_PATH) {
              StringCchCopyW(ct->ShortSrc, MAX_PATH, curPath);
              StringCchCopyW(ct->ShortDst, MAX_PATH, workDst);
              ct->SrcPath = ct->ShortSrc;
              ct->DstPath = ct->ShortDst;
              ct->pathFlags = TASK_PATH_FLAG_SRC_SHORT | TASK_PATH_FLAG_DST_SHORT;
            } else {
              ct->SrcPath = StrDupTransient(curPath, curLen);
              ct->DstPath = ct->SrcPath ? StrDupTransient(workDst, workDstLen) : NULL;
              ct->pathFlags = 0;
            }
            if (ct->SrcPath && ct->DstPath) {
              ct->FileSize = cur->fileSize;
              ct->CreationTime = cur->creationTime;
              ct->LastAccessTime = cur->lastAccessTime;
              ct->LastWriteTime = cur->lastWriteTime;
              ct->FileAttributes = cur->fileAttributes;
              ct->pSrcBackend = VFS_GetBackend(srcPath);
              ct->pDstBackend = VFS_GetBackend(dstPath);
              PostCopyTaskWithOverflow(NULL, ct, hIocp);
              if (!auditExtraEnumeration) {
                if (cur->fileSize >= 0)
                  InterlockedAdd64(&g_TotalFoundBytes, cur->fileSize);
                InterlockedIncrement(&g_TotalFound);
              }
              posted++;
            } else
              FreeCopyTask(ct);
          }
        }
      }
    }
  }
  ArenaDestroy(arena);
  free(hashTable);
  return posted;
}

/* MFT 扫描：枚举 USN 记录，构建 FRN 树，按 SrcPath 过滤并投递任务。成功返回投递数，失败返回 -1 回退传统扫描 */
static int MftScanAndPostTasks(HANDLE hIocp, const wchar_t *srcPath, const wchar_t *dstPath,
    BOOL auditExtraEnumeration) {
  wchar_t driveLetter = 0;
  if (srcPath[0] && srcPath[1] == L':')
    driveLetter = srcPath[0];
  else if (wcsncmp(srcPath, L"\\\\?\\", 4) == 0 && srcPath[4] && srcPath[5] == L':')
    driveLetter = srcPath[4];
  if (!driveLetter || !((driveLetter >= L'a' && driveLetter <= L'z') || (driveLetter >= L'A' && driveLetter <= L'Z')))
    return -1;
  HANDLE hVol = OpenVolumeHandle(driveLetter);
  if (hVol == INVALID_HANDLE_VALUE)
    return -1;
  Arena *arena = ArenaCreate();
  if (!arena) {
    CloseHandle(hVol);
    return -1;
  }
  DWORD bufSize = 1024 * 1024;  /* 1MB 输出缓冲 */
  BYTE *outBuf = (BYTE *)malloc(bufSize);
  if (!outBuf) {
    ArenaDestroy(arena);
    CloseHandle(hVol);
    return -1;
  }
  MftFrnNode **hashTable = (MftFrnNode **)calloc(MFT_FRN_HASH_SIZE, sizeof(MftFrnNode *));
  if (!hashTable) {
    free(outBuf);
    ArenaDestroy(arena);
    CloseHandle(hVol);
    return -1;
  }
  int posted = 0;
  DWORDLONG nextFrn = 0;
  wchar_t rootPath[16];
  StringCchPrintfW(rootPath, 16,  L"\\\\?\\%c:\\", driveLetter >= L'a' && driveLetter <= L'z' ? (wchar_t)(driveLetter - 32) : driveLetter);
// 统一提取去除了 \\?\ 的纯净源路径进行比较
  const wchar_t *srcForCmp = (wcsncmp(srcPath, L"\\\\?\\", 4) == 0) ? srcPath + 4 : srcPath;
  size_t srcPrefixLen = wcslen(srcForCmp);
  if (srcPrefixLen > 0 && srcForCmp[srcPrefixLen - 1] == L'\\')
    srcPrefixLen--;
  for (;;) {
	// 旦取消立即打断底层 USN 枚举
    if (IsCanceling()) break;

    MFT_ENUM_DATA_V0 inData = {0};
    inData.StartFileReferenceNumber = nextFrn;
    inData.LowUsn = 0;
    inData.HighUsn = (USN)0x7FFFFFFFFFFFFFFFLL;
    DWORD returned = 0;
    if (!DeviceIoControl(hVol, FSCTL_ENUM_USN_DATA, &inData, sizeof(inData),
        outBuf, bufSize, &returned, NULL)) {
      DWORD err = GetLastError();
      if (err == ERROR_HANDLE_EOF)
        break;  /* 遍历完美结束 */
      if (err == ERROR_MORE_DATA && bufSize < 32 * 1024 * 1024) {
        bufSize *= 2;
        BYTE *nb = (BYTE *)realloc(outBuf, bufSize);
        if (!nb) break;
        outBuf = nb;
        continue;
      }
      break;
    }
    if (returned < 8) break;
    /* 变长记录块：首 8 字节为下一次 StartFileReferenceNumber，非第一条记录 */
    nextFrn = *(DWORDLONG *)outBuf;
    BYTE *p = outBuf + 8;
    BYTE *end = outBuf + returned;
    while ((BYTE *)p < end) {
      PUSN_RECORD_V2 rec = (PUSN_RECORD_V2)p;
      if (rec->RecordLength == 0 || p + rec->RecordLength > end)
        break;
      USHORT major = rec->MajorVersion;
      DWORDLONG frn = 0, parentFrn = 0;
      DWORD nameBytes = 0;
      int nameLen = 0;
      PWCHAR pName = NULL;
      DWORD fileAttr = 0;
      DWORD tsLo = 0, tsHi = 0;
      WORD fnOff = 0;
      DWORD recLen = rec->RecordLength;

      if (major == 2) {
        frn = rec->FileReferenceNumber & 0x0000FFFFFFFFFFFFULL;
        parentFrn = rec->ParentFileReferenceNumber & 0x0000FFFFFFFFFFFFULL;
        nameBytes = rec->FileNameLength;
        nameLen = nameBytes / (int)sizeof(wchar_t);
        fileAttr = rec->FileAttributes;
        tsLo = rec->TimeStamp.LowPart;
        tsHi = rec->TimeStamp.HighPart;
        fnOff = rec->FileNameOffset;
        pName = (PWCHAR)((PUCHAR)rec + fnOff);
      } else if (major == 3) {
        XFLOW_USN_RECORD_V3 *v3 = (XFLOW_USN_RECORD_V3 *)(void *)p;
        nameBytes = v3->FileNameLength;
        nameLen = nameBytes / (int)sizeof(wchar_t);
        frn = *(DWORDLONG *)&v3->FileReferenceNumber[0];
        parentFrn = *(DWORDLONG *)&v3->ParentFileReferenceNumber[0];
        frn &= 0x0000FFFFFFFFFFFFULL;
        parentFrn &= 0x0000FFFFFFFFFFFFULL;
        fileAttr = v3->FileAttributes;
        tsLo = v3->TimeStamp.LowPart;
        tsHi = v3->TimeStamp.HighPart;
        fnOff = v3->FileNameOffset;
        pName = (PWCHAR)((PUCHAR)v3 + fnOff);
      } else {
        p = (BYTE *)p + rec->RecordLength;
        continue;
      }
      /* FileNameLength 为字节数；V2/V3 均用 RecordLength 滑动 */
      if (nameLen > 0 && nameLen < 32768 && fnOff > 0 &&
          (DWORD)fnOff + nameBytes <= recLen && p + recLen <= end) {
        if (nameLen >= 1 && (pName[0] == L'.' && (nameLen == 1 || (nameLen == 2 && pName[1] == L'.')))) {
          p = (BYTE *)p + rec->RecordLength;
          continue;
        }
        MftFrnNode *n = (MftFrnNode *)ArenaAlloc(arena, sizeof(MftFrnNode));
        if (n) {
          n->frn = frn;
          n->parentFrn = parentFrn;
          n->fileName = (wchar_t *)ArenaAlloc(arena, (nameLen + 1) * sizeof(wchar_t));
          if (n->fileName) {
            StringCchCopyNW(n->fileName, nameLen + 1, pName, nameLen);
            n->fileName[nameLen] = L'\0';
          } else {
            p = (BYTE *)p + rec->RecordLength;
            continue;
          }
          n->fileAttributes = fileAttr;
          n->fileSize = 0;
          n->creationTime.dwLowDateTime = tsLo;
          n->creationTime.dwHighDateTime = tsHi;
          n->lastAccessTime = n->lastWriteTime = n->creationTime;
          n->resolvedPath = NULL;
          n->next = hashTable[frn % MFT_FRN_HASH_SIZE];
          hashTable[frn % MFT_FRN_HASH_SIZE] = n;
        }
      }
      /* 变长结构体：按 RecordLength 滑动到下一条记录 */
      p = (BYTE *)p + rec->RecordLength;
    }
    if (nextFrn == 0) break;
  }
  /* 构建路径并投递：遍历所有节点，递归解析路径，过滤 SrcPath 前缀 */
  //定义局部计数器和时间戳
  DWORD scanCount = 0;
  DWORD lastTick = GetTickCount();

  for (size_t i = 0; i < MFT_FRN_HASH_SIZE && !IsCanceling(); i++) {
    for (MftFrnNode *cur = hashTable[i]; cur; cur = cur->next) {
      //立即打断百万级链表遍历
      if (IsCanceling()) break;

      // 每处理 5000 个文件，或者距离上次超过 500 毫秒，就强行休眠 1ms，给日志线程刷新屏幕的机会
      scanCount++;
      if (scanCount % 5000 == 0 || (GetTickCount() - lastTick > 500)) {
         Sleep(1); 
         lastTick = GetTickCount();
		 //让主线程在投递 88 万个任务的这 2 分钟里，也能实时刷新日志！
		 PrintStats(0); 
      }

      if (!MftResolvePath(hashTable, cur, rootPath, arena) || !cur->resolvedPath)
        continue;
      if (!MftMatchSourcePrefixOrLongPath(cur, arena, srcForCmp, srcPrefixLen))
        continue;
      const wchar_t *curPath = cur->resolvedPath;
      const wchar_t *curPathForCmp = (wcsncmp(curPath, L"\\\\?\\", 4) == 0) ? curPath + 4 : curPath;

      wchar_t workDst[MAX_PATH_EXT];
      // 必须基于 curPathForCmp 计算相对偏移，否则会因长度错位导致截断错误
      const wchar_t *rel = curPathForCmp + (srcPrefixLen > 0 && curPathForCmp[srcPrefixLen] == L'\\' ? srcPrefixLen + 1 : srcPrefixLen);
      if (rel[0])
        StringCchPrintfW(workDst, MAX_PATH_EXT, L"%ls\\%ls", dstPath, rel);
      else
        StringCchCopyW(workDst, MAX_PATH_EXT, dstPath);
      if (cur->fileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        if (!g_Config.AuditOnly)
          EnsureParentDirExists(workDst);
        if (g_Config.IsMoveMode && g_IsSameVolume &&
            MoveFileExW(curPath, workDst, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
          posted++;
          continue;
        }
        if (g_Config.IsMoveMode && !g_IsSameVolume)
          AddMoveSourceDir(curPath);
        if (!g_Config.AuditOnly &&
            !CreateDirectoryW(workDst, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
          LogMessage(LOG_WARNING, L"[MFT] CreateDirectory failed: %ls\n", workDst);
        if (!g_Config.AuditOnly && !g_Config.FastMode && g_DirMetaStack) {
          WIN32_FILE_ATTRIBUTE_DATA fad;
          if (GetFileAttributesExW(curPath, GetFileExInfoStandard, &fad)) {
            DirMetaTask *dmt = AllocDirMetaTask();
            if (dmt) {
              size_t curLen = wcslen(curPath);
              size_t workDstLen = wcslen(workDst);
              dmt->SrcPath = StrDupWithLen(NULL, g_StringArena, curPath, curLen);
              dmt->SrcLen = (uint32_t)curLen;
              dmt->DstPath = dmt->SrcPath ? StrDupWithLen(NULL, g_StringArena, workDst, workDstLen) : NULL;
              dmt->DstLen = (uint32_t)workDstLen;
              dmt->pathFlags = TASK_PATH_FLAG_SRC_ARENA | TASK_PATH_FLAG_DST_ARENA;
              if (dmt->SrcPath && dmt->DstPath) {
                dmt->CreationTime = fad.ftCreationTime;
                dmt->LastAccessTime = fad.ftLastAccessTime;
                dmt->LastWriteTime = fad.ftLastWriteTime;
                dmt->FileAttributes = fad.dwFileAttributes;
                InterlockedPushEntrySList(g_DirMetaStack, &dmt->ItemEntry);
              } else
                FreeDirMetaTask(dmt);
            }
          }
        }
        posted++;
      } else {
        /* advice1 P0: USN 无 FileSize——推迟到 Copier 打开后 GetFileSizeEx，消灭千万次 GetFileAttributesExW */
        cur->fileSize = -1;
        if (PassesDateSizeFilter(cur->fileSize, &cur->lastWriteTime)) {
          CopyTask *ct = AllocCopyTask();
          if (ct) {
            size_t curLen = wcslen(curPath);
            size_t workDstLen = wcslen(workDst);
            ct->SrcLen = (uint32_t)curLen;
            ct->DstLen = (uint32_t)workDstLen;
            if (curLen < MAX_PATH && workDstLen < MAX_PATH) {
              StringCchCopyW(ct->ShortSrc, MAX_PATH, curPath);
              StringCchCopyW(ct->ShortDst, MAX_PATH, workDst);
              ct->SrcPath = ct->ShortSrc;
              ct->DstPath = ct->ShortDst;
              ct->pathFlags = TASK_PATH_FLAG_SRC_SHORT | TASK_PATH_FLAG_DST_SHORT;
            } else {
              ct->SrcPath = StrDupTransient(curPath, curLen);
              ct->DstPath = ct->SrcPath ? StrDupTransient(workDst, workDstLen) : NULL;
              ct->pathFlags = 0;
            }
            if (ct->SrcPath && ct->DstPath) {
              ct->FileSize = -1;
              ct->CreationTime = cur->creationTime;
              ct->LastAccessTime = cur->lastAccessTime;
              ct->LastWriteTime = cur->lastWriteTime;
              ct->FileAttributes = cur->fileAttributes;
              ct->pSrcBackend = VFS_GetBackend(srcPath);
              ct->pDstBackend = VFS_GetBackend(dstPath);
              PostCopyTaskWithOverflow(NULL, ct, hIocp);
              if (!auditExtraEnumeration) {
                InterlockedIncrement(&g_TotalFound);
              }
              posted++;
            } else
              FreeCopyTask(ct);
          }
        }
      }
    }
  }
  /* Arena 释放：整块 VirtualFree，零逐个 free 开销 */
  ArenaDestroy(arena);
  free(hashTable);
  free(outBuf);
  CloseHandle(hVol);
  return posted;
}

/* OPT-01: 用 uint64_t 哈希代替离散字符串指针——100 万文件时内存从 ~200MB 降至 8MB */

/* XXH3_64bits 哈希文件名（大小写无关时先转小写），字节序与平台无关 */
static UINT64 HashNameForMirror(const wchar_t *name, DWORD nameLen) {
  if (g_Config.CaseInsensitive) {
    wchar_t lower[MAX_PATH];
    DWORD len = (nameLen < MAX_PATH - 1) ? nameLen : MAX_PATH - 1;
    StringCchCopyNW(lower, MAX_PATH, name, len);
    lower[len] = L'\0';
    _wcslwr(lower);
    return (UINT64)XXH3_64bits(lower, len * sizeof(wchar_t));
  }
  return (UINT64)XXH3_64bits(name, nameLen * sizeof(wchar_t));
}

static int CompareU64(const void *a, const void *b) {
  UINT64 ua = *(const UINT64 *)a;
  UINT64 ub = *(const UINT64 *)b;
  return (ua > ub) - (ua < ub);
}

/* O(log N) 二分查找哈希数组；调用前必须已 qsort 排序 */
static BOOL IsHashInSource(UINT64 h, const UINT64 *hashes, int count) {
  if (count <= 0)
    return FALSE;
  return bsearch(&h, hashes, (size_t)count, sizeof(UINT64), CompareU64) != NULL;
}

/* 镜像模式：删除目标目录中源端不存在的孤儿文件/目录（哈希版） */
static void DeleteOrphansInDir(const wchar_t *dstPath, const UINT64 *srcHashes,
                               int srcHashCount) {
  if (!dstPath || !srcHashes || srcHashCount < 0)
    return;
  HANDLE hDst = CreateFileW(dstPath, GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
  if (hDst == INVALID_HANDLE_VALUE)
    return;
  size_t bufSize = 64 * 1024;
  BYTE *dBuf = (BYTE *)malloc(bufSize);
  if (!dBuf) {
    CloseHandle(hDst);
    return;
  }
  for (;;) {
    if (!GetFileInformationByHandleEx(hDst, FileIdBothDirectoryInfo, dBuf,
                                     (DWORD)bufSize)) {
      DWORD errD = GetLastError();
      if (errD == ERROR_MORE_DATA) {
        if (bufSize >= 32 * 1024 * 1024) {
          free(dBuf);
          CloseHandle(hDst);
          LogMessage(LOG_WARNING, L"[Mirror] directory listing buffer capped at 32MB: %ls\n", dstPath);
          return;
        }
        size_t newSize = bufSize * 2;
        BYTE *nb = (BYTE *)realloc(dBuf, newSize);
        if (!nb) {
          free(dBuf);
          CloseHandle(hDst);
          return;
        }
        dBuf = nb;
        bufSize = newSize;
        continue;
      }
      if (errD == ERROR_NO_MORE_FILES)
        break;
      break;
    }
    FILE_ID_BOTH_DIR_INFO *dp = (FILE_ID_BOTH_DIR_INFO *)dBuf;
    while (1) {
      DWORD dNameLen = dp->FileNameLength / sizeof(wchar_t);
      wchar_t dName[MAX_PATH];
      if (dNameLen >= MAX_PATH)
        dNameLen = MAX_PATH - 1;
      StringCchCopyNW(dName, MAX_PATH, dp->FileName, dNameLen);
      if (wcscmp(dName, L".") != 0 && wcscmp(dName, L"..") != 0) {
        UINT64 h = HashNameForMirror(dName, dNameLen);
        if (!IsHashInSource(h, srcHashes, srcHashCount)) {
          wchar_t fullPath[MAX_PATH_EXT];
          StringCchPrintfW(fullPath, MAX_PATH_EXT, L"%ls\\%ls", dstPath, dName);
          DeletePathRecursive(fullPath);
        }
      }
      if (dp->NextEntryOffset == 0)
        break;
      dp = (FILE_ID_BOTH_DIR_INFO *)((BYTE *)dp + dp->NextEntryOffset);
    }
  }
  free(dBuf);
  CloseHandle(hDst);
}

static int CompareDirEntryByFileId(const void *a, const void *b) {
  const DirEntryForSort *ea = (const DirEntryForSort *)a;
  const DirEntryForSort *eb = (const DirEntryForSort *)b;
  if (ea->FileId < eb->FileId) return -1;
  if (ea->FileId > eb->FileId) return 1;
  return 0;
}

/* O(n) LSD 基数排序替代 qsort，按 FileId 物理顺序减少 HDD 寻道 */
static void RadixSortDirEntryByFileId(DirEntryForSort *arr, int n) {
  DirEntryForSort *aux = (DirEntryForSort *)malloc((size_t)n * sizeof(DirEntryForSort));
  if (!aux) {
    qsort(arr, (size_t)n, sizeof(DirEntryForSort), CompareDirEntryByFileId);
    return;
  }
  DirEntryForSort *src = arr, *dst = aux;
  for (int pass = 0; pass < 8; pass++) {
    size_t count[256] = {0};
    for (int i = 0; i < n; i++) {
      UINT64 u = (UINT64)(src[i].FileId ^ (UINT64)0x8000000000000000ULL);
      count[(u >> (pass * 8)) & 0xFF]++;
    }
    size_t pos[256];
    pos[0] = 0;
    for (int i = 1; i < 256; i++)
      pos[i] = pos[i - 1] + count[i - 1];
    for (int i = 0; i < n; i++) {
      UINT64 u = (UINT64)(src[i].FileId ^ (UINT64)0x8000000000000000ULL);
      int digit = (int)((u >> (pass * 8)) & 0xFF);
      dst[pos[digit]++] = src[i];
    }
    DirEntryForSort *tmp = src; src = dst; dst = tmp;
  }
  if (src != arr)
    memcpy(arr, src, (size_t)n * sizeof(DirEntryForSort));
  free(aux);
}

/* FindNextFileW：遇单点 ACCESS_DENIED/SHARING_VIOLATION 时记录并继续枚举下一项，避免整目录被截断 */
static BOOL ProcessScanTask_FindNextFileWithRetry(HANDLE hFind, WIN32_FIND_DATAW *fd,
                                                  const wchar_t *scanPathForLog) {
  for (;;) {
    if (FindNextFileW(hFind, fd))
      return TRUE;
    DWORD e2 = GetLastError();
    if (e2 == ERROR_NO_MORE_FILES)
      return FALSE;
    if (e2 == ERROR_ACCESS_DENIED || e2 == ERROR_SHARING_VIOLATION) {
      LogMessage(LOG_WARNING,
                 L"[ProcessScanTask] FindNextFile: access denied/sharing, continuing: %ls err=%lu\n",
                 scanPathForLog, (unsigned long)e2);
      continue;
    }
    LogMessage(LOG_WARNING, L"[ProcessScanTask] FindNextFile failed: %ls err=%lu\n", scanPathForLog,
               (unsigned long)e2);
    return FALSE;
  }
}

/* GetFileInformationByHandleEx 在部分卷/权限下失败时，用 FindFirst/FindNext 回退（无 -O 物理排序收集） */
static void ProcessScanTask_EnumerateFindFirstFallback(
    ScanTask *scanTask, CopierParam *threadParam, size_t parentSrcLen, size_t parentDstLen,
    const wchar_t *parentDstBase, BOOL srcNeedsNorm, BOOL dstNeedsNorm, wchar_t *workSrc,
    wchar_t *workDst, wchar_t *tempNorm) {
#ifndef FIND_FIRST_EX_LARGE_FETCH
#define FIND_FIRST_EX_LARGE_FETCH 0x00000001
#endif
  wchar_t pattern[MAX_PATH_EXT];
  if (FAILED(StringCchPrintfW(pattern, MAX_PATH_EXT, L"%ls\\*", scanTask->SrcPath)))
    return;
  WIN32_FIND_DATAW fd;
  DWORD findFlags = FIND_FIRST_EX_LARGE_FETCH;
  HANDLE hFind =
      FindFirstFileExW(pattern, FindExInfoBasic, &fd, FindExSearchNameMatch, NULL, findFlags);
  if (hFind == INVALID_HANDLE_VALUE && findFlags != 0)
    hFind = FindFirstFileW(pattern, &fd);
  if (hFind == INVALID_HANDLE_VALUE) {
    DWORD e2 = GetLastError();
    LogMessage(LOG_WARNING, L"[ProcessScanTask] FindFirst fallback failed: %ls err=%lu\n",
               scanTask->SrcPath, (unsigned long)e2);
    return;
  }
  do {
    if (IsCanceling()) {
      FindClose(hFind);
      return;
    }
    DWORD nameLen = (DWORD)wcslen(fd.cFileName);
    wchar_t tempName[MAX_PATH];
    if (nameLen >= MAX_PATH)
      nameLen = MAX_PATH - 1;
    StringCchCopyNW(tempName, MAX_PATH, fd.cFileName, nameLen);
    if (wcscmp(tempName, L".") != 0 && wcscmp(tempName, L"..") != 0) {
      if (PHASE14_IS_JUNCTION_DIR(fd.dwFileAttributes))
        goto next_fd_fb;
      size_t fullSrcLen = parentSrcLen + 1 + (size_t)nameLen;
      size_t fullDstLen = parentDstLen + 1 + (size_t)nameLen;
      if (fullSrcLen >= MAX_PATH_EXT || fullDstLen >= MAX_PATH_EXT) {
        LogMessageRaw(LOG_ERROR, 206, workSrc, 0, 0);
        InterlockedIncrement(&g_TotalFailed);
        goto next_fd_fb;
      }
      memcpy(workSrc, scanTask->SrcPath, parentSrcLen * sizeof(wchar_t));
      workSrc[parentSrcLen] = L'\\';
      memcpy(workSrc + parentSrcLen + 1, tempName, ((size_t)nameLen + 1) * sizeof(wchar_t));
      memcpy(workDst, parentDstBase, parentDstLen * sizeof(wchar_t));
      workDst[parentDstLen] = L'\\';
      memcpy(workDst + parentDstLen + 1, tempName, ((size_t)nameLen + 1) * sizeof(wchar_t));
      if (srcNeedsNorm) {
        NormalizePath(workSrc, tempNorm, MAX_PATH_EXT);
        StringCchCopyW(workSrc, MAX_PATH_EXT, tempNorm);
        fullSrcLen = wcslen(workSrc);
      }
      if (dstNeedsNorm) {
        NormalizePath(workDst, tempNorm, MAX_PATH_EXT);
        StringCchCopyW(workDst, MAX_PATH_EXT, tempNorm);
        fullDstLen = wcslen(workDst);
      }
      LONGLONG fileSize = ((LONGLONG)(ULONGLONG)fd.nFileSizeHigh << 32) | (LONGLONG)(ULONGLONG)fd.nFileSizeLow;
      if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        if (IsCanceling())
          goto next_fd_fb;
        if (!g_Config.FlattenDir && !g_Config.AuditOnly) {
          EnsureParentDirExistsEx(workDst, fullDstLen - (size_t)nameLen - 1);
          if (g_Config.IsMoveMode && g_IsSameVolume &&
              MoveFileExW(workSrc, workDst, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            goto next_fd_fb;
          if (g_Config.IsMoveMode && !g_IsSameVolume)
            AddMoveSourceDir(workSrc);
          if (!CreateDirectoryW(workDst, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
            LogMessage(LOG_WARNING, L"[ProcessScanTask] CreateDirectory failed: %ls\n", workDst);
          if (!g_Config.FastMode && g_DirMetaStack) {
            DirMetaTask *dmt = AllocDirMetaTask();
            if (dmt) {
              dmt->SrcPath = StrDupWithLen(&threadParam->tlab, g_StringArena, workSrc, fullSrcLen);
              dmt->SrcLen = (uint32_t)fullSrcLen;
              dmt->DstPath = dmt->SrcPath ? StrDupWithLen(&threadParam->tlab, g_StringArena, workDst, fullDstLen) : NULL;
              dmt->DstLen = (uint32_t)fullDstLen;
              dmt->pathFlags = TASK_PATH_FLAG_SRC_ARENA | TASK_PATH_FLAG_DST_ARENA;
              if (dmt->SrcPath && dmt->DstPath) {
                dmt->CreationTime = fd.ftCreationTime;
                dmt->LastAccessTime = fd.ftLastAccessTime;
                dmt->LastWriteTime = fd.ftLastWriteTime;
                dmt->FileAttributes = fd.dwFileAttributes;
                InterlockedPushEntrySList(g_DirMetaStack, &dmt->ItemEntry);
              } else {
                FreeDirMetaTask(dmt);
              }
            }
          }
        }
        ScanTask *nT = AllocScanTask();
        if (!nT)
          goto next_fd_fb;
        if (fullSrcLen < MAX_PATH && fullDstLen < MAX_PATH) {
          StringCchCopyW(nT->ShortSrc, MAX_PATH, workSrc);
          StringCchCopyW(nT->ShortDst, MAX_PATH, workDst);
          nT->SrcPath = nT->ShortSrc;
          nT->DstPath = nT->ShortDst;
          nT->SrcLen = (uint32_t)fullSrcLen;
          nT->DstLen = (uint32_t)fullDstLen;
          nT->pathFlags = TASK_PATH_FLAG_SRC_SHORT | TASK_PATH_FLAG_DST_SHORT;
        } else {
          nT->SrcPath = StrDupTransient(workSrc, fullSrcLen);
          nT->DstPath = nT->SrcPath ? StrDupTransient(workDst, fullDstLen) : NULL;
          nT->SrcLen = (uint32_t)fullSrcLen;
          nT->DstLen = (uint32_t)fullDstLen;
          if (!nT->SrcPath || !nT->DstPath) {
            FreeScanTask(nT);
            goto next_fd_fb;
          }
          nT->pathFlags = 0;
        }
        InterlockedIncrement(&g_PendingActive);
        if (g_Config.BfsScan && g_BfsScanQueue) {
          PushBfsScanTask(nT);
          PostQueuedCompletionStatus(threadParam->hIocp, 0, KEY_SCAN_TASK, NULL);
        } else
          PostQueuedCompletionStatus(threadParam->hIocp, 0, KEY_SCAN_TASK, (LPOVERLAPPED)nT);
      } else {
        if (IsCanceling())
          goto next_fd_fb;
        if (!PassesDateSizeFilter(fileSize, &fd.ftLastWriteTime))
          goto next_fd_fb;
        CopyTask *cT = TLC_AllocCopyTask(threadParam);
        if (cT) {
          if (fullSrcLen < MAX_PATH && fullDstLen < MAX_PATH) {
            StringCchCopyW(cT->ShortSrc, MAX_PATH, workSrc);
            StringCchCopyW(cT->ShortDst, MAX_PATH, workDst);
            cT->SrcPath = cT->ShortSrc;
            cT->DstPath = cT->ShortDst;
            cT->SrcLen = (uint32_t)fullSrcLen;
            cT->DstLen = (uint32_t)fullDstLen;
            cT->pathFlags = TASK_PATH_FLAG_SRC_SHORT | TASK_PATH_FLAG_DST_SHORT;
          } else {
            cT->SrcPath = StrDupTransient(workSrc, fullSrcLen);
            cT->DstPath = cT->SrcPath ? StrDupTransient(workDst, fullDstLen) : NULL;
            cT->SrcLen = (uint32_t)fullSrcLen;
            cT->DstLen = (uint32_t)fullDstLen;
            if (!cT->SrcPath || !cT->DstPath) {
              TLC_FreeCopyTask(threadParam, cT);
              goto next_fd_fb;
            }
            cT->pathFlags = 0;
          }
          cT->FileSize = fileSize;
          cT->CreationTime = fd.ftCreationTime;
          cT->LastAccessTime = fd.ftLastAccessTime;
          cT->LastWriteTime = fd.ftLastWriteTime;
          cT->FileAttributes = fd.dwFileAttributes;
          if (cT->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            TLC_FreeCopyTask(threadParam, cT);
            goto next_fd_fb;
          }
          InterlockedIncrement(&g_TotalFound);
          InterlockedAdd64(&g_TotalFoundBytes, cT->FileSize);
          PostCopyTaskWithOverflow(threadParam, cT, threadParam->hIocp);
        }
      }
    }
  next_fd_fb:;
  } while (ProcessScanTask_FindNextFileWithRetry(hFind, &fd, scanTask->SrcPath));
  FindClose(hFind);
}

void ProcessScanTask(ScanTask *scanTask, CopierParam *threadParam) {
  if (!CheckAndAddDirCacheEx(scanTask->SrcPath, scanTask->SrcLen)) {
    LogMessage(LOG_DEBUG, L"[ProcessScanTask] DirCache skip (dup): %ls\n", scanTask->SrcPath);
    FreeScanTask(scanTask);
    InterlockedDecrement(&g_PendingActive);
    return;
  }
  /* 目录句柄：须与 wmain 中 EnablePrivilege(SE_BACKUP/SE_RESTORE)+EnableBackupPrivileges 配合；
   * 仅当传入 FILE_FLAG_BACKUP_SEMANTICS 时备份特权才参与 ACL 旁路；仍 DENIED 则属独占/策略上限。 */
  HANDLE hDir =
      CreateFileW(scanTask->SrcPath, GENERIC_READ,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                  OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
  if (hDir == INVALID_HANDLE_VALUE) {
    DWORD eOpen = GetLastError();
    if (eOpen == ERROR_ACCESS_DENIED || eOpen == ERROR_SHARING_VIOLATION)
      LogMessage(LOG_WARNING,
                 L"[ProcessScanTask] CreateFileW failed (inaccessible subtree), skipping: %ls err=%lu\n",
                 scanTask->SrcPath, (unsigned long)eOpen);
    else
      LogMessage(LOG_WARNING, L"[ProcessScanTask] CreateFileW failed for %ls, err=%lu\n",
                 scanTask->SrcPath, (unsigned long)eOpen);
    FreeScanTask(scanTask);
    InterlockedDecrement(&g_PendingActive);
    return;
  }
  /* OPT-01: 镜像模式预扫——哈希数组版：1 次 malloc，无碎片，100 万文件仅 8MB */
  if (g_Config.MirrorDelete && !g_Config.FlattenDir && !g_Config.IsFtpDest) {
    HANDLE hMirror = CreateFileW(scanTask->SrcPath, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hMirror != INVALID_HANDLE_VALUE) {
      UINT64 *srcHashes = NULL;
      int srcHashCount = 0, srcHashCap = 0;
      DWORD mBufSize = SCAN_BUFFER_SIZE;
      BYTE *mBuf = (BYTE *)malloc(mBufSize);
      if (mBuf) {
        for (;;) {
          if (!GetFileInformationByHandleEx(hMirror, FileIdBothDirectoryInfo,
                                            mBuf, mBufSize)) {
            DWORD errM = GetLastError();
            if (errM == ERROR_MORE_DATA) {
              free(mBuf);
              mBufSize = (mBufSize < 1024 * 1024) ? 1024 * 1024 : mBufSize * 2;
              if (mBufSize > 16 * 1024 * 1024) break;
              mBuf = (BYTE *)malloc(mBufSize);
              if (!mBuf) break;
              continue;
            }
            if (errM == ERROR_NO_MORE_FILES)
              break;
            break;
          }
          FILE_ID_BOTH_DIR_INFO *q = (FILE_ID_BOTH_DIR_INFO *)mBuf;
          while (1) {
            DWORD qLen = q->FileNameLength / sizeof(wchar_t);
            if (qLen >= MAX_PATH) qLen = MAX_PATH - 1;
            if (wcscmp(q->FileName, L".") != 0 && wcscmp(q->FileName, L"..") != 0) {
              if (srcHashCount >= srcHashCap) {
                /* 无上限扩容：支持超大扁平目录（百万级文件） */
                int newCap = (srcHashCap == 0) ? 4096 : srcHashCap * 2;
                UINT64 *nh = (UINT64 *)realloc(srcHashes, newCap * sizeof(UINT64));
                if (!nh) break;
                srcHashes = nh;
                srcHashCap = newCap;
              }
              srcHashes[srcHashCount++] = HashNameForMirror(q->FileName, qLen);
            }
            if (q->NextEntryOffset == 0) break;
            q = (FILE_ID_BOTH_DIR_INFO *)((BYTE *)q + q->NextEntryOffset);
          }
        }
        free(mBuf);
      }
      if (srcHashCount > 0) {
        qsort(srcHashes, (size_t)srcHashCount, sizeof(UINT64), CompareU64);
        DeleteOrphansInDir(scanTask->DstPath, srcHashes, srcHashCount);
        free(srcHashes);
      }
      CloseHandle(hMirror);
    }
  }
  BYTE *buffer = threadParam->ScanBuffer;
  DWORD bufSize = SCAN_BUFFER_SIZE;
  wchar_t *workSrc = threadParam->ScanWorkSrc;
  wchar_t *workDst = threadParam->ScanWorkDst;
  wchar_t *tempNorm = threadParam->ScanTempNorm;
  /* Phase 20 长度透传：父目录长度循环外只算一次，循环内 memcpy 零 wcslen */
  size_t parentSrcLen = scanTask->SrcLen ? scanTask->SrcLen : wcslen(scanTask->SrcPath);
  size_t parentDstLen = g_Config.FlattenDir ? wcslen(g_Config.DstPath)
      : (scanTask->DstLen ? scanTask->DstLen : wcslen(scanTask->DstPath));
  const wchar_t *parentDstBase = g_Config.FlattenDir ? g_Config.DstPath : scanTask->DstPath;
  /* 将路径规范化判断提升到循环外：同一 ScanTask 的 SrcPath/DstPath 在整个扫描过程不变 */
  BOOL srcNeedsNorm = (wcsncmp(scanTask->SrcPath, L"\\\\?\\", 4) != 0);
  BOOL dstNeedsNorm = (wcsncmp(parentDstBase, L"\\\\?\\", 4) != 0);
  DirEntryForSort *sortedEntries = NULL;
  int entryCount = 0, entryCap = 0;
  BOOL useCollectAndSort = (g_Config.OrderByPhysical && !g_Config.IsFtpSource);
  for (;;) {
    if (IsCanceling())
      break;
    if (!GetFileInformationByHandleEx(hDir, FileIdBothDirectoryInfo, buffer,
                                      bufSize)) {
      DWORD scanErr = GetLastError();
      if (scanErr == ERROR_MORE_DATA) {
        if (buffer != threadParam->ScanBuffer)
          free(buffer);
        bufSize = (bufSize < 1024 * 1024) ? 1024 * 1024 : bufSize * 2;
        if (bufSize > 16 * 1024 * 1024) {
          LogMessage(LOG_WARNING, L"[ProcessScanTask] Dir too large (>16MB), skipping: %ls\n",
                     scanTask->SrcPath);
          break;
        }
        buffer = (BYTE *)malloc(bufSize);
        if (!buffer)
          break;
        continue;
      }
      if (scanErr == ERROR_NO_MORE_FILES) {
        break; /* 该目录所有批次已枚举完毕 */
      }
      if (scanErr == ERROR_ACCESS_DENIED || scanErr == ERROR_SHARING_VIOLATION) {
        LogMessage(LOG_WARNING,
                   L"[ProcessScanTask] GetFileInformationByHandleEx failed: %ls err=%lu "
                   L"(ACCESS_DENIED/SHARING; using FindFirst fallback)\n",
                   scanTask->SrcPath, (unsigned long)scanErr);
        ProcessScanTask_EnumerateFindFirstFallback(scanTask, threadParam, parentSrcLen, parentDstLen,
                                                  parentDstBase, srcNeedsNorm, dstNeedsNorm, workSrc,
                                                  workDst, tempNorm);
        break;
      }
      LogMessage(LOG_WARNING, L"[ProcessScanTask] GetFileInformationByHandleEx failed: %ls err=%lu\n",
                 scanTask->SrcPath, (unsigned long)scanErr);
      break;
    }
    FILE_ID_BOTH_DIR_INFO *p = (FILE_ID_BOTH_DIR_INFO *)buffer;
    while (1) {
      DWORD nameLen = p->FileNameLength / sizeof(wchar_t);
      wchar_t tempName[MAX_PATH];
      if (nameLen >= MAX_PATH)
        nameLen = MAX_PATH - 1;
      StringCchCopyNW(tempName, MAX_PATH, p->FileName, nameLen);
      if (wcscmp(tempName, L".") != 0 && wcscmp(tempName, L"..") != 0) {
        if (PHASE14_IS_JUNCTION_DIR(p->FileAttributes))
          goto next_entry;
        /* -O 物理顺序：先收集再按 FileId 排序，超 5 万项不排序 */
        if (useCollectAndSort) {
          if (entryCount >= ORDER_BY_PHYSICAL_MAX_ENTRIES) {
            useCollectAndSort = FALSE;
          } else {
            if (entryCount >= entryCap) {
              int newCap = (entryCap == 0) ? 4096 : entryCap * 2;
              if (newCap > ORDER_BY_PHYSICAL_MAX_ENTRIES)
                newCap = ORDER_BY_PHYSICAL_MAX_ENTRIES;
              DirEntryForSort *n = (DirEntryForSort *)realloc(
                  sortedEntries, (size_t)newCap * sizeof(DirEntryForSort));
              if (!n) {
                useCollectAndSort = FALSE;
              } else {
                sortedEntries = n;
                entryCap = newCap;
              }
            }
            if (useCollectAndSort && entryCount < entryCap) {
              DirEntryForSort *e = &sortedEntries[entryCount++];
              e->FileId = p->FileId.QuadPart;
              e->FileAttributes = p->FileAttributes;
              e->EndOfFile.QuadPart = p->EndOfFile.QuadPart;
              e->CreationTime.dwLowDateTime = p->CreationTime.LowPart;
              e->CreationTime.dwHighDateTime = p->CreationTime.HighPart;
              e->LastAccessTime.dwLowDateTime = p->LastAccessTime.LowPart;
              e->LastAccessTime.dwHighDateTime = p->LastAccessTime.HighPart;
              e->LastWriteTime.dwLowDateTime = p->LastWriteTime.LowPart;
              e->LastWriteTime.dwHighDateTime = p->LastWriteTime.HighPart;
              e->nameLen = nameLen;
              StringCchCopyNW(e->FileName, MAX_PATH, p->FileName, nameLen);
              e->FileName[nameLen] = L'\0';
              goto next_entry;
            }
          }
        }
        /* Phase 20 memcpy 拼接：零 StringCchPrintfW 内部 wcslen */
        size_t fullSrcLen = parentSrcLen + 1 + (size_t)nameLen;
        size_t fullDstLen = parentDstLen + 1 + (size_t)nameLen;
        if (fullSrcLen >= MAX_PATH_EXT || fullDstLen >= MAX_PATH_EXT) {
          LogMessageRaw(LOG_ERROR, 206, workSrc, 0, 0);  /* 206=ERROR_FILENAME_EXCED_RANGE */
          InterlockedIncrement(&g_TotalFailed);
          goto next_entry;
        }
        memcpy(workSrc, scanTask->SrcPath, parentSrcLen * sizeof(wchar_t));
        workSrc[parentSrcLen] = L'\\';
        memcpy(workSrc + parentSrcLen + 1, tempName, ((size_t)nameLen + 1) * sizeof(wchar_t));
        memcpy(workDst, parentDstBase, parentDstLen * sizeof(wchar_t));
        workDst[parentDstLen] = L'\\';
        memcpy(workDst + parentDstLen + 1, tempName, ((size_t)nameLen + 1) * sizeof(wchar_t));
        if (srcNeedsNorm) {
          NormalizePath(workSrc, tempNorm, MAX_PATH_EXT);
          StringCchCopyW(workSrc, MAX_PATH_EXT, tempNorm);
          fullSrcLen = wcslen(workSrc);
        }
        if (dstNeedsNorm) {
          NormalizePath(workDst, tempNorm, MAX_PATH_EXT);
          StringCchCopyW(workDst, MAX_PATH_EXT, tempNorm);
          fullDstLen = wcslen(workDst);
        }
        if (p->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
          if (IsCanceling())
            goto next_entry;
          if (!g_Config.FlattenDir && !g_Config.AuditOnly) {
            EnsureParentDirExistsEx(workDst, fullDstLen - (size_t)nameLen - 1);
            /* -move 同卷：一次 MoveFileExW 原子移动整棵子树，MFT 仅改父指针，无递归 */
            if (g_Config.IsMoveMode && g_IsSameVolume &&
                MoveFileExW(workSrc, workDst, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
              goto next_entry; /* 已移动，不投递子任务 */
            }
            if (g_Config.IsMoveMode && !g_IsSameVolume)
              AddMoveSourceDir(workSrc);
            if (!CreateDirectoryW(workDst, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
              LogMessage(LOG_WARNING, L"[ProcessScanTask] CreateDirectory failed: %ls\n", workDst);
            if (!g_Config.FastMode && g_DirMetaStack) {
              DirMetaTask *dmt = AllocDirMetaTask();
              if (dmt) {
                dmt->SrcPath = StrDupWithLen(&threadParam->tlab, g_StringArena, workSrc, fullSrcLen);
                dmt->SrcLen = (uint32_t)fullSrcLen;
                dmt->DstPath = dmt->SrcPath ? StrDupWithLen(&threadParam->tlab, g_StringArena, workDst, fullDstLen) : NULL;
                dmt->DstLen = (uint32_t)fullDstLen;
                dmt->pathFlags = TASK_PATH_FLAG_SRC_ARENA | TASK_PATH_FLAG_DST_ARENA;
                if (dmt->SrcPath && dmt->DstPath) {
                  dmt->CreationTime.dwLowDateTime = p->CreationTime.LowPart;
                  dmt->CreationTime.dwHighDateTime = p->CreationTime.HighPart;
                  dmt->LastAccessTime.dwLowDateTime = p->LastAccessTime.LowPart;
                  dmt->LastAccessTime.dwHighDateTime = p->LastAccessTime.HighPart;
                  dmt->LastWriteTime.dwLowDateTime = p->LastWriteTime.LowPart;
                  dmt->LastWriteTime.dwHighDateTime = p->LastWriteTime.HighPart;
                  dmt->FileAttributes = p->FileAttributes;
                  InterlockedPushEntrySList(g_DirMetaStack, &dmt->ItemEntry);
                } else {
                  FreeDirMetaTask(dmt);
                }
              }
            }
          }
          ScanTask *nT = AllocScanTask();
          if (!nT)
            goto next_entry;
          {
            if (fullSrcLen < MAX_PATH && fullDstLen < MAX_PATH) {
              StringCchCopyW(nT->ShortSrc, MAX_PATH, workSrc);
              StringCchCopyW(nT->ShortDst, MAX_PATH, workDst);
              nT->SrcPath = nT->ShortSrc;
              nT->DstPath = nT->ShortDst;
              nT->SrcLen = (uint32_t)fullSrcLen;
              nT->DstLen = (uint32_t)fullDstLen;
              nT->pathFlags = TASK_PATH_FLAG_SRC_SHORT | TASK_PATH_FLAG_DST_SHORT;
            } else {
              nT->SrcPath = StrDupTransient(workSrc, fullSrcLen);
              nT->DstPath = nT->SrcPath ? StrDupTransient(workDst, fullDstLen) : NULL;
              nT->SrcLen = (uint32_t)fullSrcLen;
              nT->DstLen = (uint32_t)fullDstLen;
              if (!nT->SrcPath || !nT->DstPath) {
                FreeScanTask(nT);
                goto next_entry;
              }
              nT->pathFlags = 0;
            }
          }
            InterlockedIncrement(&g_PendingActive);
            if (g_Config.BfsScan && g_BfsScanQueue) {
              PushBfsScanTask(nT);
              PostQueuedCompletionStatus(threadParam->hIocp, 0, KEY_SCAN_TASK, NULL);
            } else
              PostQueuedCompletionStatus(threadParam->hIocp, 0, KEY_SCAN_TASK, (LPOVERLAPPED)nT);
          } else {
          if (IsCanceling())
            goto next_entry;
          /* P1: 日期/大小过滤器（收集路径） */
          if (!PassesDateSizeFilter(p->EndOfFile.QuadPart, &p->LastWriteTime))
            goto next_entry;
          CopyTask *cT = TLC_AllocCopyTask(threadParam);
          if (cT) {
            if (fullSrcLen < MAX_PATH && fullDstLen < MAX_PATH) {
              StringCchCopyW(cT->ShortSrc, MAX_PATH, workSrc);
              StringCchCopyW(cT->ShortDst, MAX_PATH, workDst);
              cT->SrcPath = cT->ShortSrc;
              cT->DstPath = cT->ShortDst;
              cT->SrcLen = (uint32_t)fullSrcLen;
              cT->DstLen = (uint32_t)fullDstLen;
              cT->pathFlags = TASK_PATH_FLAG_SRC_SHORT | TASK_PATH_FLAG_DST_SHORT;
            } else {
              cT->SrcPath = StrDupTransient(workSrc, fullSrcLen);
              cT->DstPath = cT->SrcPath ? StrDupTransient(workDst, fullDstLen) : NULL;
              cT->SrcLen = (uint32_t)fullSrcLen;
              cT->DstLen = (uint32_t)fullDstLen;
              if (!cT->SrcPath || !cT->DstPath) {
                TLC_FreeCopyTask(threadParam, cT);
                goto next_entry;
              }
              cT->pathFlags = 0;
            }
            cT->FileSize = p->EndOfFile.QuadPart;
            cT->CreationTime.dwLowDateTime = p->CreationTime.LowPart;
            cT->CreationTime.dwHighDateTime = p->CreationTime.HighPart;
            cT->LastAccessTime.dwLowDateTime = p->LastAccessTime.LowPart;
            cT->LastAccessTime.dwHighDateTime = p->LastAccessTime.HighPart;
            cT->LastWriteTime.dwLowDateTime = p->LastWriteTime.LowPart;
            cT->LastWriteTime.dwHighDateTime = p->LastWriteTime.HighPart;
            cT->FileAttributes = p->FileAttributes;
            if (cT->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
              TLC_FreeCopyTask(threadParam, cT);
              goto next_entry;
            }
            InterlockedIncrement(&g_TotalFound);
            InterlockedAdd64(&g_TotalFoundBytes, cT->FileSize);
            PostCopyTaskWithOverflow(threadParam, cT, threadParam->hIocp);
          }
        }
      next_entry:;
      }
      if (p->NextEntryOffset == 0)
        break;
      p = (FILE_ID_BOTH_DIR_INFO *)((BYTE *)p + p->NextEntryOffset);
    }
    /* 同一目录句柄继续循环调用，直至返回 ERROR_NO_MORE_FILES（大目录多批 1MB 块） */
  }
  /* -O 物理顺序：按 FileId 排序后处理 */
  if (useCollectAndSort && sortedEntries && entryCount > 0) {
    if (entryCount <= ORDER_BY_PHYSICAL_MAX_ENTRIES)
      RadixSortDirEntryByFileId(sortedEntries, entryCount);
    for (int i = 0; i < entryCount; i++) {
      DirEntryForSort *e = &sortedEntries[i];
      if (IsCanceling())
        break;
      size_t childLen = (size_t)e->nameLen;
      size_t fullSrcLen = parentSrcLen + 1 + childLen;
      size_t fullDstLen = parentDstLen + 1 + childLen;
      if (fullSrcLen >= MAX_PATH_EXT || fullDstLen >= MAX_PATH_EXT)
        continue;
      memcpy(workSrc, scanTask->SrcPath, parentSrcLen * sizeof(wchar_t));
      workSrc[parentSrcLen] = L'\\';
      memcpy(workSrc + parentSrcLen + 1, e->FileName, (childLen + 1) * sizeof(wchar_t));
      memcpy(workDst, parentDstBase, parentDstLen * sizeof(wchar_t));
      workDst[parentDstLen] = L'\\';
      memcpy(workDst + parentDstLen + 1, e->FileName, (childLen + 1) * sizeof(wchar_t));
      if (srcNeedsNorm) {
        NormalizePath(workSrc, tempNorm, MAX_PATH_EXT);
        StringCchCopyW(workSrc, MAX_PATH_EXT, tempNorm);
        fullSrcLen = wcslen(workSrc);
      }
      if (dstNeedsNorm) {
        NormalizePath(workDst, tempNorm, MAX_PATH_EXT);
        StringCchCopyW(workDst, MAX_PATH_EXT, tempNorm);
        fullDstLen = wcslen(workDst);
      }
      if (e->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        if (!g_Config.FlattenDir && !g_Config.AuditOnly) {
          EnsureParentDirExistsEx(workDst, fullDstLen - childLen - 1);
          if (g_Config.IsMoveMode && g_IsSameVolume &&
              MoveFileExW(workSrc, workDst, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            continue; /* 同卷整棵子树已移动 */
          if (g_Config.IsMoveMode && !g_IsSameVolume)
            AddMoveSourceDir(workSrc);
          if (!CreateDirectoryW(workDst, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
            LogMessage(LOG_WARNING, L"[ProcessScanTask] CreateDirectory failed: %ls\n", workDst);
          if (!g_Config.FastMode && g_DirMetaStack) {
            DirMetaTask *dmt = AllocDirMetaTask();
            if (dmt) {
              dmt->SrcPath = StrDupWithLen(&threadParam->tlab, g_StringArena, workSrc, fullSrcLen);
              dmt->SrcLen = (uint32_t)fullSrcLen;
              dmt->DstPath = dmt->SrcPath ? StrDupWithLen(&threadParam->tlab, g_StringArena, workDst, fullDstLen) : NULL;
              dmt->DstLen = (uint32_t)fullDstLen;
              dmt->pathFlags = TASK_PATH_FLAG_SRC_ARENA | TASK_PATH_FLAG_DST_ARENA;
              if (dmt->SrcPath && dmt->DstPath) {
                dmt->CreationTime = e->CreationTime;
                dmt->LastAccessTime = e->LastAccessTime;
                dmt->LastWriteTime = e->LastWriteTime;
                dmt->FileAttributes = e->FileAttributes;
                InterlockedPushEntrySList(g_DirMetaStack, &dmt->ItemEntry);
              } else {
                FreeDirMetaTask(dmt);
              }
            }
          }
        }
        ScanTask *nT = AllocScanTask();
        if (nT) {
          if (fullSrcLen < MAX_PATH && fullDstLen < MAX_PATH) {
            StringCchCopyW(nT->ShortSrc, MAX_PATH, workSrc);
            StringCchCopyW(nT->ShortDst, MAX_PATH, workDst);
            nT->SrcPath = nT->ShortSrc;
            nT->DstPath = nT->ShortDst;
            nT->SrcLen = (uint32_t)fullSrcLen;
            nT->DstLen = (uint32_t)fullDstLen;
            nT->pathFlags = TASK_PATH_FLAG_SRC_SHORT | TASK_PATH_FLAG_DST_SHORT;
          } else {
            nT->SrcPath = StrDupTransient(workSrc, fullSrcLen);
            nT->DstPath = nT->SrcPath ? StrDupTransient(workDst, fullDstLen) : NULL;
            nT->SrcLen = (uint32_t)fullSrcLen;
            nT->DstLen = (uint32_t)fullDstLen;
            if (!nT->SrcPath || !nT->DstPath) {
              FreeScanTask(nT);
              continue;
            }
            nT->pathFlags = 0;
          }
          InterlockedIncrement(&g_PendingActive);
          if (g_Config.BfsScan && g_BfsScanQueue) {
            PushBfsScanTask(nT);
            PostQueuedCompletionStatus(threadParam->hIocp, 0, KEY_SCAN_TASK, NULL);
          } else
            PostQueuedCompletionStatus(threadParam->hIocp, 0, KEY_SCAN_TASK, (LPOVERLAPPED)nT);
        }
      } else {
        /* P1: 日期/大小过滤器（排序后路径） */
        if (PassesDateSizeFilter((LONGLONG)e->EndOfFile.QuadPart, &e->LastWriteTime)) {
          CopyTask *cT = TLC_AllocCopyTask(threadParam);
          if (cT) {
            if (fullSrcLen < MAX_PATH && fullDstLen < MAX_PATH) {
              StringCchCopyW(cT->ShortSrc, MAX_PATH, workSrc);
              StringCchCopyW(cT->ShortDst, MAX_PATH, workDst);
              cT->SrcPath = cT->ShortSrc;
              cT->DstPath = cT->ShortDst;
              cT->SrcLen = (uint32_t)fullSrcLen;
              cT->DstLen = (uint32_t)fullDstLen;
              cT->pathFlags = TASK_PATH_FLAG_SRC_SHORT | TASK_PATH_FLAG_DST_SHORT;
            } else {
              cT->SrcPath = StrDupTransient(workSrc, fullSrcLen);
              cT->DstPath = cT->SrcPath ? StrDupTransient(workDst, fullDstLen) : NULL;
              cT->SrcLen = (uint32_t)fullSrcLen;
              cT->DstLen = (uint32_t)fullDstLen;
              if (!cT->SrcPath || !cT->DstPath) {
                TLC_FreeCopyTask(threadParam, cT);
                continue;
              }
              cT->pathFlags = 0;
            }
            cT->FileSize = (LONGLONG)e->EndOfFile.QuadPart;
            cT->CreationTime = e->CreationTime;
            cT->LastAccessTime = e->LastAccessTime;
            cT->LastWriteTime = e->LastWriteTime;
            cT->FileAttributes = e->FileAttributes;
            if (cT->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
              TLC_FreeCopyTask(threadParam, cT);
              continue;
            }
            InterlockedIncrement(&g_TotalFound);
            InterlockedAdd64(&g_TotalFoundBytes, cT->FileSize);
            PostCopyTaskWithOverflow(threadParam, cT, threadParam->hIocp);
          }
        }
      }
    }
    free(sortedEntries);
  }
  if (buffer != threadParam->ScanBuffer)
    free(buffer);
  CloseHandle(hDir);
  FreeScanTask(scanTask);
  InterlockedDecrement(&g_PendingActive);
}

/* 线程收到 TERMINATE 并 goto copier_exit 时，同批之外的 IOCP 上可能仍挂着根 KEY_SCAN_TASK 等
 * 完成包（先投递的扫描任务排在后到的 TERMINATE 之后未出队）。若不排空，g_PendingActive 永不少减，
 * 表现为 Found=0、PendingActive=1。此处按取消语义释放剩余 COPY/SCAN，不执行 ProcessTask/ProcessScanTask。 */
static void DrainIocpForShutdown(CopierParam *param) {
  if (!param || !param->hIocp)
    return;
  for (int spin = 0; spin < 4096; spin++) {
    OVERLAPPED_ENTRY cEntries[GQCSEx_BATCH_SIZE];
    ULONG numGot = 0;
    (void)GetQueuedCompletionStatusEx(param->hIocp, cEntries, GQCSEx_BATCH_SIZE, &numGot, 0, FALSE);
    if (numGot == 0)
      break;
    for (ULONG ci = 0; ci < numGot; ci++) {
      ULONG_PTR key = cEntries[ci].lpCompletionKey;
      LPOVERLAPPED ov = cEntries[ci].lpOverlapped;
      if (key == KEY_TERMINATE)
        continue;
      if (key == KEY_COPY_TASK && ov) {
        TLC_FreeCopyTask(param, (CopyTask *)ov);
        InterlockedDecrement(&g_PendingActive);
        {
          LONG _after = InterlockedDecrement(&g_PendingCopyTasks);
          NotePendingCopyDec(_after);
        }
      } else if (key == KEY_SCAN_TASK) {
        ScanTask *st = NULL;
        if (g_Config.BfsScan && g_BfsScanQueue) {
          st = TryPopBfsScanTask();
          if (!st && ov)
            st = (ScanTask *)ov;
        } else if (ov) {
          st = (ScanTask *)ov;
        }
        if (st) {
          FreeScanTask(st);
          InterlockedDecrement(&g_PendingActive);
        }
      }
    }
  }
}

#ifndef ALL_PROCESSOR_GROUPS
#define ALL_PROCESSOR_GROUPS ((WORD)0xFFFF)
#endif

typedef BOOL(WINAPI *PBSetThreadGroupAffinity)(HANDLE, const GROUP_AFFINITY *, PGROUP_AFFINITY);
static PBSetThreadGroupAffinity g_pSetThreadGroupAffinityFn = NULL;

static void PB_EnsureSetThreadGroupAffinity(void) {
  if (!g_pSetThreadGroupAffinityFn) {
    HMODULE h = GetModuleHandleW(L"kernel32.dll");
    if (h)
      g_pSetThreadGroupAffinityFn =
          (PBSetThreadGroupAffinity)GetProcAddress(h, "SetThreadGroupAffinity");
  }
}

unsigned __stdcall CopierThread(void *pParam) {
  CopierParam *param = (CopierParam *)pParam;
  if (g_TlsCopierParamSlot != TLS_OUT_OF_INDEXES)
    TlsSetValue(g_TlsCopierParamSlot, param);
  typedef BOOL(WINAPI * PSetThreadInformation)(HANDLE, THREAD_INFORMATION_CLASS,
                                               LPVOID, DWORD);
  PSetThreadInformation pSetThreadInfo = (PSetThreadInformation)GetProcAddress(
      GetModuleHandleW(L"kernel32.dll"), "SetThreadInformation");
  if (pSetThreadInfo && (g_Config.HighPriority || g_Config.LowIoPriority)) {
    THREAD_IO_PRIORITY_DESCRIPTOR ioPriority;
    ioPriority.Priority = g_Config.HighPriority ? IoPriorityHigh :
        (g_Config.LowIoPriority ? IoPriorityLow : IoPriorityNormal);
    pSetThreadInfo(GetCurrentThread(), (THREAD_INFORMATION_CLASS)THREAD_IO_PRIORITY_CLASS,
                   &ioPriority, sizeof(ioPriority));
  }
  /* P3 X-Flow CPU 亲和性 + Phase 14 心跳：>64 LP 用 SetThreadGroupAffinity；否则 1<<n 在 n>=64 未定义 */
  DWORD_PTR affinityMask = 0;
  GROUP_AFFINITY affinityGroup = {0};
  BOOL affinityIsGroup = FALSE;
  if (g_Config.CpuAffinity) {
    PB_EnsureSetThreadGroupAffinity();
    DWORD totalLp = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    if (totalLp == 0) {
      SYSTEM_INFO siTmp = {0};
      GetSystemInfo(&siTmp);
      totalLp = siTmp.dwNumberOfProcessors;
    }

    DWORD_PTR mask = 0;
    if (g_NumPCores > 0) {
      /* 12 代+ 异构核：工作线程绑定 P-Core，round-robin 分配（Probe 当前为 Group0 掩码） */
      mask = g_PCoreMasks[param->ThreadIndex % g_NumPCores];
    }
    if (!mask) {
      ULONG highestNode = 0;
      if (GetNumaHighestNodeNumber(&highestNode)) {
        ULONG node = (ULONG)(param->ThreadIndex % (highestNode + 1));
        ULONGLONG nodeMask = 0;
        if (GetNumaNodeProcessorMask((UCHAR)node, &nodeMask) && nodeMask != 0)
          mask = (DWORD_PTR)nodeMask;
      }
    }
    if (!mask) {
      /* 无 P-Core/NUMA：在所有逻辑处理器上轮询；>64 LP 必须按 Processor Group 拆分 */
      if (totalLp > 0 && totalLp > 64 && g_pSetThreadGroupAffinityFn) {
        DWORD idx = (DWORD)(param->ThreadIndex % (int)totalLp);
        WORD g = 0;
        DWORD rem = idx;
        for (;;) {
          DWORD cnt = GetActiveProcessorCount(g);
          if (cnt == 0)
            break;
          if (rem < cnt)
            break;
          rem -= cnt;
          g++;
        }
        affinityGroup.Group = g;
        affinityGroup.Mask = (KAFFINITY)((DWORD_PTR)1 << rem);
        if (g_pSetThreadGroupAffinityFn(GetCurrentThread(), &affinityGroup, NULL))
          affinityIsGroup = TRUE;
        else if (totalLp > 0) {
          int bit = (int)(param->ThreadIndex % 64);
          mask = (DWORD_PTR)1 << bit;
        }
      } else if (totalLp > 0) {
        int bit = (int)(param->ThreadIndex % (int)totalLp);
        if (totalLp > 64 && !g_pSetThreadGroupAffinityFn)
          bit = (int)(param->ThreadIndex % 64);
        if (bit < 64)
          mask = (DWORD_PTR)1 << bit;
      }
    }

    if (mask && !affinityIsGroup) {
      if (totalLp > 64 && g_pSetThreadGroupAffinityFn) {
        affinityGroup.Group = 0;
        affinityGroup.Mask = (KAFFINITY)mask;
        if (g_pSetThreadGroupAffinityFn(GetCurrentThread(), &affinityGroup, NULL))
          affinityIsGroup = TRUE;
        else {
          SetThreadAffinityMask(GetCurrentThread(), mask);
          affinityMask = mask;
        }
      } else {
        SetThreadAffinityMask(GetCurrentThread(), mask);
        affinityMask = mask;
      }
    }
  }

  /* Phase 18 去抖动：MMCSS Pro-Audio 调度，前 8 个 I/O 线程获得真实实时级时间片，屏蔽 DPC 毛刺 */
  if (param->ThreadIndex < 8 && g_pAvSetMmThreadCharacteristics && g_pAvSetMmThreadPriority) {
    DWORD taskIdx = 0;
    HANDLE hTask = g_pAvSetMmThreadCharacteristics(L"Pro Audio", &taskIdx);
    if (hTask) {
      g_pAvSetMmThreadPriority(hTask, 2);  /* AVRT_PRIO_CRITICAL */
      param->hMmcssTask = hTask;
    } else
      param->hMmcssTask = NULL;
  } else
    param->hMmcssTask = NULL;

  /* Phase 12 NUMA 拓扑感知：-W 时 IoRingBuffer/HashBuffer 绑定当前线程所在节点，多路服务器减少跨 UPI 延迟 */
  if (g_Config.CpuAffinity && (!param->IoRingBuffer || !param->HashBuffer)) {
    typedef LPVOID (WINAPI * PVirtualAllocExNuma)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD, DWORD);
    static PVirtualAllocExNuma pVirtualAllocExNuma = NULL;
    if (!pVirtualAllocExNuma)
      pVirtualAllocExNuma = (PVirtualAllocExNuma)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "VirtualAllocExNuma");
    ULONG node = 0;
    /* 多路系统优先用 GetNumaProcessorNodeEx（Processor Group 感知），回退到 GetNumaProcessorNode */
    typedef void (WINAPI * PGetCurrentProcessorNumberEx)(PROCESSOR_NUMBER *);
    typedef BOOL (WINAPI * PGetNumaProcessorNodeEx)(PROCESSOR_NUMBER *, PUSHORT);
    static PGetCurrentProcessorNumberEx pGetCurProcEx = NULL;
    static PGetNumaProcessorNodeEx pGetNumaNodeEx = NULL;
    if (!pGetCurProcEx)
      pGetCurProcEx = (PGetCurrentProcessorNumberEx)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetCurrentProcessorNumberEx");
    if (!pGetNumaNodeEx)
      pGetNumaNodeEx = (PGetNumaProcessorNodeEx)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetNumaProcessorNodeEx");
    if (pGetCurProcEx && pGetNumaNodeEx) {
      PROCESSOR_NUMBER procNum = {0};
      pGetCurProcEx(&procNum);
      USHORT nodeEx = 0;
      if (pGetNumaNodeEx(&procNum, &nodeEx))
        node = nodeEx;
    }
    if (node == 0) {
      UCHAR nodeU8 = 0;
      GetNumaProcessorNode((UCHAR)GetCurrentProcessorNumber(), &nodeU8);
      node = nodeU8;
    }
    if (pVirtualAllocExNuma) {
      if (!param->IoRingBuffer && g_Config.UseIoRing && g_IoRingAvailable) {
        DWORD fl = MEM_COMMIT | MEM_RESERVE;
        if (g_LargePagesAvailable) {
          typedef SIZE_T (WINAPI * PGetLPMin)(void);
          static PGetLPMin pGetLPMin = NULL;
          if (!pGetLPMin)
            pGetLPMin = (PGetLPMin)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetLargePageMinimum");
          if (pGetLPMin) {
            SIZE_T pgMin = pGetLPMin();
            if (pgMin > 0 && THREAD_IORING_BUFFER_SIZE >= pgMin) {
              BYTE *p = (BYTE *)pVirtualAllocExNuma(GetCurrentProcess(), NULL,
                  THREAD_IORING_BUFFER_SIZE, fl | MEM_LARGE_PAGES, PAGE_READWRITE, (DWORD)node);
              if (p) param->IoRingBuffer = p;
              else g_LargePagesAvailable = FALSE;
            }
          }
        }
        if (!param->IoRingBuffer)
          param->IoRingBuffer = (BYTE *)pVirtualAllocExNuma(GetCurrentProcess(), NULL,
              THREAD_IORING_BUFFER_SIZE, fl, PAGE_READWRITE, (DWORD)node);
      }
      if (!param->HashBuffer && g_Config.CompareContent) {
        param->HashBuffer = (BYTE *)pVirtualAllocExNuma(GetCurrentProcess(), NULL,
            1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, (DWORD)node);
      }
    }
  }
  if (!param->IoRingBuffer && g_Config.UseIoRing && g_IoRingAvailable) {
    param->IoRingBuffer = (BYTE *)AllocBufferWithLargePagesFallback(THREAD_IORING_BUFFER_SIZE);
    if (!param->IoRingBuffer && param->ThreadIndex == 0)
      LogMessage(LOG_WARNING, L"[CopierThread] IoRingBuffer alloc failed, IoRing disabled for worker 0\n");
  }
  if (!param->HashBuffer && g_Config.CompareContent) {
    param->HashBuffer = (BYTE *)VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT, PAGE_READWRITE);
  }

  ULONG_PTR key;
  LPOVERLAPPED ov;
  int copyTaskCount = 0;  /* Phase 14 亲和性心跳计数 */
  while (1) {
#if USE_SHM_TELEMETRY
    WaitIfPaused();  /* Phase 8 cmd_Pause：暂停时释放 I/O，不占用磁盘 */
#endif
    LONG l = g_ActiveCopierLimit;
    if (!g_Config.IsSSD && g_SmallFileRatio > 50 && l > 8)
      l = 8;
    /* 启动期保障：有挂起任务时至少允许线程 0 处理，避免传统扫描根任务无人消费导致 Q:0 永久卡死 */
    if (param->ThreadIndex == 0 && READ_VOLATILE_32(&g_PendingActive) > 0 && l < 1)
      l = 1;
    /* P2 自适应退让：DLQ 过深说明系统已在 NTFS 目录锁竞争下挣扎，
     * 序号靠后的额外线程主动暂停 20ms，把 CPU 和目录锁让给前 8 个核心线程，
     * 避免 64 线程轰炸同一目录导致全部失败入 DLQ 的雪崩 */
    if (g_DeadLetterQueue && param->ThreadIndex >= 8) {
      LONG dlqDepthNow = (LONG)QueryDepthSList(g_DeadLetterQueue);
      if (dlqDepthNow > 2000) {
        if (g_PendingActive <= 0) break;
        Sleep(20);
        continue;
      }
    }
    /* V123: Same Physical HDD 激进流控：如果源/目在同物理 HDD 且线程索引 >= 2，
     * 强制进入半秒长休眠。只保留 2 个活跃线程（一个读一个写），彻底消除磁头死锁。
     * 启动期豁免：g_PipelineStartTick 未设置或 3 秒内不限制，确保传统扫描根任务被消费 */
    if (g_Config.IsSamePhysicalHDD && param->ThreadIndex >= 2 &&
        g_PipelineStartTick != 0 && (GetTickCount() - g_PipelineStartTick) >= 3000) {
      if (g_PendingActive <= 0) break;
      Sleep(500);
      continue;
    }
    if (param->ThreadIndex >= l && !IsCanceling()) {
      /* 线程 0 有挂起任务时强制通过，确保传统扫描根任务被消费，解决 Q:0 永久卡死 */
      if (param->ThreadIndex == 0 && READ_VOLATILE_32(&g_PendingActive) > 0)
        ; /* 放行 */
      else {
        if (g_PendingActive <= 0) break;
        Sleep(500);
        continue;
      }
    }
    OVERLAPPED_ENTRY cEntries[GQCSEx_BATCH_SIZE];
    ULONG numGot = 0;
    BOOL bRet = GetQueuedCompletionStatusEx(param->hIocp, cEntries, GQCSEx_BATCH_SIZE, &numGot,
                                            COPIER_GQCS_HEARTBEAT_MS, FALSE);
    if (numGot > 0) {
      for (ULONG ci = 0; ci < numGot; ci++) {
        /* Phase 14 L3 Warm-up：预取下个任务元数据，掩盖内存墙延迟 */
        if (ci + 1 < numGot && cEntries[ci + 1].lpOverlapped)
          _mm_prefetch((const char *)cEntries[ci + 1].lpOverlapped, _MM_HINT_T0);
        key = cEntries[ci].lpCompletionKey;
        ov = cEntries[ci].lpOverlapped;
        if (key == KEY_TERMINATE)
          continue; /* 批末统一退出，避免跳过同批 COPY_TASK 导致 g_PendingActive 泄漏 */
        if (ov) {
          /* Phase 14 亲和性心跳：每 1000 任务强制拉回 P-Core，对抗 OS 热节流 */
          if (key == KEY_COPY_TASK && (affinityMask || affinityIsGroup) &&
              UNLIKELY((++copyTaskCount % 1000) == 0)) {
            if (affinityIsGroup && g_pSetThreadGroupAffinityFn)
              g_pSetThreadGroupAffinityFn(GetCurrentThread(), &affinityGroup, NULL);
            else if (affinityMask)
              SetThreadAffinityMask(GetCurrentThread(), affinityMask);
          }
          if (UNLIKELY(IsCanceling() || !bRet)) {
            if (key == KEY_COPY_TASK) {
              TLC_FreeCopyTask(param, (CopyTask *)ov);
              InterlockedDecrement(&g_PendingActive);
              {
                LONG _after = InterlockedDecrement(&g_PendingCopyTasks);
                NotePendingCopyDec(_after);
              }
            } else if (key == KEY_SCAN_TASK) {
              /* BFS：唤醒包 ov 常为 NULL，任务在链表；TryPop 与 ov 二选一，避免 g_PendingActive 泄漏 */
              if (g_Config.BfsScan && g_BfsScanQueue) {
                ScanTask *st = TryPopBfsScanTask();
                if (!st && ov)
                  st = (ScanTask *)ov;
                if (st) {
                  FreeScanTask(st);
                  InterlockedDecrement(&g_PendingActive);
                }
              } else if (ov) {
                FreeScanTask((ScanTask *)ov);
                InterlockedDecrement(&g_PendingActive);
              }
            }
            continue;
          }
          if (key == KEY_COPY_TASK) {
            DWORD t0 = GetTickCount();
            __try {
              if (ProcessTask((CopyTask *)ov, param) == 0) {
                InterlockedDecrement(&g_PendingActive);
                {
                  LONG _after = InterlockedDecrement(&g_PendingCopyTasks);
                  NotePendingCopyDec(_after);
                }
              }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
              LogMessage(LOG_ERROR, L"[FATAL] Copy worker crashed! Access Violation (0x%08lX) caught.\n",
                         (unsigned long)GetExceptionCode());
              InterlockedDecrement(&g_PendingActive);
              {
                LONG _after = InterlockedDecrement(&g_PendingCopyTasks);
                NotePendingCopyDec(_after);
              }
              /* 不碰 ov：可能已损坏，Free 会二次崩溃；任务泄漏可接受，主循环可安全退出 */
            }
            DWORD elapsed = GetTickCount() - t0;
            if (elapsed > 0) {
              LONG idx = InterlockedIncrement(&g_IoLatencyIdx) - 1;
              g_IoLatencySamples[idx % ADAPTIVE_IO_SAMPLES] = elapsed;
              LONG cnt = InterlockedIncrement(&g_IoLatencyCount);
              if (cnt >= ADAPTIVE_IO_SAMPLES) {
                InterlockedExchange(&g_IoLatencyCount, 0);
                DWORD sum = 0;
                for (int i = 0; i < ADAPTIVE_IO_SAMPLES; i++)
                  sum += g_IoLatencySamples[i];
                DWORD avg = sum / ADAPTIVE_IO_SAMPLES;
                DWORD diskQ = g_CachedDiskQueue;  /* P3：读 OsTelemetryThread 缓存 */
                LONG base = (LONG)g_Config.ThreadCountNormal;
                if (base <= 0) base = 64;
                /* 恢复原始自适应逻辑：diskQ≥8 或 avg>15ms 时降速，avg<1ms 时恢复；中间区间不干预 */
                if (diskQ >= 8) {
                  LONG target = (base >= 8) ? 4 : 2;
                  InterlockedCompareExchange(&g_ActiveCopierLimit, target, g_ActiveCopierLimit);
                } else if (avg < ADAPTIVE_LOW_MS && diskQ < 2 && base > 4) {
                  LONG cur = READ_VOLATILE_32(&g_ActiveCopierLimit);
                  if (cur < base) InterlockedCompareExchange(&g_ActiveCopierLimit, cur + 2, cur);
                } else if (avg > ADAPTIVE_HIGH_MS) {
                  LONG target = (base >= 8) ? 4 : 2;
                  InterlockedCompareExchange(&g_ActiveCopierLimit, target, g_ActiveCopierLimit);
                }
              }
            }
          } else if (key == KEY_SCAN_TASK) {
            ScanTask *st = (g_Config.BfsScan && g_BfsScanQueue) ? PopBfsScanTask() : (ScanTask *)ov;
            if (st) {
              __try {
                ProcessScanTask(st, param);
              } __except (EXCEPTION_EXECUTE_HANDLER) {
                LogMessage(LOG_ERROR, L"[FATAL] Scan thread crashed! AV/Heap corruption (0x%08lX) caught.\n",
                           (unsigned long)GetExceptionCode());
                InterlockedDecrement(&g_PendingActive);
                /* 不碰 st：可能已损坏；让主循环能安全退出而非卡死 60s */
              }
            }
          }
        } else if (key == KEY_SCAN_TASK && g_Config.BfsScan && g_BfsScanQueue) {
          /* ov==NULL 的 BFS 唤醒包不经过上方 if(ov) 内的取消分支，须在此处理 Ctrl+C */
          ScanTask *st = IsCanceling() ? TryPopBfsScanTask() : PopBfsScanTask();
          if (st) {
            if (IsCanceling()) {
              FreeScanTask(st);
              InterlockedDecrement(&g_PendingActive);
            } else {
              __try {
                ProcessScanTask(st, param);
              } __except (EXCEPTION_EXECUTE_HANDLER) {
                LogMessage(LOG_ERROR, L"[FATAL] Scan thread crashed! AV/Heap corruption (0x%08lX) caught.\n",
                           (unsigned long)GetExceptionCode());
                InterlockedDecrement(&g_PendingActive);
              }
            }
          }
        }
      }
      if (numGot > 0) {
        for (ULONG ci = 0; ci < numGot; ci++) {
          if (cEntries[ci].lpCompletionKey == KEY_TERMINATE) {
            FlushIoRingBatch(param);
            goto copier_exit;
          }
        }
      }
    } else {
      /* numGot==0：队列真空；WAIT_TIMEOUT 为心跳，刷出未满 -j 的 IoRing 尾批 */
      if (!bRet && GetLastError() == WAIT_TIMEOUT) {
        if (param->IoRingBatchCount > 0)
          FlushIoRingBatch(param);
        continue;
      }
      if (!bRet) {
        if (g_PendingActive <= 0)
          break;
        if (param->IoRingBatchCount > 0)
          FlushIoRingBatch(param);
        continue;
      }
      /* bRet==TRUE 且 numGot==0 极少见，仍排空 IoRing 以防万一 */
      if (param->IoRingBatchCount > 0)
        FlushIoRingBatch(param);
    }
  }
copier_exit:
  DrainIocpForShutdown(param);
  TlabThreadExit(&param->tlab);
  if (param->hMmcssTask && g_pAvRevertMmThreadCharacteristics) {
    g_pAvRevertMmThreadCharacteristics(param->hMmcssTask);
    param->hMmcssTask = NULL;
  }
  {
    int _i;
    for (_i = 0; _i < NTAPI_DIR_LRU_SLOTS; _i++) {
      if (param->NtApiDstLru[_i].hDir && param->NtApiDstLru[_i].hDir != INVALID_HANDLE_VALUE) {
        CloseHandle(param->NtApiDstLru[_i].hDir);
        param->NtApiDstLru[_i].hDir = INVALID_HANDLE_VALUE;
      }
      if (param->NtApiSrcLru[_i].hDir && param->NtApiSrcLru[_i].hDir != INVALID_HANDLE_VALUE) {
        CloseHandle(param->NtApiSrcLru[_i].hDir);
        param->NtApiSrcLru[_i].hDir = INVALID_HANDLE_VALUE;
      }
    }
    if (param->hFileIocp) {
      CloseHandle(param->hFileIocp);
      param->hFileIocp = NULL;
    }
  }
  if (param->SdCacheBlob) {
    free(param->SdCacheBlob);
    param->SdCacheBlob = NULL;
    param->SdCacheValid = FALSE;
  }
  FlushLocalCounters(param, TRUE);
  FlushIoRingBatch(param);
  /* 线程退出前将 Magazine 剩余任务归还全局池 */
  while (param->LocalCount > 0) {
    CopyTask *p = param->LocalTaskPool[--param->LocalCount];
    InterlockedPushEntrySList(g_CopyTaskPool, &p->ItemEntry);
  }
  return 0;
}

#if HAS_VSS
/* VSS 存储快照：复制被独占锁定的 SQL .mdf 等，底层 I/O 逻辑无需改动 */
static BOOL CreateVssSnapshotAndReplaceSrcPath(void) {
  if (g_Config.SrcPath[0] == L'\\' && g_Config.SrcPath[1] == L'\\' &&
      g_Config.SrcPath[2] != L'?') {
    wprintf(L"Warning: -V (VSS) not supported for UNC paths, skipping.\n");
    return FALSE;
  }
  wchar_t volumePath[MAX_PATH] = {0};
  if (!GetVolumePathNameW(g_Config.SrcPath, volumePath, MAX_PATH)) {
    wprintf(L"Error: GetVolumePathNameW failed, err=%lu\n",
            (unsigned long)GetLastError());
    return FALSE;
  }
  size_t volLen = wcslen(volumePath);
  if (volLen == 0 || volumePath[volLen - 1] != L'\\') {
    wprintf(L"Error: Invalid volume path from GetVolumePathNameW\n");
    return FALSE;
  }
  const wchar_t *relPath = g_Config.SrcPath + volLen;
  while (*relPath == L'\\') relPath++;

  HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
  if (hr != S_OK && hr != S_FALSE && hr != RPC_E_CHANGED_MODE) {
    wprintf(L"Error: CoInitializeEx failed, hr=0x%08lX\n", (unsigned long)hr);
    return FALSE;
  }
  IVssBackupComponents *pVss = NULL;
  hr = CreateVssBackupComponents(&pVss);
  if (FAILED(hr) || !pVss) {
    wprintf(L"Error: CreateVssBackupComponents failed, hr=0x%08lX\n",
            (unsigned long)hr);
    CoUninitialize();
    return FALSE;
  }
  hr = pVss->lpVtbl->InitializeForBackup(pVss, NULL);
  if (FAILED(hr)) {
    wprintf(L"Error: InitializeForBackup failed, hr=0x%08lX\n", (unsigned long)hr);
    pVss->lpVtbl->Release(pVss);
    CoUninitialize();
    return FALSE;
  }
  hr = pVss->lpVtbl->SetContext(pVss, VSS_CTX_BACKUP);
  if (FAILED(hr)) {
    wprintf(L"Error: SetContext failed, hr=0x%08lX\n", (unsigned long)hr);
    pVss->lpVtbl->Release(pVss);
    CoUninitialize();
    return FALSE;
  }
  VSS_ID snapshotSetId = {0};
  hr = pVss->lpVtbl->StartSnapshotSet(pVss, &snapshotSetId);
  if (FAILED(hr)) {
    wprintf(L"Error: StartSnapshotSet failed, hr=0x%08lX\n", (unsigned long)hr);
    pVss->lpVtbl->Release(pVss);
    CoUninitialize();
    return FALSE;
  }
  VSS_ID snapshotId = {0};
  hr = pVss->lpVtbl->AddToSnapshotSet(pVss, volumePath, GUID_NULL, &snapshotId);
  if (FAILED(hr)) {
    wprintf(L"Error: AddToSnapshotSet failed, hr=0x%08lX\n", (unsigned long)hr);
    pVss->lpVtbl->Release(pVss);
    CoUninitialize();
    return FALSE;
  }
  IVssAsync *pAsync = NULL;
  hr = pVss->lpVtbl->PrepareForBackup(pVss, &pAsync);
  if (FAILED(hr) || !pAsync) {
    wprintf(L"Error: PrepareForBackup failed, hr=0x%08lX\n", (unsigned long)hr);
    pVss->lpVtbl->Release(pVss);
    CoUninitialize();
    return FALSE;
  }
  hr = pAsync->lpVtbl->Wait(pAsync, INFINITE);
  pAsync->lpVtbl->Release(pAsync);
  pAsync = NULL;
  if (FAILED(hr)) {
    wprintf(L"Error: PrepareForBackup Wait failed, hr=0x%08lX\n", (unsigned long)hr);
    pVss->lpVtbl->Release(pVss);
    CoUninitialize();
    return FALSE;
  }
  pAsync = NULL;
  hr = pVss->lpVtbl->DoSnapshotSet(pVss, &pAsync);
  if (FAILED(hr) || !pAsync) {
    wprintf(L"Error: DoSnapshotSet failed, hr=0x%08lX\n", (unsigned long)hr);
    pVss->lpVtbl->Release(pVss);
    CoUninitialize();
    return FALSE;
  }
  hr = pAsync->lpVtbl->Wait(pAsync, INFINITE);
  pAsync->lpVtbl->Release(pAsync);
  pAsync = NULL;
  if (FAILED(hr)) {
    wprintf(L"Error: DoSnapshotSet Wait failed, hr=0x%08lX\n", (unsigned long)hr);
    pVss->lpVtbl->Release(pVss);
    CoUninitialize();
    return FALSE;
  }
  VSS_SNAPSHOT_PROP prop = {0};
  hr = pVss->lpVtbl->GetSnapshotProperties(pVss, snapshotId, &prop);
  if (FAILED(hr)) {
    wprintf(L"Error: GetSnapshotProperties failed, hr=0x%08lX\n", (unsigned long)hr);
    pVss->lpVtbl->Release(pVss);
    CoUninitialize();
    return FALSE;
  }
  wchar_t newSrc[MAX_PATH_EXT];
  if (*relPath) {
    StringCchPrintfW(newSrc, MAX_PATH_EXT, L"%ls\\%ls", prop.m_pwszSnapshotDeviceObject,
                     relPath);
  } else {
    StringCchPrintfW(newSrc, MAX_PATH_EXT, L"%ls\\", prop.m_pwszSnapshotDeviceObject);
  }
  StringCchCopyW(g_Config.SrcPath, MAX_PATH_EXT, newSrc);
  VssFreeSnapshotProperties(&prop);
  /* 【致命修复】：不在此处 Release(pVss)！快照生命周期与 pVss 强绑定，
   * 一旦释放 VSS Coordinator 立刻销毁快照，后续 CreateFileW 全部 ERROR_PATH_NOT_FOUND。
   * 转让所有权给全局变量 g_pVss，程序退出时（CleanupVss）统一释放。*/
  g_pVss = pVss;
  wprintf(L"VSS snapshot active, source redirected to shadow copy.\n");
  return TRUE;
}
#endif

void PrintHelp(void) {
  wprintf(L"PB X-Flow - PB data copy tool (V123)\n");
  wprintf(L"Usage: fast_copy_universal_v123.exe -s <source> -d <dest> [-t "
          L"threads]\n");
  wprintf(L"Note: Run as Administrator so SeBackup/SeRestore can take effect; "
          L"without elevation, backup-semantics directory opens cannot bypass all ACL denials.\n");
  wprintf(L"Options:\n");
  wprintf(L"  -s <path>   source path\n");
  wprintf(L"  -d <path>   destination path\n");
  wprintf(L"  -t <n>      worker threads (default 64, flat dir try -t 32)\n");
  wprintf(L"  -T <n>      worker threads outside normal time (-b/-e)\n");
  wprintf(L"  -b <0-23>   start hour for normal time\n");
  wprintf(L"  -e <0-23>   end hour for normal time\n");
  wprintf(L"  -f <ext>    file suffix filter, multi-ext with ; (e.g. .txt or .txt;.log;.bak)\n");
  wprintf(L"  -i          flatten directory structure (same-name overwrite)\n");
  wprintf(L"  -M          metadata-only (ACL/time/attr, no data, AD repair)\n");
  wprintf(L"  -S          large file sampling (>5GB: head/mid/tail 100MB each)\n");
  wprintf(L"  -c          case-insensitive file filter\n");
  wprintf(L"  -p <path>   log path\n");
  wprintf(L"  -N <name>   normal log file name\n");
  wprintf(L"  -E <name>   error log file name\n");
  wprintf(L"  -m          compare modification time (implies size check)\n");
  wprintf(L"  -C          compare file size only (skip if size matches)\n");
  wprintf(L"  -D          compare content (MD5)\n");
  wprintf(L"  -X          compare content (XXH3, ~10GB/s, use with -D or alone)\n");
  wprintf(L"  -R          real-time statistics\n");
  wprintf(L"  -A          copy ACL\n");
  wprintf(L"  -F          fast mode (skip attr/time/ACL)\n");
  wprintf(L"  -H          high priority\n");
  wprintf(L"  -U          low I/O priority (yield to other apps)\n");
  wprintf(L"  -G <ms>     timestamp tolerance for NAS/FAT\n");
  wprintf(L"  -B <MB>     big buffer size\n");
  wprintf(L"  -Q <n>      queue depth\n");
  wprintf(L"  -q <n>      big file I/O depth (0=auto: HDD=2 SSD=8 Net=16)\n");
  wprintf(L"  -I <ms>     refresh interval\n");
  wprintf(L"  -J          IoRing batch for small files (Win11/Server2022+)\n");
  wprintf(L"  -j <size>   IoRing batch size 1-2048 (default 256, flat dir try -j 512)\n");
  wprintf(L"  -L <MB/s>   speed limit (QoS token bucket, 0=unlimited)\n");
  wprintf(L"  -ipg <ms>   inter-packet gap: sleep N ms per 64KB block (WAN flow control)\n");
  wprintf(L"  -copyall    copy DACL+SACL+Owner+Group (full NTFS clone, needs admin)\n");
  wprintf(L"  -defender-exclude  opt-in: UAC to add src/dst to Defender exclusions (local paths; not UNC)\n");
  wprintf(L"  -rh_strict  run hours strict: sleep 60s when outside -b/-e window\n");
  wprintf(L"  -V          VSS snapshot (copy locked SQL .mdf etc, Enterprise)\n");
  wprintf(L"  -audit_only | -audit src   read-only audit: baseline=source (no Extra pass); report append\n");
  wprintf(L"  -audit dst   baseline=target, peer=source (orphans / missing-on-source)\n");
  wprintf(L"  -audit full  src baseline + shallow Extra pass on target; PBXFlow_Audit_Report.txt\n");
  wprintf(L"  -precount    with -audit*: synchronous recursive tree file counts before scan (slow; default off)\n");
  wprintf(L"  -K          mirror mode: delete orphan files/dirs on destination\n");
  wprintf(L"  -move       move mode: same-volume O(1) MoveFileEx, cross-volume copy+delete\n");
  wprintf(L"  -delete     fast delete mode: -s <path> only, bottom-up concurrent delete\n");
  wprintf(L"  -O          order by physical (FileId) to reduce HDD seeks\n");
  wprintf(L"  -bfs       breadth-first scan: batch sibling dirs, HDD MFT prefetch (Phase 10)\n");
  wprintf(L"  -W          CPU affinity: pin worker threads to cores\n");
  wprintf(L"  -hard_ws    hard working set: 1GB min, prevent memory trim (Phase 18, V9)\n");
  wprintf(L"  -host_aware Phase 20: CPU>80%% or disk queue>10时主动降速 70%%，运维友好\n");
  wprintf(L"  -sample_threshold=N  Phase 20: 抽样阈值 GB，默认 5\n");
  wprintf(L"  -sample_random=N    Phase 20: 中间随机块数，默认 6\n");
  wprintf(L"  -Y          delta transfer: overwrite only changed 1MB blocks (XXH3)\n");
  wprintf(L"  -l <file>   retry list: copy only paths in file (one path per line, -s/-d required)\n");
  wprintf(L"  -z          quiet: suppress per-file logs (GUI mode, avoid pipe back-pressure)\n");
  wprintf(L"  -P <pid>    GUI only: watch PID; when it exits, copy cancels. Also enables SHM telemetry.\n");
  wprintf(L"              Omit -P when running alone in CMD (do not paste -P from GUI command line).\n");
  wprintf(L"  -from_date=YYYYMMDD  only copy files newer than date\n");
  wprintf(L"  -to_date=YYYYMMDD    only copy files older than date\n");
  wprintf(L"  -min_size=1M        only copy files larger than size (K/M/G/T)\n");
  wprintf(L"  -max_size=1G        only copy files smaller than size\n");
  wprintf(L"  -job=<name>         load task from [name] in pb_xflow.ini\n");
  wprintf(L"  -perfect_verify      verify by re-reading both src and dst\n");
  wprintf(L"  -no_verify_rename   do not rename to .fc_verify_err on error\n");
  wprintf(L"  -verifyinfo         write :fc_verify stream after successful verify\n");
  wprintf(L"  -mft_scan           MFT/USN fast scan (NTFS+admin, millions/sec)\n");
  wprintf(L"                      Note: one MFT file record -> at most one dest path; extra NTFS\n");
  wprintf(L"                      hard-link names under src are not duplicated. Explorer \"file count\"\n");
  wprintf(L"                      often counts each link -> higher than MFT; omit -mft_scan for full parity.\n");
  wprintf(L"  -mft_raw            Raw $MFT direct read, bypass VFS (NTFS+admin)\n");
  wprintf(L"  -checkpoint_interval=300  write resume checkpoint every N seconds\n");
  wprintf(L"  -checkpoint_gb=100  write checkpoint every N GB copied\n");
  wprintf(L"  -resume             (NOT IMPLEMENTED) was intended for pb_xflow_resume.dat;\n");
  wprintf(L"                      currently only writes progress checkpoints. Use -Y delta instead.\n");
  wprintf(L"  -no_space_preflight  skip destination free-space pre-check (risky if disk really full)\n");
  wprintf(L"  -no_ads             skip Alternate Data Streams (PB tiny-file; use with care)\n");
  wprintf(L"  -write_through      big-file path: FILE_FLAG_WRITE_THROUGH on dest (slower; default: flush at close)\n");
  wprintf(L"  -J -X               IoRing + XXH3 verify (batch hash + async dst verify; preferred for PB)\n");
  wprintf(L"  -h          show help\n");
  wprintf(L"  big files (100M+):\n");
  wprintf(L"    -s <src> -d <dst> -B 64 -q 8 -t 64 -F -W\n");
  wprintf(L"  small files (15K):\n");
  wprintf(L"    -s <src> -d <dst> -J -D -F -t 24 -j 512 -W\n");
  wprintf(L"  big + small mixed:\n");
  wprintf(L"    -s <src> -d <dst> -J -j 256 -B 32 -q 8 -t 64 -F\n");
  wprintf(L"  flat dir (flatten -i):\n");
  wprintf(L"    -s <src> -d <dst> -i -t 32 -j 512 -F\n");
  wprintf(L"  network (UNC/NAS):\n");
  wprintf(L"    -s <src> -d <dst> -q 16 -t 64 -J -F\n");
}

#define PREALLOC_SCAN_TASKS 2048
#define PREALLOC_DIR_META 2048

/* -l 模式：从列表文件读取路径，直接投递 CopyTask/ScanTask，跳过全盘扫描 */
static int LoadListAndPostTasks(HANDLE iocp) {
  FILE *fp = _wfopen(g_Config.ListFilePath, L"r, ccs=UTF-8");
  if (!fp) {
    fp = _wfopen(g_Config.ListFilePath, L"r");
    if (!fp) {
      wprintf(L"Error: cannot open list file: %ls\n", g_Config.ListFilePath);
      return -1;
    }
  }
  wchar_t line[MAX_PATH_EXT];
  int count = 0;
  size_t lenSrc = wcslen(g_Config.SrcPath);
  if (lenSrc > 0 && g_Config.SrcPath[lenSrc - 1] == L'\\')
    lenSrc--;
  wchar_t workSrc[MAX_PATH_EXT], workDst[MAX_PATH_EXT], tempNorm[MAX_PATH_EXT];
  BOOL srcNeedsNorm = (wcsncmp(g_Config.SrcPath, L"\\\\?\\", 4) != 0);
  BOOL dstNeedsNorm = (wcsncmp(g_Config.DstPath, L"\\\\?\\", 4) != 0);

  while (fgetws(line, MAX_PATH_EXT, fp)) {
    wchar_t *p = line;
    while (*p == L' ' || *p == L'\t') p++;
    size_t len = wcslen(p);
    while (len > 0 && (p[len - 1] == L'\n' || p[len - 1] == L'\r' || p[len - 1] == L' ' || p[len - 1] == L'\t'))
      p[--len] = L'\0';
    if (len == 0 || p[0] == L'#') continue;

    const wchar_t *rel = NULL;
    if (p[0] == L'\\' || (len >= 2 && p[1] == L':')) {
      if (lenSrc > 0 && len >= lenSrc && wcsncmp(p, g_Config.SrcPath, lenSrc) == 0 &&
          (p[lenSrc] == L'\\' || p[lenSrc] == L'\0')) {
        rel = p + lenSrc + (p[lenSrc] == L'\\' ? 1 : 0);
        StringCchCopyW(workSrc, MAX_PATH_EXT, p);
        if (srcNeedsNorm)
          NormalizePath(workSrc, tempNorm, MAX_PATH_EXT), StringCchCopyW(workSrc, MAX_PATH_EXT, tempNorm);
      } else
        continue;
    } else {
      StringCchPrintfW(workSrc, MAX_PATH_EXT, L"%ls\\%ls", g_Config.SrcPath, p);
      if (srcNeedsNorm)
        NormalizePath(workSrc, tempNorm, MAX_PATH_EXT), StringCchCopyW(workSrc, MAX_PATH_EXT, tempNorm);
      rel = p;
    }
    if (!rel || *rel == L'\0') continue;
    if (g_Config.FlattenDir) {
      const wchar_t *base = wcsrchr(rel, L'\\');
      base = base ? base + 1 : rel;
      StringCchPrintfW(workDst, MAX_PATH_EXT, L"%ls\\%ls", g_Config.DstPath, base);
    } else {
      StringCchPrintfW(workDst, MAX_PATH_EXT, L"%ls\\%ls", g_Config.DstPath, rel);
    }
    if (dstNeedsNorm)
      NormalizePath(workDst, tempNorm, MAX_PATH_EXT), StringCchCopyW(workDst, MAX_PATH_EXT, tempNorm);

    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(workSrc, GetFileExInfoStandard, &fad))
      continue;
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      ScanTask *st = AllocScanTask();
      if (!st) continue;
      size_t workSrcLen = wcslen(workSrc);
      size_t workDstLen = wcslen(workDst);
      st->SrcLen = (uint32_t)workSrcLen;
      st->DstLen = (uint32_t)workDstLen;
      if (workSrcLen < MAX_PATH && workDstLen < MAX_PATH) {
        StringCchCopyW(st->ShortSrc, MAX_PATH, workSrc);
        StringCchCopyW(st->ShortDst, MAX_PATH, workDst);
        st->SrcPath = st->ShortSrc;
        st->DstPath = st->ShortDst;
        st->pathFlags = TASK_PATH_FLAG_SRC_SHORT | TASK_PATH_FLAG_DST_SHORT;
      } else {
        st->SrcPath = StrDupTransient(workSrc, workSrcLen);
        st->DstPath = st->SrcPath ? StrDupTransient(workDst, workDstLen) : NULL;
        st->pathFlags = 0;  /* Round6 P1：malloc 路径 */
        if (!st->SrcPath || !st->DstPath) {
          FreeScanTask(st);
          continue;
        }
      }
      InterlockedIncrement(&g_PendingActive);
      if (g_Config.BfsScan && g_BfsScanQueue) {
        PushBfsScanTask(st);
        PostQueuedCompletionStatus(iocp, 0, KEY_SCAN_TASK, NULL);
      } else
        PostQueuedCompletionStatus(iocp, 0, KEY_SCAN_TASK, (LPOVERLAPPED)st);
      count++;
    } else {
      if (fad.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
        continue;
      CopyTask *ct = AllocCopyTask();
      if (ct) {
        size_t workSrcLen = wcslen(workSrc);
        size_t workDstLen = wcslen(workDst);
        ct->SrcLen = (uint32_t)workSrcLen;
        ct->DstLen = (uint32_t)workDstLen;
        if (workSrcLen < MAX_PATH && workDstLen < MAX_PATH) {
          StringCchCopyW(ct->ShortSrc, MAX_PATH, workSrc);
          StringCchCopyW(ct->ShortDst, MAX_PATH, workDst);
          ct->SrcPath = ct->ShortSrc;
          ct->DstPath = ct->ShortDst;
          ct->pathFlags = TASK_PATH_FLAG_SRC_SHORT | TASK_PATH_FLAG_DST_SHORT;
        } else {
          ct->SrcPath = StrDupTransient(workSrc, workSrcLen);
          ct->DstPath = ct->SrcPath ? StrDupTransient(workDst, workDstLen) : NULL;
          ct->pathFlags = 0;
          if (!ct->SrcPath || !ct->DstPath) {
            FreeCopyTask(ct);
            continue;
          }
        }
        ct->FileSize = (LONGLONG)fad.nFileSizeLow + ((LONGLONG)fad.nFileSizeHigh << 32);
        ct->CreationTime = fad.ftCreationTime;
        ct->LastAccessTime = fad.ftLastAccessTime;
        ct->LastWriteTime = fad.ftLastWriteTime;
        ct->FileAttributes = fad.dwFileAttributes;
        ct->pSrcBackend = VFS_GetBackend(g_Config.SrcPath);
        ct->pDstBackend = VFS_GetBackend(g_Config.DstPath);
        InterlockedIncrement(&g_TotalFound);
        InterlockedAdd64(&g_TotalFoundBytes, ct->FileSize);
        PostCopyTaskWithOverflow(NULL, ct, iocp);
        count++;
      }
    }
  }
  fclose(fp);
  wprintf(L"List mode: loaded %d paths from %ls\n", count, g_Config.ListFilePath);
  return count;
}

BOOL InitMemoryPools(int bigWorkers, int numCopiers) {
  /* 静态 CopyTask 槽：min(队列深度 + 每 Copier 弹匣余量×2, COPY_POOL_STATIC_MAX)。×sizeof 级 WS 硬顶，超出走弹性 _aligned_malloc */
  if (numCopiers < 1)
    numCopiers = 1;
  if (numCopiers > 64)
    numCopiers = 64;
  int copyTaskRequested;
  {
    LONG maxQ = READ_VOLATILE_32(&g_MaxQueueDepth);
    LONG64 req64 = (LONG64)maxQ + (LONG64)numCopiers * 2LL;
    if (req64 < 0)
      req64 = 0;
    if (req64 > INT_MAX)
      req64 = INT_MAX;
    copyTaskRequested = (int)req64;
  }
  int copyTaskStaticSlots = copyTaskRequested;
  if (copyTaskStaticSlots > COPY_POOL_STATIC_MAX)
    copyTaskStaticSlots = COPY_POOL_STATIC_MAX;

  int bigBufOk = 0, copyOk = 0, scanOk = 0, cleanupOk = 0;
  if (g_Config.BigBufferSizeMB > 0) {
    DWORD mb = (DWORD)g_Config.BigBufferSizeMB;
    if (mb > 256)
      mb = 256;
    g_BigBufferSize = mb * 1024 * 1024;
  }
  /* 物理扇区对齐：NO_BUFFERING 与 Large Pages 要求 */
  {
    DWORD align = (g_SectorSize > PHYSICAL_SECTOR_ALIGN) ? g_SectorSize : PHYSICAL_SECTOR_ALIGN;
    g_BigBufferSize = (g_BigBufferSize + align - 1) & ~(align - 1);
  }
  g_BigBufferPool = (PSLIST_HEADER)_aligned_malloc(sizeof(SLIST_HEADER), 16);
  g_CopyTaskPool = (PSLIST_HEADER)_aligned_malloc(sizeof(SLIST_HEADER), 16);
  g_DeadLetterQueue = (PSLIST_HEADER)_aligned_malloc(sizeof(SLIST_HEADER), 16);
  g_ScanTaskPool = (PSLIST_HEADER)_aligned_malloc(sizeof(SLIST_HEADER), 16);
  g_DirMetaStack = (PSLIST_HEADER)_aligned_malloc(sizeof(SLIST_HEADER), 16);
  g_DirMetaPool = (PSLIST_HEADER)_aligned_malloc(sizeof(SLIST_HEADER), 16);
  if (g_Config.CompareContent)
    g_VerifyTaskPool = (PSLIST_HEADER)_aligned_malloc(sizeof(SLIST_HEADER), 16);
  if (!g_BigBufferPool || !g_CopyTaskPool || !g_DeadLetterQueue || !g_ScanTaskPool || !g_DirMetaStack || !g_DirMetaPool) {
    if (g_BigBufferPool) { PB_ALIGNED_FREE(g_BigBufferPool); g_BigBufferPool = NULL; }
    if (g_CopyTaskPool) { PB_ALIGNED_FREE(g_CopyTaskPool); g_CopyTaskPool = NULL; }
    if (g_DeadLetterQueue) { PB_ALIGNED_FREE(g_DeadLetterQueue); g_DeadLetterQueue = NULL; }
    if (g_ScanTaskPool) { PB_ALIGNED_FREE(g_ScanTaskPool); g_ScanTaskPool = NULL; }
    if (g_DirMetaStack) { PB_ALIGNED_FREE(g_DirMetaStack); g_DirMetaStack = NULL; }
    if (g_DirMetaPool) { PB_ALIGNED_FREE(g_DirMetaPool); g_DirMetaPool = NULL; }
    if (g_VerifyTaskPool) { PB_ALIGNED_FREE(g_VerifyTaskPool); g_VerifyTaskPool = NULL; }
    wprintf(L"Fatal: _aligned_malloc failed for pool headers\n");
    return FALSE;
  }
  /* 提前启用 Large Pages：供 StringArena/BigBuffer/IoRingBuffer 等 ≥2MB 块使用 */
  if (!g_LargePagesAvailable) {
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
      TOKEN_PRIVILEGES tp = {0};
      if (LookupPrivilegeValueW(NULL, L"SeLockMemoryPrivilege", &tp.Privileges[0].Luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL))
          g_LargePagesAvailable = TRUE;
      }
      CloseHandle(hToken);
    }
  }
  /* P2 分片 + P3 溢出续接：4 个 Arena，每 Arena 链式 Chunk 可无限扩展 */
  memset(g_StringArenaShards, 0, sizeof(g_StringArenaShards));
  for (int i = 0; i < STRING_ARENA_SHARDS; i++) {
    StringArena *a = (StringArena *)calloc(1, sizeof(StringArena));
    if (a) {
      InitializeCriticalSection(&a->cs);
      ArenaChunk *chunk = (ArenaChunk *)calloc(1, sizeof(ArenaChunk));
      if (chunk) {
        chunk->data = (char *)AllocBufferWithLargePagesFallback(STRING_ARENA_CHUNK_SIZE);
        if (chunk->data) {
          chunk->capacity = STRING_ARENA_CHUNK_SIZE;
          a->head = a->current = chunk;
          g_StringArenaShards[i] = a;
        } else {
          free(chunk);
          DeleteCriticalSection(&a->cs);
          free(a);
        }
      } else {
        DeleteCriticalSection(&a->cs);
        free(a);
      }
    }
  }
  g_StringArena = g_StringArenaShards[0];  /* 兼容 */
  /* Phase 20 TLAB：纪元级释放，任务结束时 CleanupTlabGarbage */
  g_GlobalTlabGarbageList = (PSLIST_HEADER)_aligned_malloc(sizeof(SLIST_HEADER), 16);
  if (g_GlobalTlabGarbageList) {
    InitializeSListHead(g_GlobalTlabGarbageList);
    InitializeCriticalSection(&g_TlabChunkCs);
    g_TlabInitialized = TRUE;
  }
  InitializeSListHead(g_BigBufferPool);
  InitializeSListHead(g_CopyTaskPool);
  InitializeSListHead(g_DeadLetterQueue);
  InitializeSListHead(g_ScanTaskPool);
  InitializeSListHead(g_DirMetaStack);
  InitializeSListHead(g_DirMetaPool);
  for (int i = 0; i < bigWorkers * g_BigFileQD; i++) {
    BigBufferObj *obj = _aligned_malloc(sizeof(BigBufferObj), 16);
    if (obj) {
      obj->Buffer = (BYTE *)AllocBufferWithLargePagesFallback((SIZE_T)g_BigBufferSize);
      if (obj->Buffer) {
        /* P3 预缺页：强制触碰每页，消除 I/O 起跑时的软缺页顿挫。步进 64KB 兼顾大页与普通页 */
        for (SIZE_T off = 0; off < (SIZE_T)g_BigBufferSize; off += 65536)
          ((volatile char *)obj->Buffer)[off] = 0;
        /* VirtualLock：高负载下防止 I/O 缓冲被换出，消除缺页抖动。失败时静默降级 */
        if (VirtualLock(obj->Buffer, g_BigBufferSize))
          ; /* 锁定成功，I/O 吞吐更稳定 */
        InterlockedPushEntrySList(g_BigBufferPool, &obj->ItemEntry);
        bigBufOk++;
      } else
        PB_ALIGNED_FREE(obj);
    }
  }
  /* 迭代二：单块静态池，一次 _aligned_malloc 入池；COPY_POOL_STATIC_MAX 槽硬顶后超出走弹性 */
  {
    int capped = copyTaskStaticSlots;
    size_t blockSize = (size_t)capped * COPY_TASK_ALIGNED_SIZE;
    g_CopyTaskStaticBlock = (CopyTask *)_aligned_malloc(blockSize, 16);
    if (g_CopyTaskStaticBlock) {
      g_CopyTaskStaticTotalSize = blockSize;  /* 弹性兜底：边界判定用 */
      InitializeSListHead(g_CopyTaskPool);
      for (int i = 0; i < capped; i++) {
        CopyTask *t = (CopyTask *)((char *)g_CopyTaskStaticBlock +
            (size_t)i * COPY_TASK_ALIGNED_SIZE);
        memset(t, 0, sizeof(CopyTask));
        InterlockedPushEntrySList(g_CopyTaskPool, &t->ItemEntry);
        copyOk++;
      }
      if (capped < copyTaskRequested)
        wprintf(L"[INFO] CopyTask pool capped at %d slots (requested %d), remainder uses elastic fallback.\n",
                capped, copyTaskRequested);
    } else {
      wprintf(L"[WARN] CopyTask static block alloc failed (%zu MB), using elastic fallback only.\n",
              (size_t)(blockSize / (1024 * 1024)));
    }
  }
  /* 迭代二：ScanTask 单块静态池 */
  {
    size_t blockSize = (size_t)PREALLOC_SCAN_TASKS * SCAN_TASK_ALIGNED_SIZE;
    g_ScanTaskStaticBlock = (ScanTask *)_aligned_malloc(blockSize, 16);
    if (g_ScanTaskStaticBlock) {
      g_ScanTaskStaticTotalSize = blockSize;  /* 弹性兜底：边界判定用 */
      for (int i = 0; i < PREALLOC_SCAN_TASKS; i++) {
        ScanTask *t = (ScanTask *)((char *)g_ScanTaskStaticBlock +
            (size_t)i * SCAN_TASK_ALIGNED_SIZE);
        memset(t, 0, sizeof(ScanTask));
        InterlockedPushEntrySList(g_ScanTaskPool, &t->ItemEntry);
        scanOk++;
      }
      scanOk = PREALLOC_SCAN_TASKS;
    }
  }
  for (int i = 0; i < PREALLOC_DIR_META; i++) {
    DirMetaTask *t = (DirMetaTask *)_aligned_malloc(sizeof(DirMetaTask), 16);
    if (t) {
      memset(t, 0, sizeof(DirMetaTask));
      InterlockedPushEntrySList(g_DirMetaPool, &t->ItemEntry);
    }
  }
  if (g_VerifyTaskPool) {
    InitializeSListHead(g_VerifyTaskPool);
    for (int i = 0; i < PREALLOC_VERIFY_TASKS; i++) {
      VerifyTask *t = (VerifyTask *)_aligned_malloc(sizeof(VerifyTask), 16);
      if (t) {
        memset(t, 0, sizeof(VerifyTask));
        InterlockedPushEntrySList(g_VerifyTaskPool, &t->ItemEntry);
      }
    }
  }
  g_CleanupPool = (PSLIST_HEADER)_aligned_malloc(sizeof(SLIST_HEADER), 16);
  g_CleanupQueue = (PSLIST_HEADER)_aligned_malloc(sizeof(SLIST_HEADER), 16);
  if (!g_CleanupPool || !g_CleanupQueue) {
    if (g_CleanupPool) { PB_ALIGNED_FREE(g_CleanupPool); g_CleanupPool = NULL; }
    if (g_CleanupQueue) { PB_ALIGNED_FREE(g_CleanupQueue); g_CleanupQueue = NULL; }
    FreeAllPools();
    wprintf(L"Fatal: _aligned_malloc failed for Cleanup pool headers\n");
    return FALSE;
  }
  InitializeSListHead(g_CleanupPool);
  InitializeSListHead(g_CleanupQueue);
  for (int i = 0; i < 256; i++) {
    CleanupTask *t = (CleanupTask *)_aligned_malloc(sizeof(CleanupTask), 16);
    if (t) {
      t->Path = NULL;
      InterlockedPushEntrySList(g_CleanupPool, &t->ItemEntry);
      cleanupOk++;
    }
  }
  if (bigBufOk < bigWorkers * g_BigFileQD || copyOk < copyTaskStaticSlots ||
      scanOk < PREALLOC_SCAN_TASKS || cleanupOk < 256)
    wprintf(L"Warning: Memory pool prealloc partial (BigBuf:%d/%d Copy:%d/%d "
            L"Scan:%d/%d Cleanup:%d/256), may degrade under load.\n",
            bigBufOk, bigWorkers * g_BigFileQD, copyOk, copyTaskStaticSlots, scanOk,
            PREALLOC_SCAN_TASKS, cleanupOk);
  g_hCleanupEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
  if (!g_hCleanupEvent) {
    wprintf(L"Fatal: CreateEvent failed for Cleanup, err=%lu\n",
            (unsigned long)GetLastError());
    FreeAllPools();
    return FALSE;
  }
  g_hCleanupThread =
      (HANDLE)_beginthreadex(NULL, 0, CleanupThread, NULL, 0, NULL);
  if (!g_hCleanupThread) {
    wprintf(L"Warning: _beginthreadex failed for CleanupThread, err=%lu\n",
            (unsigned long)GetLastError());
  }
  return TRUE;
}

void FreeAllPools(void) {
  for (int i = 0; i < STRING_ARENA_SHARDS; i++) {
    StringArena *a = g_StringArenaShards[i];
    if (a) {
      ArenaChunk *c = a->head;
      while (c) {
        ArenaChunk *next = c->next;
        if (c->data) VirtualFree(c->data, 0, MEM_RELEASE);
        free(c);
        c = next;
      }
      DeleteCriticalSection(&a->cs);
      free(a);
      g_StringArenaShards[i] = NULL;
    }
  }
  g_StringArena = NULL;
  CleanupTlabGarbage();
  if (g_GlobalTlabGarbageList) {
    PB_ALIGNED_FREE(g_GlobalTlabGarbageList);
    g_GlobalTlabGarbageList = NULL;
  }
  if (g_TlabInitialized) {
    DeleteCriticalSection(&g_TlabChunkCs);
    g_TlabInitialized = FALSE;
  }
  if (g_LogEntryPool) {
    PSLIST_ENTRY e;
    while ((e = InterlockedPopEntrySList(g_LogEntryPool)) != NULL)
      PB_ALIGNED_FREE(e);
    PB_ALIGNED_FREE(g_LogEntryPool);
    g_LogEntryPool = NULL;
  }
  if (g_StatsEntryPool) {
    PSLIST_ENTRY e;
    while ((e = InterlockedPopEntrySList(g_StatsEntryPool)) != NULL)
      PB_ALIGNED_FREE(e);
    PB_ALIGNED_FREE(g_StatsEntryPool);
    g_StatsEntryPool = NULL;
  }
  if (g_CopyTaskPool) {
    /* 迭代二：单块静态内存，绝不 while(Pop) free(e)！仅 drain 链表后释放 header+块 */
    while (InterlockedPopEntrySList(g_CopyTaskPool) != NULL) { /* drain only */ }
    PB_ALIGNED_FREE(g_CopyTaskPool);
    g_CopyTaskPool = NULL;
  }
  if (g_DeadLetterQueue) {
    PSLIST_ENTRY e;
    while ((e = InterlockedPopEntrySList(g_DeadLetterQueue)) != NULL) {
      CopyTask *t = (CopyTask *)e;
      /* BUG-FIX：必须用 pathFlags 而非 IsArenaPtr。此时 Arena 已释放，IsArenaPtr 恒为 FALSE，
       * 会误对 Arena/VirtualAlloc 指针调用 free() 触发 0xc0000374 堆损坏。pathFlags 在任务创建时已记录。 */
      if (t->SrcPath && !(t->pathFlags & (TASK_PATH_FLAG_SRC_ARENA | TASK_PATH_FLAG_SRC_SHORT)))
        free(t->SrcPath);
      if (t->DstPath && !(t->pathFlags & (TASK_PATH_FLAG_DST_ARENA | TASK_PATH_FLAG_DST_SHORT)))
        free(t->DstPath);
      /* 弹性兜底：弹性溢出的任务需 _aligned_free，静态块中的随块释放 */
      if (g_CopyTaskStaticBlock && g_CopyTaskStaticTotalSize > 0 &&
          (char *)t >= (char *)g_CopyTaskStaticBlock &&
          (char *)t < (char *)g_CopyTaskStaticBlock + g_CopyTaskStaticTotalSize) {
        ; /* 静态块内，随 g_CopyTaskStaticBlock 一并释放 */
      } else {
        _aligned_free(t);
      }
    }
    PB_ALIGNED_FREE(g_DeadLetterQueue);
    g_DeadLetterQueue = NULL;
  }
  if (g_CopyTaskStaticBlock) {
    PB_ALIGNED_FREE(g_CopyTaskStaticBlock);
    g_CopyTaskStaticBlock = NULL;
    g_CopyTaskStaticTotalSize = 0;
  }
  if (g_ScanTaskPool) {
    /* 迭代二：单块静态内存，绝不 while(Pop) free(e)！仅 drain 后释放 */
    while (InterlockedPopEntrySList(g_ScanTaskPool) != NULL) { /* drain only */ }
    PB_ALIGNED_FREE(g_ScanTaskPool);
    g_ScanTaskPool = NULL;
  }
  if (g_ScanTaskStaticBlock) {
    PB_ALIGNED_FREE(g_ScanTaskStaticBlock);
    g_ScanTaskStaticBlock = NULL;
  }
  if (g_BfsScanQueue) {
    EnterCriticalSection(&g_BfsScanQueue->cs);
    while (g_BfsScanQueue->head) {
      ScanTask *t = g_BfsScanQueue->head;
      g_BfsScanQueue->head = t->ItemEntry.Next ? (ScanTask *)t->ItemEntry.Next : NULL;
      if (!g_BfsScanQueue->head) g_BfsScanQueue->tail = NULL;
      FreeScanTask(t);
      InterlockedDecrement(&g_PendingActive); /* 与 Push 时 +1 配对，避免池释放后计数悬空 */
    }
    LeaveCriticalSection(&g_BfsScanQueue->cs);
    if (g_BfsScanQueue->hSem) CloseHandle(g_BfsScanQueue->hSem);
    DeleteCriticalSection(&g_BfsScanQueue->cs);
    free(g_BfsScanQueue);
    g_BfsScanQueue = NULL;
  }
  if (g_DirMetaStack) {
    PSLIST_ENTRY e;
    while ((e = InterlockedPopEntrySList(g_DirMetaStack)) != NULL) {
      FreeDirMetaTask((DirMetaTask *)e);
    }
    PB_ALIGNED_FREE(g_DirMetaStack);
    g_DirMetaStack = NULL;
  }
  if (g_DirMetaPool) {
    PSLIST_ENTRY e;
    while ((e = InterlockedPopEntrySList(g_DirMetaPool)) != NULL)
      PB_ALIGNED_FREE(e);
    PB_ALIGNED_FREE(g_DirMetaPool);
    g_DirMetaPool = NULL;
  }
  if (g_VerifyTaskPool) {
    PSLIST_ENTRY e;
    while ((e = InterlockedPopEntrySList(g_VerifyTaskPool)) != NULL) {
      VerifyTask *vt = (VerifyTask *)e;
      if (vt->DstPath && vt->DstPath != vt->ShortDst)
        free(vt->DstPath);
      PB_ALIGNED_FREE(vt);
    }
    PB_ALIGNED_FREE(g_VerifyTaskPool);
    g_VerifyTaskPool = NULL;
  }
  if (g_BigBufferPool) {
    PSLIST_ENTRY e;
    while ((e = InterlockedPopEntrySList(g_BigBufferPool)) != NULL) {
      BigBufferObj *buf = (BigBufferObj *)e;
      if (buf->Buffer) {
        VirtualUnlock(buf->Buffer, g_BigBufferSize); /* 配对 VirtualLock，未锁时无副作用 */
        VirtualFree(buf->Buffer, 0, MEM_RELEASE);
      }
      PB_ALIGNED_FREE(buf);
    }
    PB_ALIGNED_FREE(g_BigBufferPool);
    g_BigBufferPool = NULL;
  }
  if (g_CleanupPool) {
    PSLIST_ENTRY e;
    while ((e = InterlockedPopEntrySList(g_CleanupPool)) != NULL) {
      CleanupTask *t = (CleanupTask *)e;
      if (t->Path)
        free(t->Path);
      PB_ALIGNED_FREE(t);
    }
    PB_ALIGNED_FREE(g_CleanupPool);
    g_CleanupPool = NULL;
  }
  if (g_CleanupQueue) {
    PSLIST_ENTRY e;
    while ((e = InterlockedPopEntrySList(g_CleanupQueue)) != NULL) {
      CleanupTask *t = (CleanupTask *)e;
      if (t->Path)
        free(t->Path);
      PB_ALIGNED_FREE(t);
    }
    PB_ALIGNED_FREE(g_CleanupQueue);
    g_CleanupQueue = NULL;
  }
}

/* OPT-07: 参数解析 wcstol 错误检测，无效时返回默认值 */
static int ParseIntSafe(const wchar_t *s, int defaultVal) {
  if (!s || !s[0]) return defaultVal;
  wchar_t *end;
  errno = 0;
  long v = wcstol(s, &end, 10);
  if (end == s || *end != L'\0' || errno == ERANGE || v < -2147483647 || v > 2147483647)
    return defaultVal;
  return (int)v;
}

/* P1: 解析日期过滤器 YYYYMMDD 或 YYYYMMDDhhmmss，返回可比较的整数 */
static LONGLONG ParseDateFilter(const wchar_t *s) {
  if (!s || !s[0]) return 0;
  int y = 0, m = 0, d = 0, hh = 0, mm = 0, ss = 0;
  if (swscanf(s, L"%4d%2d%2d%2d%2d%2d", &y, &m, &d, &hh, &mm, &ss) >= 3) {
    if (y < 1 || y > 9999) return 0;
    if (m < 1) m = 1; if (m > 12) m = 12;
    if (d < 1) d = 1; if (d > 31) d = 31;
    return (LONGLONG)y * 10000000000LL + (LONGLONG)m * 100000000LL +
           (LONGLONG)d * 1000000LL + (LONGLONG)hh * 10000LL +
           (LONGLONG)mm * 100LL + (LONGLONG)ss;
  }
  return 0;
}

/* P1: 解析大小过滤器 1K/1M/1G 或纯数字，返回字节数
 * QA 加固：errno 检测与乘法溢出防护，避免 999999T 等异常值 */
static LONGLONG ParseSizeFilter(const wchar_t *s) {
  if (!s || !s[0]) return -1;
  wchar_t *end = NULL;
  errno = 0;
  LONGLONG v;
#ifdef _MSC_VER
  v = _wcstoi64(s, &end, 10);
#else
  v = (LONGLONG)wcstoll(s, &end, 10);
#endif
  if (errno == ERANGE || v < 0) return -1;
  if (end && *end) {
    LONGLONG mult = 1;
    if (*end == L'K' || *end == L'k') mult = 1024;
    else if (*end == L'M' || *end == L'm') mult = 1024LL * 1024;
    else if (*end == L'G' || *end == L'g') mult = 1024LL * 1024 * 1024;
    else if (*end == L'T' || *end == L't') mult = 1024LL * 1024 * 1024 * 1024;
    if (mult > 1 && v > LLONG_MAX / mult) return -1;  /* 溢出防护 */
    v *= mult;
  }
  return v >= 0 ? v : -1;
}

/* 将 FILETIME 转为可比较的 yyyymmddhhmmss 整数 */
static LONGLONG FileTimeToCompare(const FILETIME *ft) {
  SYSTEMTIME st;
  if (!FileTimeToSystemTime(ft, &st))
    return 0;
  return (LONGLONG)st.wYear * 10000000000LL + (LONGLONG)st.wMonth * 100000000LL +
         (LONGLONG)st.wDay * 1000000LL + (LONGLONG)st.wHour * 10000LL +
         (LONGLONG)st.wMinute * 100LL + (LONGLONG)st.wSecond;
}

/* P1: 日期/大小过滤器，返回 FALSE 表示应跳过该文件；lastWrite 可为 LARGE_INTEGER* 或 FILETIME* */
static BOOL PassesDateSizeFilter(LONGLONG fileSize, const void *lastWrite) {
  const LARGE_INTEGER *li = (const LARGE_INTEGER *)lastWrite;
  /* fileSize < 0：USN 推迟取大小，仅过日期过滤；大小在 Copier 打开后再筛 */
  if (fileSize >= 0) {
    if (g_Config.MinSizeFilter >= 0 && fileSize < g_Config.MinSizeFilter)
      return FALSE;
    if (g_Config.MaxSizeFilter >= 0 && fileSize > g_Config.MaxSizeFilter)
      return FALSE;
  }
  if (g_Config.FromDateFilter > 0 || g_Config.ToDateFilter > 0) {
    FILETIME ft;
    ft.dwLowDateTime = li->LowPart;
    ft.dwHighDateTime = (DWORD)li->HighPart;
    LONGLONG cmp = FileTimeToCompare(&ft);
    if (g_Config.FromDateFilter > 0 && cmp < g_Config.FromDateFilter)
      return FALSE;
    if (g_Config.ToDateFilter > 0 && cmp > g_Config.ToDateFilter)
      return FALSE;
  }
  return TRUE;
}

static void EnableBackupPrivileges(void) {
  HANDLE hToken;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
    struct {
      DWORD PrivilegeCount;
      LUID_AND_ATTRIBUTES Privileges[5];
    } tp;
    tp.PrivilegeCount = g_Config.CopyAllSecurity ? 5 : 3;
    if (LookupPrivilegeValueW(NULL, SE_BACKUP_NAME, &tp.Privileges[0].Luid) &&
        LookupPrivilegeValueW(NULL, SE_RESTORE_NAME, &tp.Privileges[1].Luid) &&
        LookupPrivilegeValueW(NULL, SE_MANAGE_VOLUME_NAME, &tp.Privileges[2].Luid)) {
      tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
      tp.Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;
      tp.Privileges[2].Attributes = SE_PRIVILEGE_ENABLED;
      if (g_Config.CopyAllSecurity &&
          LookupPrivilegeValueW(NULL, SE_SECURITY_NAME, &tp.Privileges[3].Luid) &&
          LookupPrivilegeValueW(NULL, SE_TAKE_OWNERSHIP_NAME, &tp.Privileges[4].Luid)) {
        tp.Privileges[3].Attributes = SE_PRIVILEGE_ENABLED;
        tp.Privileges[4].Attributes = SE_PRIVILEGE_ENABLED;
      }
      AdjustTokenPrivileges(hToken, FALSE, (PTOKEN_PRIVILEGES)&tp, 0, NULL, NULL);
    }
    CloseHandle(hToken);
  }
}

/* Phase 18 去抖动：强物理页面保留，钳制 Working Set Trimmer，需 -H 显式启用 */
#ifndef QUOTA_LIMITS_HARDWS_MIN_ENABLE
#define QUOTA_LIMITS_HARDWS_MIN_ENABLE 0x00000001
#endif
#ifndef QUOTA_LIMITS_HARDWS_MAX_DISABLE
#define QUOTA_LIMITS_HARDWS_MAX_DISABLE 0x00000008
#endif
static void TrySetHardWorkingSet(void) {
  if (!g_Config.HardWorkingSet) return;
  typedef BOOL (WINAPI *PSetProcessWorkingSetSizeEx)(HANDLE, SIZE_T, SIZE_T, DWORD);
  PSetProcessWorkingSetSizeEx pFn = (PSetProcessWorkingSetSizeEx)GetProcAddress(
      GetModuleHandleW(L"kernel32.dll"), "SetProcessWorkingSetSizeEx");
  if (!pFn) return;
  SIZE_T minWS = 1024ULL * 1024 * 1024;   /* 1GB 核心缓冲硬下限 */
  SIZE_T maxWS = 2048ULL * 1024 * 1024;   /* 2GB 软上限 */
  DWORD flags = QUOTA_LIMITS_HARDWS_MIN_ENABLE | QUOTA_LIMITS_HARDWS_MAX_DISABLE;
  if (pFn(GetCurrentProcess(), minWS, maxWS, flags))
    wprintf(L"[Phase 18] Hard working set: min 1GB enabled\n");
}

/* 若未以管理员运行则请求 UAC 提权并重新启动，用于 Defender 排除等
 * QA 加固：StringCchCatW 防 params 溢出，超长命令行放弃提权 */
static BOOL TryElevateToAdmin(int argc, wchar_t *argv[]) {
  if (IsUserAnAdmin()) return FALSE;
  wchar_t selfPath[MAX_PATH];
  if (GetModuleFileNameW(NULL, selfPath, MAX_PATH) == 0) return FALSE;
  wchar_t params[32768];
  params[0] = L'\0';
  for (int i = 1; i < argc && argv[i]; i++) {
    if (i > 1 && FAILED(StringCchCatW(params, 32768, L" ")))
      break;
    if (wcschr(argv[i], L' ') != NULL) {
      if (FAILED(StringCchCatW(params, 32768, L"\"")) ||
          FAILED(StringCchCatW(params, 32768, argv[i])) ||
          FAILED(StringCchCatW(params, 32768, L"\"")))
        break;
    } else {
      if (FAILED(StringCchCatW(params, 32768, argv[i])))
        break;
    }
  }
  INT_PTR ret = (INT_PTR)ShellExecuteW(NULL, L"runas", selfPath, params[0] ? params : NULL, NULL, SW_SHOW);
  if (ret > 32) return TRUE;
  return FALSE;
}

/* 检测是否需要管理员：-mft_scan/-mft_raw/-copyall 需 NTFS 底层或完整 ACL 克隆 */
static BOOL NeedsAdminRights(int argc, wchar_t *argv[]) {
  for (int i = 1; i < argc && argv[i]; i++) {
    if (argv[i][0] != L'-') continue;
    if (wcscmp(argv[i], L"-mft_scan") == 0 || wcscmp(argv[i], L"-mft_raw") == 0 ||
        wcscmp(argv[i], L"-copyall") == 0)
      return TRUE;
  }
  return FALSE;
}

/* 用户显式请求：自动将源/目标加入 Defender 排除项（需管理员）；与 NeedsAdminRights 分离，避免普通复制弹 UAC */
static BOOL NeedsDefenderExclusionOptIn(int argc, wchar_t *argv[]) {
  for (int i = 1; i < argc && argv[i]; i++) {
    if (argv[i][0] != L'-') continue;
    if (_wcsicmp(argv[i], L"-defender-exclude") == 0)
      return TRUE;
  }
  return FALSE;
}

/* 提权前窥探 -P：GUI 子进程禁止 ShellExecute runas（否则管道/SHM 生命周期断裂） */
static DWORD PeekParentPidFromArgv(int argc, wchar_t *argv[]) {
  for (int i = 1; i < argc && argv[i]; i++) {
    if (wcsncmp(argv[i], L"-P", 2) != 0) continue;
    if (argv[i][2] == L'=' || argv[i][2] == L':')
      return (DWORD)ParseIntSafe(argv[i] + 3, 0);
    if (argv[i][2] == L'\0' && i + 1 < argc)
      return (DWORD)ParseIntSafe(argv[i + 1], 0);
  }
  return 0;
}

int wmain(int argc, wchar_t *argv[]) {
    // 【新增】1. 进程启动第一件事：激活底层磁盘与备份特权
    EnablePrivilege(SE_BACKUP_NAME);         // 允许读取绕过文件权限限制
    EnablePrivilege(SE_RESTORE_NAME);        // 允许写入绕过文件权限限制（可选，但建议加上）
    EnablePrivilege(SE_MANAGE_VOLUME_NAME);  // 允许执行底层的卷管理操作 (MFT/USN 强依赖)
  for (int i = 1; i < argc; i++) {
    if (!argv[i]) continue;  /* QA：防御 argv 异常/恶意构造 */
    if (argv[i][0] == L'-' && argv[i][1] == L'h' && argv[i][2] == L'\0') {
      PrintHelp();
      return 0;
    }
  }
  {
    DWORD parentHint = PeekParentPidFromArgv(argc, argv);
    BOOL needAdmin = NeedsAdminRights(argc, argv) || NeedsDefenderExclusionOptIn(argc, argv);
    if (parentHint != 0) {
      /* GUI 已挂 -P：禁止自提权；缺权限则明确失败，让用户提升 GUI */
      if (needAdmin && !IsUserAnAdmin()) {
        wprintf(L"[ERR] Administrator rights required for this job, but engine was started "
                L"by GUI (-P %lu). Relaunch PB X-Flow GUI as Administrator.\n",
                (unsigned long)parentHint);
        return 1;
      }
    } else {
      if (NeedsAdminRights(argc, argv) && TryElevateToAdmin(argc, argv)) return 0;
      if (NeedsDefenderExclusionOptIn(argc, argv) && TryElevateToAdmin(argc, argv)) return 0;
    }
  }

  InitSyncFunctions();  /* D7：动态加载 WaitOnAddress / WakeByAddressAll（Win8+）*/
  setvbuf(stdout, NULL, _IONBF, 0);  /* CLI 实时进度：无缓冲，wprintf 立即显示到控制台 */
  { /* 管道输出强制 UTF-8，与 GUI ENGINE_STDOUT_ENCODING=utf-8 对齐 */
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut && hOut != INVALID_HANDLE_VALUE && GetFileType(hOut) != FILE_TYPE_CHAR)
      _setmode(_fileno(stdout), _O_U8TEXT);
  }
  { /* Win10+：启用 ANSI/VT，[RUN] 在 stdout 为 Pipe 时仍可清行单行刷新 */
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode;
    if (h && h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode))
      SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
  }
  SetUnhandledExceptionFilter(CrashExceptionFilter);  /* 崩溃时写 pb_xflow_exit_debug.txt */
  { wchar_t tmp[MAX_PATH];
    if (GetTempPathW(MAX_PATH, tmp) > 0) {
      StringCchCatW(tmp, MAX_PATH, L"pb_xflow_exit_debug.txt");
      StringCchCopyW(g_ExitDebugPath, MAX_PATH, tmp);
      wprintf(L"[INFO] Exit debug file: %ls\n", g_ExitDebugPath);
    }
  }

  srand((unsigned)time(NULL)); /* 重试抖动 rand 种子 */
  /* 提前解析 -copyall，以便 EnableBackupPrivileges 启用 SE_SECURITY/SE_TAKE_OWNERSHIP */
  for (int i = 1; i < argc; i++) {
    if (!argv[i]) continue;
    if (argv[i][0] == L'-' && wcscmp(argv[i], L"-copyall") == 0) {
      g_Config.CopyAllSecurity = TRUE;
      g_Config.CopyAcl = TRUE;
      break;
    }
  }
  EnableBackupPrivileges();
  g_Config.ThreadCountNormal = 64;
  g_Config.ThreadCountIdle = 64;
  g_Config.StartHour = -1;
  g_Config.EndHour = -1;
  g_Config.RefreshInterval = 500;
  g_Config.RealTimeStats = TRUE;
  g_Config.LogVerbosity = LOG_INFO;
  g_Config.MaxQueueDepth = 30000;
  g_Config.BigFileQD = 0;
  g_Config.BigBufferSizeMB = 32;
  GetCurrentDirectoryW(MAX_PATH, g_Config.LogPath);
  StringCchCopyW(g_Config.NormalLogName, MAX_PATH, L"PBXFlowNormal.log");
  StringCchCopyW(g_Config.ErrorLogName, MAX_PATH, L"PBXFlowError.log");

  g_Config.MinSizeFilter = -1;
  g_Config.MaxSizeFilter = -1;
  g_Config.VerifyErrRename = TRUE;  /* 默认校验错误时重命名 */

  for (int i = 1; i < argc; i++) {
    if (!argv[i]) continue;
    if (argv[i][0] == L'-' && wcscmp(argv[i], L"-preflight") == 0) {
      g_Config.Preflight = TRUE;
      continue;
    }
    if (argv[i][0] == L'-' && wcscmp(argv[i], L"-no_space_preflight") == 0) {
      g_Config.SkipSpacePreflight = TRUE;
      continue;
    }
    if (argv[i][0] == L'-' && wcscmp(argv[i], L"-precount") == 0) {
      g_Config.AuditPrecount = TRUE;
      continue;
    }
    if (argv[i][0] == L'-' && wcscmp(argv[i], L"-audit_only") == 0) {
      g_Config.AuditOnly = TRUE;
      g_Config.AuditMode = AUDIT_MODE_SRC;
      continue;
    }
    if (argv[i][0] == L'-' && wcscmp(argv[i], L"-audit") == 0) {
      if (i + 1 >= argc) {
        wprintf(L"Error: -audit requires an argument: src | dst | full\n");
        return 1;
      }
      i++;
      g_Config.AuditOnly = TRUE;
      if (_wcsicmp(argv[i], L"src") == 0)
        g_Config.AuditMode = AUDIT_MODE_SRC;
      else if (_wcsicmp(argv[i], L"dst") == 0)
        g_Config.AuditMode = AUDIT_MODE_DST;
      else if (_wcsicmp(argv[i], L"full") == 0)
        g_Config.AuditMode = AUDIT_MODE_FULL;
      else {
        wprintf(L"Error: -audit argument must be src, dst, or full\n");
        return 1;
      }
      continue;
    }
    /* Round4 P2 架构3：SetFileValidData 合规开关，默认关闭
     * 断电/BSOD 后目标文件含旧磁盘扇区历史数据（Data Leakage），金融/医疗合规场景禁用。
     * 仅明确知情并传入此参数时才启用，启动时写入审计警告日志。 */
    if (argv[i][0] == L'-' && wcscmp(argv[i], L"-unsafe_fast_alloc") == 0) {
      g_Config.UnsafeFastAlloc = TRUE;
      continue;
    }
    if (argv[i][0] == L'-' && wcscmp(argv[i], L"-write_through") == 0) {
      g_Config.WriteThroughBigFiles = TRUE;
      continue;
    }
    if (argv[i][0] == L'-' && wcsncmp(argv[i], L"-from_date=", 11) == 0) {
      g_Config.FromDateFilter = ParseDateFilter(argv[i] + 11);
      continue;
    }
    if (argv[i][0] == L'-' && wcsncmp(argv[i], L"-to_date=", 9) == 0) {
      g_Config.ToDateFilter = ParseDateFilter(argv[i] + 9);
      continue;
    }
    if (argv[i][0] == L'-' && wcsncmp(argv[i], L"-min_size=", 10) == 0) {
      g_Config.MinSizeFilter = ParseSizeFilter(argv[i] + 10);
      continue;
    }
    if (argv[i][0] == L'-' && wcsncmp(argv[i], L"-max_size=", 10) == 0) {
      g_Config.MaxSizeFilter = ParseSizeFilter(argv[i] + 10);
      continue;
    }
    if (argv[i][0] == L'-' && wcsncmp(argv[i], L"-job=", 5) == 0) {
      StringCchCopyW(g_Config.JobName, MAX_PATH, argv[i] + 5);
      continue;
    }
    if (argv[i][0] == L'-' && wcscmp(argv[i], L"-perfect_verify") == 0) {
      g_Config.PerfectVerify = TRUE;
      g_Config.CompareContent = TRUE;
      continue;
    }
    if (argv[i][0] == L'-' && wcscmp(argv[i], L"-no_verify_rename") == 0) {
      g_Config.VerifyErrRename = FALSE;
      continue;
    }
    if (argv[i][0] == L'-' && wcscmp(argv[i], L"-verifyinfo") == 0) {
      g_Config.AddVerifyInfo = TRUE;
      g_Config.CompareContent = TRUE;
      continue;
    }
    if (argv[i][0] == L'-' && wcsncmp(argv[i], L"-directio_threshold=", 19) == 0) {
      g_Config.DirectIoThresholdMB = ParseIntSafe(argv[i] + 19, 0);
      continue;
    }
    if (argv[i][0] == L'-' && wcscmp(argv[i], L"-zero-skip") == 0) {
      g_Config.UseZeroSkip = TRUE;
      continue;
    }
    if (argv[i][0] == L'-' && wcscmp(argv[i], L"-mft_scan") == 0) {
      g_Config.UseMftScan = TRUE;
      continue;
    }
    if (argv[i][0] == L'-' && wcscmp(argv[i], L"-mft_raw") == 0) {
      g_Config.UseMftRawScan = TRUE;
      continue;
    }
    if (argv[i][0] == L'-' && wcsncmp(argv[i], L"-checkpoint_interval=", 20) == 0) {
      int v = ParseIntSafe(argv[i] + 20, 300);
      g_Config.CheckpointIntervalSec = (v > 86400) ? 86400 : (v < 0 ? 0 : v);
      continue;
    }
    if (argv[i][0] == L'-' && wcsncmp(argv[i], L"-checkpoint_gb=", 14) == 0) {
      int v = ParseIntSafe(argv[i] + 14, 100);
      g_Config.CheckpointIntervalGB = (v > 1000) ? 1000 : (v < 1 ? 0 : (LONGLONG)v);
      continue;
    }
    if (argv[i][0] == L'-' && wcscmp(argv[i], L"-resume") == 0) {
      /* 产品契约：checkpoint 仅遥测进度，无 per-file 续传；避免运维误判 */
      wprintf(L"[WARN] -resume is not implemented (pb_xflow_resume.dat is progress-only). "
              L"Ignoring -resume; use -Y for incremental sync.\n");
      g_Config.ResumeMode = FALSE;
      continue;
    }
    if (argv[i][0] == L'-' && wcscmp(argv[i], L"-no_ads") == 0) {
      g_Config.SkipAds = TRUE;
      continue;
    }
    if (argv[i][0] == L'-' && wcscmp(argv[i], L"-move") == 0) {
      g_Config.IsMoveMode = TRUE;
      continue;
    }
    if (argv[i][0] == L'-' && wcscmp(argv[i], L"-delete") == 0) {
      g_Config.IsDeleteMode = TRUE;
      continue;
    }
    if (argv[i][0] == L'-' && wcsncmp(argv[i], L"-ipg", 4) == 0) {
      if (argv[i][4] == L'=' || argv[i][4] == L':')
        g_Config.IpGapMs = ParseIntSafe(argv[i] + 5, 0);
      else if (argv[i][4] == L'\0' && i + 1 < argc)
        g_Config.IpGapMs = ParseIntSafe(argv[++i], 0);
      else if (argv[i][4] == L'\0')
        g_Config.IpGapMs = 10;  /* 默认 10ms */
      continue;
    }
    if (argv[i][0] == L'-' && wcscmp(argv[i], L"-copyall") == 0) {
      g_Config.CopyAllSecurity = TRUE;
      g_Config.CopyAcl = TRUE;
      continue;
    }
    if (argv[i][0] == L'-' && wcscmp(argv[i], L"-rh_strict") == 0) {
      g_Config.RunHoursStrict = TRUE;
      continue;
    }
    if (argv[i][0] == L'-' && wcscmp(argv[i], L"-hard_ws") == 0) {
      g_Config.HardWorkingSet = TRUE;  /* V9：-H 冲突修复，独立选项强物理页面保留 */
      continue;
    }
    if (argv[i][0] == L'-' && wcscmp(argv[i], L"-host_aware") == 0) {
      g_Config.HostAware = TRUE;  /* Phase 20: 系统负载高时主动降速 */
      continue;
    }
    if (argv[i][0] == L'-' && wcsncmp(argv[i], L"-sample_threshold", 16) == 0) {
      const wchar_t *v = (argv[i][16] == L'=' || argv[i][16] == L':') ? argv[i] + 17 : L"5";
      int gb = ParseIntSafe(v, 5);
      if (gb < 1) gb = 1;
      if (gb > 1024) gb = 1024;
      g_Config.SampleThresholdGB = gb;
      continue;
    }
    if (argv[i][0] == L'-' && wcsncmp(argv[i], L"-sample_random", 13) == 0) {
      const wchar_t *v = (argv[i][13] == L'=' || argv[i][13] == L':') ? argv[i] + 14 : L"6";
      int n = ParseIntSafe(v, 6);
      if (n < 0) n = 0;
      if (n > 32) n = 32;
      g_Config.SampleRandomBlocks = n;
      continue;
    }
    if (argv[i][0] == L'-' && wcslen(argv[i]) == 2) {
      wchar_t opt = argv[i][1];
      if (opt == L'h') {
        PrintHelp();
        return 0;
      }
      if (opt == L's' && i + 1 < argc)
        NormalizePath(argv[++i], g_Config.SrcPath, MAX_PATH_EXT);
      else if (opt == L'd' && i + 1 < argc)
        NormalizePath(argv[++i], g_Config.DstPath, MAX_PATH_EXT);
      else if (opt == L't' && i + 1 < argc) {
        int v = ParseIntSafe(argv[++i], 64);
        g_Config.ThreadCountNormal = (v > 64) ? 64 : (v < 1 ? 1 : v);
      }
      else if (opt == L'T' && i + 1 < argc) {
        int v = ParseIntSafe(argv[++i], 64);
        g_Config.ThreadCountIdle = (v > 64) ? 64 : (v < 1 ? 1 : v);
      }
      else if (opt == L'b' && i + 1 < argc)
        g_Config.StartHour = ParseIntSafe(argv[++i], -1);
      else if (opt == L'e' && i + 1 < argc)
        g_Config.EndHour = ParseIntSafe(argv[++i], -1);
      else if (opt == L'f' && i + 1 < argc)
        StringCchCopyW(g_Config.FileFilter, MAX_PATH, argv[++i]);
      else if (opt == L'i')
        g_Config.FlattenDir = TRUE;
      else if (opt == L'M')
        g_Config.MetadataOnly = TRUE;
      else if (opt == L'S')
        g_Config.SampleLargeFiles = TRUE;
      else if (opt == L'c')
        g_Config.CaseInsensitive = TRUE;
      else if (opt == L'p' && i + 1 < argc)
        StringCchCopyW(g_Config.LogPath, MAX_PATH, argv[++i]);
      else if (opt == L'N' && i + 1 < argc)
        StringCchCopyW(g_Config.NormalLogName, MAX_PATH, argv[++i]);
      else if (opt == L'E' && i + 1 < argc)
        StringCchCopyW(g_Config.ErrorLogName, MAX_PATH, argv[++i]);
      else if (opt == L'I' && i + 1 < argc)
        g_Config.RefreshInterval = ParseIntSafe(argv[++i], 500);
      else if (opt == L'F')
        g_Config.FastMode = TRUE;
      else if (opt == L'J')
        g_Config.UseIoRing = TRUE;
      else if (opt == L'j' && i + 1 < argc) {
        g_IoRingBatchSize = ParseIntSafe(argv[++i], 64);
        if (g_IoRingBatchSize < 1) g_IoRingBatchSize = 1;
        if (g_IoRingBatchSize > 2048) g_IoRingBatchSize = 2048; /* 大 batch 需 8MB 缓冲容纳，小文件可试 -j 512 */
      }       else if (opt == L'H')
        g_Config.HighPriority = TRUE;
      else if (opt == L'U')
        g_Config.LowIoPriority = TRUE;  /* P0: 低 I/O 优先级 */
      else if (opt == L'G' && i + 1 < argc)
        g_Config.TimeAllowMs = ParseIntSafe(argv[++i], 0);  /* P1: 时间戳容差 ms */
      else if (opt == L'L' && i + 1 < argc) {
        int v = ParseIntSafe(argv[++i], 0);
        g_Config.SpeedLimitMB = (v > 10000) ? 10000 : (v < 0 ? 0 : v);
      }
      else if (opt == L'Q' && i + 1 < argc) {
        int v = ParseIntSafe(argv[++i], 30000);
        g_Config.MaxQueueDepth = (v > 1000000) ? 1000000 : (v < 1 ? 30000 : v);
      }
      else if (opt == L'q' && i + 1 < argc)
        g_Config.BigFileQD = ParseIntSafe(argv[++i], 0);
      else if (opt == L'B' && i + 1 < argc) {
        int v = ParseIntSafe(argv[++i], 32);
        g_Config.BigBufferSizeMB = (v > 1024) ? 1024 : (v < 0 ? 0 : v);
      }
      else if (opt == L'R')
        g_Config.RealTimeStats = TRUE;
      else if (opt == L'm')
        g_Config.CompareMTime = TRUE;
      else if (opt == L'C')
        g_Config.CompareSize = TRUE;
      else if (opt == L'D')
        g_Config.CompareContent = TRUE;
      else if (opt == L'X') {
        g_Config.CompareContent = TRUE;
        g_Config.UseXxh3 = TRUE;
      } else if (opt == L'A')
        g_Config.CopyAcl = TRUE;
      else if (opt == L'V')
        g_Config.UseVss = TRUE;
      else if (opt == L'K')
        g_Config.MirrorDelete = TRUE;
      else if (opt == L'O')
        g_Config.OrderByPhysical = TRUE;
      else if (_wcsicmp(argv[i], L"-bfs") == 0)
        g_Config.BfsScan = TRUE;  /* Phase 10: 广度优先扫描，HDD 同级 MFT 预热 */
      else if (opt == L'W')
        g_Config.CpuAffinity = TRUE;
      /* -H 仅 HighPriority；HardWorkingSet 用 -hard_ws */
      else if (opt == L'Y')
        g_Config.UseDeltaTransfer = TRUE;
      else if (opt == L'l' && i + 1 < argc)
        NormalizePath(argv[++i], g_Config.ListFilePath, MAX_PATH_EXT);
      else if (opt == L'z')
        g_Config.Quiet = TRUE;
      else if (opt == L'P' && i + 1 < argc)
        g_Config.ParentPid = (DWORD)ParseIntSafe(argv[++i], 0);
      else if (opt == L'Z' && i + 1 < argc) {
        i++; /* 消费参数，避免误解析；-Z 已移除（会改变目标结构） */
        wprintf(L"Warning: -Z removed (changed dest structure), ignored\n");
      }
    }
  }

  if (g_Config.AuditOnly) {
    if (g_Config.AuditMode == AUDIT_MODE_NONE)
      g_Config.AuditMode = AUDIT_MODE_SRC;
    /* 审计模式强制只读校验：禁用所有会触发目标写入的业务开关 */
    g_Config.CompareContent = TRUE;
    g_Config.UseXxh3 = TRUE;
    g_Config.MetadataOnly = FALSE;
    g_Config.IsMoveMode = FALSE;
    g_Config.IsDeleteMode = FALSE;
    g_Config.MirrorDelete = FALSE;
    g_Config.UseDeltaTransfer = FALSE;
    g_Config.CopyAcl = FALSE;
    g_Config.CopyAllSecurity = FALSE;
    g_Config.FastMode = FALSE;
    g_Config.UseVss = FALSE;
  }

  /* P3: 任务模板 -job=name 从 ini 加载，命令行参数优先 */
  if (wcslen(g_Config.JobName) > 0) {
    wchar_t iniPath[MAX_PATH] = L"pb_xflow.ini";
    wchar_t buf[MAX_PATH_EXT];
    GetPrivateProfileStringW(g_Config.JobName, L"Src", L"", buf, MAX_PATH_EXT, iniPath);
    if (wcslen(buf) > 0 && wcslen(g_Config.SrcPath) == 0)
      NormalizePath(buf, g_Config.SrcPath, MAX_PATH_EXT);
    GetPrivateProfileStringW(g_Config.JobName, L"Dst", L"", buf, MAX_PATH_EXT, iniPath);
    if (wcslen(buf) > 0 && wcslen(g_Config.DstPath) == 0)
      NormalizePath(buf, g_Config.DstPath, MAX_PATH_EXT);
    int jt = GetPrivateProfileIntW(g_Config.JobName, L"Threads", 0, iniPath);
    if (jt > 0 && g_Config.ThreadCountNormal == 64)
      g_Config.ThreadCountNormal = jt;
    int jb = GetPrivateProfileIntW(g_Config.JobName, L"Buffer", 0, iniPath);
    if (jb > 0 && g_Config.BigBufferSizeMB == 32)
      g_Config.BigBufferSizeMB = jb;
    if (GetPrivateProfileIntW(g_Config.JobName, L"Fast", -1, iniPath) == 1)
      g_Config.FastMode = TRUE;
    if (GetPrivateProfileIntW(g_Config.JobName, L"IoRing", -1, iniPath) == 1)
      g_Config.UseIoRing = TRUE;
    if (GetPrivateProfileIntW(g_Config.JobName, L"WriteThrough", -1, iniPath) == 1)
      g_Config.WriteThroughBigFiles = TRUE;
  }

  /* 根路径统一 \\?\ 绝对形式，传统扫描 CreateFile 才能贯穿 >260 字符子树。
   * 交叉验证预期（与 dir \\?\ 全量对比时）：
   * - 无 -mft_scan：计数会明显高于旧版，但若遍历遇单点 ACCESS_DENIED/损坏仍 return/break，
   *   会截断其后子树，可能仍低于基准；卡在中间值多属权限墙而非“计数回归恶化”。
   * - -mft_scan：USN V3 解析后应大幅补齐；若仍差一小撮，常见为 8.3 短名导致前缀匹配偏差，
   *   需后续 GetLongPathNameW 等增强，非 V3 解析本身回退。 */
  if (wcslen(g_Config.SrcPath) > 0)
    ApplyLongPathRootToConfig(g_Config.SrcPath, MAX_PATH_EXT);
  if (wcslen(g_Config.DstPath) > 0)
    ApplyLongPathRootToConfig(g_Config.DstPath, MAX_PATH_EXT);

  if (wcslen(g_Config.FileFilter) > 0) {
    g_Config.HasFilter = TRUE;
    StringCchCopyW(g_Config.FileFilterLower, MAX_PATH, g_Config.FileFilter);
    if (g_Config.CaseInsensitive)
      _wcslwr(g_Config.FileFilterLower);
    g_FilterExtCount = 0;
    { wchar_t buf[MAX_PATH];
      wchar_t *ctx = NULL;
      StringCchCopyW(buf, MAX_PATH, g_Config.FileFilterLower);
      for (wchar_t *tok = wcstok(buf, L";", &ctx); tok && g_FilterExtCount < FILTER_EXT_MAX; tok = wcstok(NULL, L";", &ctx)) {
        int n = (int)wcslen(tok);
        if (n <= 0 || n >= 128) continue;
        if (n <= 4) {
          UINT64 raw = 0;
          memcpy(&raw, tok, (size_t)n * sizeof(wchar_t));
          g_FilterExts[g_FilterExtCount].hash = raw;
          g_FilterExts[g_FilterExtCount].len = n;
        } else {
          g_FilterExts[g_FilterExtCount].hash = (UINT64)XXH3_64bits(tok, (size_t)n * sizeof(wchar_t));
          g_FilterExts[g_FilterExtCount].len = n;
        }
        g_FilterExtCount++;
      }
    }
  } else {
    g_Config.HasFilter = FALSE;
    g_FilterExtCount = 0;
  }
  if (g_Config.ThreadCountNormal < 1)
    g_Config.ThreadCountNormal = 1;
  if (g_Config.ThreadCountIdle < 1)
    g_Config.ThreadCountIdle = 1;
  int numCopiers = (g_Config.ThreadCountNormal > g_Config.ThreadCountIdle)
                       ? g_Config.ThreadCountNormal
                       : g_Config.ThreadCountIdle;
  if (numCopiers > 64) {
    wprintf(L"Warning: thread count clamped to 64 (max supported)\n");
    numCopiers = 64;
    if (g_Config.ThreadCountNormal > 64) g_Config.ThreadCountNormal = 64;
    if (g_Config.ThreadCountIdle > 64) g_Config.ThreadCountIdle = 64;
  }
  /* IOCP 黄金法则：NumberOfConcurrentThreads=核心数，避免惊群/上下文切换 */
  SYSTEM_INFO si;
  GetSystemInfo(&si);
  int iocpConcurrent = (int)si.dwNumberOfProcessors;
  if (iocpConcurrent < 1) iocpConcurrent = 1;

  if (g_Config.IsDeleteMode) {
    if (wcslen(g_Config.SrcPath) == 0) {
      wprintf(L"Error: -delete mode requires -s <path>.\n");
      PrintHelp();
      return 1;
    }
    if (GetFileAttributesW(g_Config.SrcPath) == INVALID_FILE_ATTRIBUTES) {
      wprintf(L"Error: Path to delete does not exist: %ls\n", g_Config.SrcPath);
      return 1;
    }
    return RunFastDeleteMode();
  }
  if (wcslen(g_Config.SrcPath) == 0 || wcslen(g_Config.DstPath) == 0) {
    wprintf(L"Error: -s and -d are required.\n");
    PrintHelp();
    return 1;
  }
  if (wcslen(g_Config.LogPath) == 0)
    GetCurrentDirectoryW(MAX_PATH, g_Config.LogPath);
  if (g_Config.MaxQueueDepth > 0)
    g_MaxQueueDepth = g_Config.MaxQueueDepth;
  else
    g_MaxQueueDepth = (10000 > numCopiers * 500) ? 10000 : numCopiers * 500;
#if HAS_VSS
  if (g_Config.UseVss) {
    if (!CreateVssSnapshotAndReplaceSrcPath()) {
      wprintf(L"Error: VSS snapshot creation failed.\n");
      return 1;
    }
  }
#endif
  if (wcslen(g_Config.SrcPath) > 0)
    ApplyLongPathRootToConfig(g_Config.SrcPath, MAX_PATH_EXT);
  if (GetFileAttributesW(g_Config.SrcPath) == INVALID_FILE_ATTRIBUTES) {
    wprintf(L"Error: Source path invalid.\n");
    return 1;
  }
  if (!g_Config.AuditOnly) {
    if (!CreateDirectoryW(g_Config.DstPath, NULL) &&
        GetLastError() != ERROR_ALREADY_EXISTS)
      wprintf(L"Warning: CreateDirectoryW failed for %ls, err=%lu\n",
              g_Config.DstPath, (unsigned long)GetLastError());
  }
  /* P3 元数据缓存：DstDir 根路径预填充，EnsureParentDirExists 零网络查询 */
  AddDstDirCache(g_Config.DstPath);
  if (GetFileAttributesW(g_Config.DstPath) == INVALID_FILE_ATTRIBUTES) {
    wprintf(L"Error: Destination path inaccessible.\n");
    return 1;
  }
  if (g_Config.AuditOnly) {
    AuditReportInit();
    if (g_Config.AuditPrecount) {
      wprintf(L"[AUDIT] -precount: synchronous recursive file count (can take minutes on huge trees)...\n");
      g_AuditDestFileCount = CountRegularFilesRecursive(g_Config.DstPath);
      g_AuditPeerCountInit = CountRegularFilesRecursive(g_Config.SrcPath);
      wprintf(L"[AUDIT] Target tree file count (recursive): %ld\n", (long)g_AuditDestFileCount);
      wprintf(L"[AUDIT] Source tree file count (recursive): %ld\n", (long)g_AuditPeerCountInit);
    } else {
      g_AuditDestFileCount = -1;
      g_AuditPeerCountInit = -1;
      wprintf(L"[AUDIT] Pre-count skipped (default). Use -precount if you need synchronous tree totals before scan.\n");
      wprintf(L"[AUDIT] Authoritative baseline file count is g_TotalFound at completion (streaming enumeration).\n");
    }
  }

  /* 仅 -defender-exclude：尝试 Add-MpPreference 排除源/目标（需管理员；非管理员时启动阶段已可弹 UAC） */
  if (NeedsDefenderExclusionOptIn(argc, argv)) {
    if (!IsUserAnAdmin()) {
      wprintf(L"[WARN] Defender exclusion skipped: not running as Administrator "
              L"(use -defender-exclude and approve UAC, or run elevated).\n");
    } else {
      wprintf(L"[INFO] Adding paths to Windows Defender exclusions...\n");
      BOOL r1 = AddDefenderExclusionsPair(g_Config.SrcPath, g_Config.DstPath);
      BOOL r2 = r1; /* pair 一次完成；保留变量供下方日志兼容 */
      if (!r1 || !r2)
        wprintf(L"[INFO] Defender tip: Windows Security → Virus & threat protection → "
                L"Manage settings → Exclusions → Add or remove exclusions.\n");
    }
  }

  InitializeCriticalSection(&g_PidCs);
  if (!InitializeCriticalSectionEx(&g_LogCs, 0, 0)) {
    wprintf(L"Fatal: InitializeCriticalSectionEx failed, err=%lu\n",
            GetLastError());
    return 1;
  }
  wchar_t normalLogPath[MAX_PATH_EXT], errorLogPath[MAX_PATH_EXT];
  StringCchPrintfW(normalLogPath, MAX_PATH_EXT, L"%ls\\%ls", g_Config.LogPath,
                   g_Config.NormalLogName);
  StringCchPrintfW(errorLogPath, MAX_PATH_EXT, L"%ls\\%ls", g_Config.LogPath,
                   g_Config.ErrorLogName);
  g_fNormalLog = _wfopen(normalLogPath, L"a, ccs=UTF-8");
  g_fErrorLog = _wfopen(errorLogPath, L"a, ccs=UTF-8");
  if (!g_fNormalLog)
    wprintf(L"Warning: _wfopen failed for normal log: %ls\n", normalLogPath);
  if (!g_fErrorLog)
    wprintf(L"Warning: _wfopen failed for error log: %ls\n", errorLogPath);

  g_LogQueue = (PSLIST_HEADER)_aligned_malloc(sizeof(SLIST_HEADER), 16);
  g_LogEntryPool = (PSLIST_HEADER)_aligned_malloc(sizeof(SLIST_HEADER), 16);
  g_StatsEntryPool = (PSLIST_HEADER)_aligned_malloc(sizeof(SLIST_HEADER), 16);
  if (!g_LogQueue || !g_LogEntryPool || !g_StatsEntryPool) {
    if (g_LogQueue) { PB_ALIGNED_FREE(g_LogQueue); g_LogQueue = NULL; }
    if (g_LogEntryPool) { PB_ALIGNED_FREE(g_LogEntryPool); g_LogEntryPool = NULL; }
    if (g_StatsEntryPool) { PB_ALIGNED_FREE(g_StatsEntryPool); g_StatsEntryPool = NULL; }
    if (g_fNormalLog) fclose(g_fNormalLog);
    if (g_fErrorLog) fclose(g_fErrorLog);
    DeleteCriticalSection(&g_LogCs);
    wprintf(L"Fatal: _aligned_malloc failed for Log pool headers\n");
    return 1;
  }
  InitializeSListHead(g_LogQueue);
  InitializeSListHead(g_LogEntryPool);
  InitializeSListHead(g_StatsEntryPool);
  for (int i = 0; i < 4; i++) {
    LogEntry *se = (LogEntry *)_aligned_malloc(sizeof(LogEntry), 16);
    if (se) InterlockedPushEntrySList(g_StatsEntryPool, &se->ItemEntry);
  }
  /* D8 优化：日志池大小由固定 1024 改为 numCopiers×16，适配实际并发线程数。
   * 64 线程下从 1024 → 1024 条（恰好相等），但也支持更高 threadCount 场景。
   * 最低 1024，最高 4096，避免极少数线程时过小或极多线程时过大。 */
  {
    int numCopiers = (g_Config.ThreadCountNormal > g_Config.ThreadCountIdle)
        ? g_Config.ThreadCountNormal : g_Config.ThreadCountIdle;
    if (numCopiers > 64) numCopiers = 64;
    int logPoolSize = numCopiers * 16;
    if (logPoolSize < 1024) logPoolSize = 1024;
    if (logPoolSize > 4096) logPoolSize = 4096;
    for (int i = 0; i < logPoolSize; i++) {
      LogEntry *e = (LogEntry *)_aligned_malloc(sizeof(LogEntry), 16);
      if (e)
        InterlockedPushEntrySList(g_LogEntryPool, &e->ItemEntry);
    }
  }
  g_hLogEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
  if (!g_hLogEvent) {
    if (g_LogQueue) { PB_ALIGNED_FREE(g_LogQueue); g_LogQueue = NULL; }
    if (g_LogEntryPool) {
      PSLIST_ENTRY e;
      while ((e = InterlockedPopEntrySList(g_LogEntryPool)) != NULL)
        PB_ALIGNED_FREE(e);
      PB_ALIGNED_FREE(g_LogEntryPool);
      g_LogEntryPool = NULL;
    }
    if (g_StatsEntryPool) {
      PSLIST_ENTRY e;
      while ((e = InterlockedPopEntrySList(g_StatsEntryPool)) != NULL)
        PB_ALIGNED_FREE(e);
      PB_ALIGNED_FREE(g_StatsEntryPool);
      g_StatsEntryPool = NULL;
    }
    if (g_fNormalLog) fclose(g_fNormalLog);
    if (g_fErrorLog) fclose(g_fErrorLog);
    DeleteCriticalSection(&g_LogCs);
    wprintf(L"Fatal: CreateEvent failed for Log, err=%lu\n",
            (unsigned long)GetLastError());
    return 1;
  }
  g_hLogThread = (HANDLE)_beginthreadex(NULL, 0, LogThread, NULL, 0, NULL);
  if (!g_hLogThread) {
    wprintf(L"Warning: _beginthreadex failed for LogThread, err=%lu\n",
            (unsigned long)GetLastError());
  }

  SetConsoleCtrlHandler(CtrlHandler, TRUE);
  InitPerformanceCounters();
  if (g_PdhQuery) {
    g_hOsTelemetryStopEvent = CreateEvent(NULL, FALSE, FALSE, NULL);  /* N8：手动重置事件 */
    g_hOsTelemetryThread = (HANDLE)_beginthreadex(NULL, 0, OsTelemetryThread, NULL, 0, NULL);
    if (!g_hOsTelemetryThread) g_hOsTelemetryThread = NULL;
  }
  {
    /* 动态物理扇区：兼容 512B/4K/8K/16K 企业级阵列；源/目 IOCTL 均成功才允许大文件 NO_BUFFERING。
     * 审计模式下 CopyTask 可能把 baseline/peer 映射到 SrcPath/DstPath 字段，但此处始终用命令行 -s/-d 探测几何，避免张冠李戴。 */
    BOOL trSrc = FALSE, trDst = FALSE;
    DWORD srcSector = ProbePhysicalSectorSizeTrusted(g_Config.SrcPath, &trSrc);
    DWORD dstSector = ProbePhysicalSectorSizeTrusted(g_Config.DstPath, &trDst);
    g_SectorSize = (srcSector >= dstSector) ? srcSector : dstSector;
    if (g_SectorSize == 0)
      g_SectorSize = 4096;
    g_BigFileUseDirectIo = trSrc && trDst;
    if (!g_BigFileUseDirectIo)
      wprintf(L"[INFO] Direct I/O: sector alignment IOCTL not fully confirmed (UNC, network, or driver miss). "
              L"Large files use buffered copy; see IoStrategy summary at exit.\n");
  }
  InitSameVolumeCache(g_Config.SrcPath, g_Config.DstPath);
  g_Config.IsSSD = IsSSD(g_Config.DstPath);
  /* 介质自适应 -O：SSD/NVMe 无寻道惩罚，物理排序浪费 O(N log N)，自动禁用 */
  if (g_Config.OrderByPhysical && g_Config.IsSSD) {
    g_Config.OrderByPhysical = FALSE;
    wprintf(L"[INFO] -O disabled (target is SSD, no seek penalty)\n");
  }
  if (g_Config.IsMoveMode && !g_IsSameVolume) {
    g_MoveSourceDirsList = (PSLIST_HEADER)_aligned_malloc(sizeof(SLIST_HEADER), 16);
    if (g_MoveSourceDirsList) {
      InitializeSListHead(g_MoveSourceDirsList);
      InitializeCriticalSectionEx(&g_MoveSourceDirsCs, 0, 0);
    }
  }

  /* 智能自适应大文件 I/O 深度：HDD 防磁头寻道风暴，网络填 BDP */
  if (g_Config.BigFileQD > 0) {
    g_BigFileQD = g_Config.BigFileQD;
    if (g_BigFileQD > BIGFILE_QUEUE_DEPTH_MAX)
      g_BigFileQD = BIGFILE_QUEUE_DEPTH_MAX;
  } else {
    if (g_Config.IsFtpSource || g_Config.IsFtpDest ||
        (g_Config.DstPath[0] == L'\\' && g_Config.DstPath[1] == L'\\') ||
        (g_Config.SrcPath[0] == L'\\' && g_Config.SrcPath[1] == L'\\'))
      g_BigFileQD = 16;
    else if (g_Config.IsSSD)
      g_BigFileQD = 8;
    else
      g_BigFileQD = 2;
  }

  InitNtApi();  /* 迭代一：NtCreateFile 相对路径，1 亿文件零 VFS 解析风暴 */
  if (g_Config.UseIoRing) {
    g_IoRingAvailable = IoRingProbe();
    if (!g_IoRingAvailable)
      wprintf(L"Warning: IoRing not available (need Win11/Server2022+), -J disabled\n");
  }
  CopyFile2Probe(); /* Win8+ CopyFile2：ODX/块克隆加速，兜底路径优先使用 */
  if (g_Config.UseZeroSkip)
    ProbeAVX2();    /* -zero-skip 时 AVX2 零块检测加速 */
  if (g_Config.CpuAffinity)
    ProbePECoreTopology();  /* -W 时 P/E-Core 拓扑，12 代+ 绑定工作线程到 P-Core */
  InitMmcss();  /* Phase 18：MMCSS Pro-Audio，主线程提前加载 avrt.dll */
  if (g_Config.HighPriority)
    SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS);
  TrySetHardWorkingSet();  /* Phase 18：-H 时强物理页面保留，1GB 硬下限 */
  g_ActiveCopierLimit = g_Config.ThreadCountNormal;
  BOOL isNetwork = IsUncPath(g_Config.DstPath) || IsUncPath(g_Config.SrcPath) ||
                   g_Config.IsFtpSource || g_Config.IsFtpDest;
  int maxBigWorkers = (numCopiers < 4) ? numCopiers :
      (isNetwork ? 16 : (g_Config.IsSSD ? 8 : 4));
  g_hBigFileSemaphore =
      CreateSemaphore(NULL, maxBigWorkers, maxBigWorkers, NULL);
  g_hMMFMapSemaphore = CreateSemaphore(NULL, MMF_HIGH_WATER_MB, MMF_HIGH_WATER_MB, NULL);
  if (!g_hBigFileSemaphore || !g_hMMFMapSemaphore) {
    if (g_hMMFMapSemaphore) { CloseHandle(g_hMMFMapSemaphore); g_hMMFMapSemaphore = NULL; }
    if (g_hBigFileSemaphore) { CloseHandle(g_hBigFileSemaphore); g_hBigFileSemaphore = NULL; }
    g_LogThreadRunning = FALSE;
    SetEvent(g_hLogEvent);
    if (g_hLogThread) {
      WaitForSingleObject(g_hLogThread, INFINITE);
      CloseHandle(g_hLogThread);
    }
    if (g_hOsTelemetryThread) {
      if (g_hOsTelemetryStopEvent) SetEvent(g_hOsTelemetryStopEvent);  /* N8：立即唤醒 */
      WaitForSingleObject(g_hOsTelemetryThread, 3000);
      CloseHandle(g_hOsTelemetryThread);
      g_hOsTelemetryThread = NULL;
    }
    if (g_hOsTelemetryStopEvent) { CloseHandle(g_hOsTelemetryStopEvent); g_hOsTelemetryStopEvent = NULL; }
    if (g_LogEntryPool) {
      PSLIST_ENTRY e;
      while ((e = InterlockedPopEntrySList(g_LogEntryPool)) != NULL)
        PB_ALIGNED_FREE(e);
      PB_ALIGNED_FREE(g_LogEntryPool);
    }
    if (g_StatsEntryPool) {
      PSLIST_ENTRY e;
      while ((e = InterlockedPopEntrySList(g_StatsEntryPool)) != NULL)
        PB_ALIGNED_FREE(e);
      PB_ALIGNED_FREE(g_StatsEntryPool);
    }
    if (g_LogQueue) PB_ALIGNED_FREE(g_LogQueue);
    if (g_hLogEvent) CloseHandle(g_hLogEvent);
    if (g_fNormalLog) fclose(g_fNormalLog);
    if (g_fErrorLog) fclose(g_fErrorLog);
    DeleteCriticalSection(&g_LogCs);
    wprintf(L"Fatal: CreateSemaphore failed, err=%lu\n",
            (unsigned long)GetLastError());
    return 1;
  }
  if (!InitMemoryPools(maxBigWorkers, numCopiers)) {
    FreeAllPools();
    if (g_LogQueue)
      PB_ALIGNED_FREE(g_LogQueue);
    if (g_hLogEvent)
      CloseHandle(g_hLogEvent);
    if (g_hCleanupEvent)
      CloseHandle(g_hCleanupEvent);
    CloseHandle(g_hBigFileSemaphore);
    if (g_hMMFMapSemaphore) CloseHandle(g_hMMFMapSemaphore);
    if (g_fNormalLog)
      fclose(g_fNormalLog);
    if (g_fErrorLog)
      fclose(g_fErrorLog);
    DeleteCriticalSection(&g_LogCs);
    return 1;
  }

  HANDLE iocp =
      CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, iocpConcurrent);
  if (!iocp) {
    g_LogThreadRunning = FALSE;
    SetEvent(g_hLogEvent);
    if (g_hLogThread) {
      WaitForSingleObject(g_hLogThread, INFINITE);
      CloseHandle(g_hLogThread);
    }
    if (g_hOsTelemetryThread) {
      if (g_hOsTelemetryStopEvent) SetEvent(g_hOsTelemetryStopEvent);
      WaitForSingleObject(g_hOsTelemetryThread, 3000);
      CloseHandle(g_hOsTelemetryThread);
      g_hOsTelemetryThread = NULL;
    }
    if (g_hOsTelemetryStopEvent) { CloseHandle(g_hOsTelemetryStopEvent); g_hOsTelemetryStopEvent = NULL; }
    g_CleanupThreadRunning = FALSE;
    SetEvent(g_hCleanupEvent);
    if (g_hCleanupThread) {
      WaitForSingleObject(g_hCleanupThread, INFINITE);
      CloseHandle(g_hCleanupThread);
    }
    FreeAllPools();
    if (g_LogQueue) PB_ALIGNED_FREE(g_LogQueue);
    if (g_hLogEvent) CloseHandle(g_hLogEvent);
    if (g_hCleanupEvent) CloseHandle(g_hCleanupEvent);
    CloseHandle(g_hBigFileSemaphore);
    if (g_hMMFMapSemaphore) CloseHandle(g_hMMFMapSemaphore);
    if (g_fNormalLog) fclose(g_fNormalLog);
    if (g_fErrorLog) fclose(g_fErrorLog);
    DeleteCriticalSection(&g_LogCs);
    wprintf(L"Fatal: CreateIoCompletionPort failed, err=%lu\n",
            (unsigned long)GetLastError());
    return 1;
  }
  QueryPerformanceFrequency(&g_Freq);
  QueryPerformanceCounter(&g_StartTime);
  timeBeginPeriod(1);  /* 1ms QoS：消除 15.6ms 默认分辨率导致的微爆发，百兆/千兆 WAN 限速平滑 */

  /* BUG-C2 修复：TLS slot 在主线程启动工作线程之前统一分配，避免 64 线程并发 TlsAlloc 竞争/泄漏 */
  if (g_TlsTokenSlot == TLS_OUT_OF_INDEXES)
    g_TlsTokenSlot = TlsAlloc();
  /* Round4 P2 架构1：Arena 分片 TLS 槽同步分配，保证所有工作线程都能使用均匀路由 */
  if (g_TlsArenaShardSlot == TLS_OUT_OF_INDEXES)
    g_TlsArenaShardSlot = TlsAlloc();

  if (g_Config.SpeedLimitMB > 0) {
    g_SpeedLimitBps = (LONG64)g_Config.SpeedLimitMB * 1024 * 1024;
    g_TokenThreadRunning = 1;
    g_hTokenThread =
        (HANDLE)_beginthreadex(NULL, 0, TokenBucketThread, NULL, 0, NULL);
    if (!g_hTokenThread) {
      g_TokenThreadRunning = 0;
      wprintf(L"Warning: TokenBucketThread failed, -L disabled\n");
    }
  }

  if (g_Config.CompareContent && g_VerifyTaskPool) {
    /* 动态验证扩展：按 CPU 核心数 4~16 自适应，匹配 NVMe 带宽与 MD5/XXH3 算力 */
    {
      SYSTEM_INFO si;
      GetSystemInfo(&si);
      int n = (int)(si.dwNumberOfProcessors / 4);
      g_NumVerifyThreads = (n < 4) ? 4 : n; /* 完全跟随核心数，NUMA 多节点自适应 */
    }
    g_hVerifyIocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, g_NumVerifyThreads);
    if (g_hVerifyIocp) {
      g_hVerifyThreads = (HANDLE *)malloc(g_NumVerifyThreads * sizeof(HANDLE));
      g_VerifyParams = (VerifyParam **)calloc(g_NumVerifyThreads, sizeof(VerifyParam *));
      if (g_hVerifyThreads) {
        for (int i = 0; i < g_NumVerifyThreads; i++) {
          VerifyParam *vp = NULL;
          if (g_VerifyParams) {
            vp = (VerifyParam *)calloc(1, sizeof(VerifyParam));
            if (vp) {
              if (g_Config.UseXxh3)
                vp->Xxh3State = XXH3_createState();
              vp->HashBuffer = (BYTE *)VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT, PAGE_READWRITE);
              if (!vp->HashBuffer || (g_Config.UseXxh3 && !vp->Xxh3State)) {
                if (vp->Xxh3State) { XXH3_freeState(vp->Xxh3State); vp->Xxh3State = NULL; }
                if (vp->HashBuffer) { VirtualFree(vp->HashBuffer, 0, MEM_RELEASE); vp->HashBuffer = NULL; }
                if (vp->hIoRingVerify && g_pCloseIoRing) { g_pCloseIoRing(vp->hIoRingVerify); vp->hIoRingVerify = NULL; }
                if (vp->IoRingSampleBuf) { VirtualFree(vp->IoRingSampleBuf, 0, MEM_RELEASE); vp->IoRingSampleBuf = NULL; }
                free(vp);
                vp = NULL;
              }
            }
            g_VerifyParams[i] = vp;
          }
          g_hVerifyThreads[i] = (HANDLE)_beginthreadex(NULL, 0, VerifyThread, vp, 0, NULL);
        }
      } else if (g_VerifyParams) {
        free(g_VerifyParams);
        g_VerifyParams = NULL;
      }
    }
  }

// 获取当前时间
  SYSTEMTIME startSt;
  GetLocalTime(&startSt);

  // 把这里的 wprintf 全部替换为 PrintAndLog，并加入时间和命令行的打印
  PrintAndLog(L"===============================================================\n");
  PrintAndLog(L" PB X-Flow\n");
  if (g_Config.AuditOnly) {
    PrintAndLog(L" Mode: AUDIT (read-only; no writes to destination)\n");
    if (g_Config.AuditMode == AUDIT_MODE_SRC)
      PrintAndLog(L" Audit profile: src (baseline=source, peer=target; Extra pass off)\n");
    else if (g_Config.AuditMode == AUDIT_MODE_DST)
      PrintAndLog(L" Audit profile: dst (baseline=target, peer=source)\n");
    else if (g_Config.AuditMode == AUDIT_MODE_FULL)
      PrintAndLog(L" Audit profile: full (baseline=source + Extra pass on target)\n");
  }
  PrintAndLog(L" RunTime: %04d-%02d-%02d %02d:%02d:%02d\n", startSt.wYear, startSt.wMonth, startSt.wDay, startSt.wHour, startSt.wMinute, startSt.wSecond);
  PrintAndLog(L" CmdLine: %ls\n", GetCommandLineW());
  {
    wchar_t dispSrc[MAX_PATH_EXT], dispDst[MAX_PATH_EXT];
    PathForDisplayW(g_Config.SrcPath, dispSrc, MAX_PATH_EXT);
    PathForDisplayW(g_Config.DstPath, dispDst, MAX_PATH_EXT);
    PrintAndLog(L" Src: %ls\n Dst: %ls\n", dispSrc, dispDst);
  }
  PrintAndLog(L" Threads: %d (Normal), %d (Idle)\n", g_Config.ThreadCountNormal, g_Config.ThreadCountIdle);
  if (g_Config.StartHour >= 0 && g_Config.EndHour >= 0)
    PrintAndLog(L" Schedule: %02d:00 - %02d:00\n", g_Config.StartHour,
            g_Config.EndHour);
  PrintAndLog(L" Buffer: %lu MB | Queue: %ld | BigFile QD: %d\n",
          (unsigned long)(g_BigBufferSize / (1024 * 1024)),
          (long)g_MaxQueueDepth, g_BigFileQD);
  if (g_Config.FastMode)
    PrintAndLog(L" Fast Mode: ON\n");
  if (g_Config.SkipAds)
    PrintAndLog(L" Skip ADS: ON (-no_ads)\n");
  if (g_Config.HighPriority)
    PrintAndLog(L" High Priority: ON\n");
  if (g_Config.CompareContent)
    PrintAndLog(L" Content verify: %ls\n", g_Config.UseXxh3 ? L"XXH3 (~10GB/s)" : L"MD5");
  if (g_Config.SampleLargeFiles) {
    int gb = g_Config.SampleThresholdGB > 0 ? g_Config.SampleThresholdGB : SAMPLE_DEFAULT_THRESHOLD_GB;
    int n = g_Config.SampleRandomBlocks > 0 ? g_Config.SampleRandomBlocks : SAMPLE_DEFAULT_RANDOM_BLOCKS;
    PrintAndLog(L" Large file sampling: ON (>%dGB: 20MB + %d*10MB)\n", gb, n);
  }
  if (g_Config.UseIoRing && g_IoRingAvailable) {
    if (g_Config.AuditOnly)
      PrintAndLog(L" IoRing batch: configured (-j %d) — not used for copy in audit-only\n",
          g_IoRingBatchSize);
    else
      PrintAndLog(L" IoRing batch: ON (<1MB files, -j %d)\n", g_IoRingBatchSize);
  }
  if (g_Config.UseMftRawScan)
    PrintAndLog(L" MFT Raw: ON (direct $MFT read, bypass VFS)\n");
  if (g_Config.UseMftScan && !g_Config.UseMftRawScan)
    PrintAndLog(L" MFT/USN scan: ON\n");
  if (g_CopyFile2Available) {
    if (g_Config.AuditOnly)
      PrintAndLog(L" CopyFile2: available — not used in audit-only (no destination copy)\n");
    else
      PrintAndLog(L" CopyFile2: ON (ODX/block clone fallback)\n");
  }
  if (g_Config.CpuAffinity)
    PrintAndLog(L" CPU affinity: ON (worker threads pinned to cores)\n");
  if (g_Config.HardWorkingSet)
    PrintAndLog(L" Hard working set: ON (1GB min, Phase 18)\n");
  if (g_Config.SpeedLimitMB > 0)
    PrintAndLog(L" Speed Limit: %d MB/s\n", g_Config.SpeedLimitMB);
  if (g_Config.UseVss)
    PrintAndLog(L" VSS snapshot: ON (Enterprise)\n");
  if (wcslen(g_Config.FileFilter) > 0)
    PrintAndLog(L" Filter: %ls\n", g_Config.FileFilter);
  if (g_Config.FlattenDir)
    PrintAndLog(L" Flatten: ON\n");
  PrintAndLog(L"===============================================================\n");
  setvbuf(stdout, NULL, _IONBF, 0);

  g_NumThreadBuckets = numCopiers;  /* Phase 8 原子桶：启用分布式计数 */

  if (g_TlsCopierParamSlot == TLS_OUT_OF_INDEXES)
    g_TlsCopierParamSlot = TlsAlloc();
  HANDLE *hW = (HANDLE *)malloc(numCopiers * sizeof(HANDLE));
  CopierParam **params =
      (CopierParam **)malloc(numCopiers * sizeof(CopierParam *));
  if (!hW || !params) {
    free(hW);
    free(params);
    wprintf(L"Fatal: malloc failed for workers\n");
    return 1;
  }
  int numCreated = 0;
  for (int i = 0; i < numCopiers; i++) {
    CopierParam *p = (CopierParam *)_aligned_malloc(sizeof(CopierParam), 64);
    if (!p) {
      wprintf(L"Fatal: calloc failed for worker %d\n", i);
      for (int j = 0; j < i; j++) {
        if (params[j]->hIoRing && g_pCloseIoRing)
          g_pCloseIoRing(params[j]->hIoRing);
        if (params[j]->Xxh3State)
          XXH3_freeState(params[j]->Xxh3State);
        if (params[j]->IoRingBuffer)
          VirtualFree(params[j]->IoRingBuffer, 0, MEM_RELEASE);
        if (params[j]->HashBuffer)
          VirtualFree(params[j]->HashBuffer, 0, MEM_RELEASE);
        free(params[j]->IoRingBatch);
        free(params[j]->IoRingBatchOk);
        free(params[j]->IoRingHandleSrc);
        free(params[j]->IoRingHandleDst);
        free(params[j]->IoRingBufs);
        free(params[j]->IoRingReadOk);
        free(params[j]->IoRingWriteOk);
        free(params[j]->IoRingRegHandles);
        free(params[j]->IoRingSrcHashes);
        if (params[j]->SdCacheBlob) free(params[j]->SdCacheBlob);
        PB_ALIGNED_FREE(params[j]);
      }
      free(params);
      free(hW);
      return 1;
    }
    memset(p, 0, sizeof(CopierParam));
    /* IoRingBuffer/HashBuffer 延后至 CopierThread 内分配，-W 时可用 VirtualAllocExNuma 绑定 NUMA 节点 */
    p->IoRingBuffer = NULL;
    if (g_Config.UseIoRing && g_IoRingAvailable && g_pCreateIoRing) {
      p->IoRingBatch      = (CopyTask **)malloc((size_t)g_IoRingBatchSize * sizeof(CopyTask *));
      p->IoRingBatchOk    = (BOOL *)    malloc((size_t)g_IoRingBatchSize * sizeof(BOOL));
      p->IoRingHandleSrc  = (HANDLE *)  malloc((size_t)g_IoRingBatchSize * sizeof(HANDLE));
      p->IoRingHandleDst  = (HANDLE *)  malloc((size_t)g_IoRingBatchSize * sizeof(HANDLE));
      p->IoRingBufs       = (BYTE **)   malloc((size_t)g_IoRingBatchSize * sizeof(BYTE *));
      p->IoRingReadOk     = (BOOL *)    malloc((size_t)g_IoRingBatchSize * sizeof(BOOL));
      p->IoRingWriteOk    = (BOOL *)    malloc((size_t)g_IoRingBatchSize * sizeof(BOOL));
      /* N6：预分配 2×BatchSize 句柄注册数组，消除 CopySmallFilesBatchIoRing 每批 malloc/free */
      p->IoRingRegHandles = (HANDLE *)  malloc((size_t)(2 * g_IoRingBatchSize) * sizeof(HANDLE));
      p->IoRingSrcHashes  = (BYTE *)    malloc((size_t)g_IoRingBatchSize * 8);
      if (p->IoRingBatch && p->IoRingBatchOk && p->IoRingHandleSrc && p->IoRingHandleDst &&
          p->IoRingBufs && p->IoRingReadOk && p->IoRingWriteOk && p->IoRingRegHandles) {
        IORING_CREATE_FLAGS flags = {0, 0};
        if (FAILED(g_pCreateIoRing(1, flags, g_IoRingQueueSize, g_IoRingQueueSize, &p->hIoRing)))
          p->hIoRing = NULL;
      } else {
        if (p->IoRingBatch)     { free(p->IoRingBatch);     p->IoRingBatch     = NULL; }
        if (p->IoRingBatchOk)   { free(p->IoRingBatchOk);   p->IoRingBatchOk   = NULL; }
        if (p->IoRingHandleSrc) { free(p->IoRingHandleSrc); p->IoRingHandleSrc = NULL; }
        if (p->IoRingHandleDst) { free(p->IoRingHandleDst); p->IoRingHandleDst = NULL; }
        if (p->IoRingBufs)      { free(p->IoRingBufs);      p->IoRingBufs      = NULL; }
        if (p->IoRingReadOk)    { free(p->IoRingReadOk);    p->IoRingReadOk    = NULL; }
        if (p->IoRingWriteOk)   { free(p->IoRingWriteOk);   p->IoRingWriteOk   = NULL; }
        if (p->IoRingRegHandles){ free(p->IoRingRegHandles);p->IoRingRegHandles= NULL; }
        if (p->IoRingSrcHashes) { free(p->IoRingSrcHashes); p->IoRingSrcHashes = NULL; }
      }
    }
    if (g_Config.UseXxh3)
      p->Xxh3State = XXH3_createState();
    p->HashBuffer = NULL;  /* 延后至 CopierThread 内分配，支持 NUMA 绑定 */
    params[i] = p;
    p->hIocp = iocp;
    p->ThreadIndex = i;
    /* Round4 P2 架构2：首个线程启动时保存 IOCP 句柄供 DLQ 后台线程使用 */
    if (i == 0) {
      InterlockedExchangePointer((volatile PVOID *)&g_hCopyIocp, iocp);
    }
    p->LastFlushTick = GetTickCount();
    hW[i] = (HANDLE)_beginthreadex(NULL, 0, CopierThread, p, 0, NULL);
    if (!hW[i]) {
      wprintf(L"Fatal: _beginthreadex failed for worker %d, err=%lu\n", i,
              (unsigned long)GetLastError());
      for (int j = 0; j < numCopiers; j++)
        PostQueuedCompletionStatus(iocp, 0, KEY_TERMINATE, NULL);
      if (numCreated > 0)
        WaitForMultipleObjects(numCreated, hW, TRUE, INFINITE);
      for (int j = 0; j <= i; j++) {
        if (j < i)
          CloseHandle(hW[j]);
        if (params[j]->hIoRing && g_pCloseIoRing)
          g_pCloseIoRing(params[j]->hIoRing);
        if (params[j]->Xxh3State)
          XXH3_freeState(params[j]->Xxh3State);
        if (params[j]->IoRingBuffer)
          VirtualFree(params[j]->IoRingBuffer, 0, MEM_RELEASE);
        if (params[j]->HashBuffer)
          VirtualFree(params[j]->HashBuffer, 0, MEM_RELEASE);
        free(params[j]->IoRingBatch);
        free(params[j]->IoRingBatchOk);
        free(params[j]->IoRingHandleSrc);
        free(params[j]->IoRingHandleDst);
        free(params[j]->IoRingBufs);
        free(params[j]->IoRingReadOk);
        free(params[j]->IoRingWriteOk);
        free(params[j]->IoRingRegHandles);
        free(params[j]->IoRingSrcHashes);
        if (params[j]->SdCacheBlob) free(params[j]->SdCacheBlob);
        PB_ALIGNED_FREE(params[j]);
      }
      free(params);
      free(hW);
      return 1;
    }
    numCreated++;
  }
  g_CopierParams = params;
  g_NumCopierParams = numCopiers;

  /* Round4 P2 架构2：所有工作线程启动后，拉起 DLQ 后台渐进重试线程。
   * 该线程在主流水线期间持续运行，每 5 分钟将 DLQ 中的旧任务平滑反刍回主队列，
   * 降低百TB任务中长期驻留的内存背压，同时尽早区分瞬时/永久性错误。*/
  if (g_DeadLetterQueue) {
    g_hDLQQuitEvent = CreateEventW(NULL, TRUE, FALSE, NULL);  /* Round6 P1：手动重置，SetEvent 后线程 0ms 唤醒 */
    InterlockedExchange((volatile LONG *)&g_DLQBackgroundRun, TRUE);  /* Round5 P3：原子写，与 READ_VOLATILE_32 对称 */
    g_hDLQBackgroundThread = (HANDLE)_beginthreadex(NULL, 0, DLQBackgroundThread, NULL, 0, NULL);
    if (!g_hDLQBackgroundThread) {
      InterlockedExchange((volatile LONG *)&g_DLQBackgroundRun, FALSE);  /* 启动失败不致命，退化为原有仅末尾重试 */
      if (g_hDLQQuitEvent) { CloseHandle(g_hDLQQuitEvent); g_hDLQQuitEvent = NULL; }
    }
  }

  int exitCode = 0;
  if (wcslen(g_Config.ListFilePath) > 0) {
    if (g_Config.BfsScan && !g_BfsScanQueue) {
      g_BfsScanQueue = (BfsScanQueue *)calloc(1, sizeof(BfsScanQueue));
      if (g_BfsScanQueue) {
        InitializeCriticalSection(&g_BfsScanQueue->cs);
        g_BfsScanQueue->hSem = CreateSemaphoreW(NULL, 0, 0x7FFFFFFF, NULL);
        if (!g_BfsScanQueue->hSem) {
          DeleteCriticalSection(&g_BfsScanQueue->cs);
          free(g_BfsScanQueue);
          g_BfsScanQueue = NULL;
          g_Config.BfsScan = FALSE;
        }
      } else
        g_Config.BfsScan = FALSE;
    }
    int listCount = LoadListAndPostTasks(iocp);
    if (listCount <= 0) {
      wprintf(L"Fatal: list file empty or invalid\n");
      exitCode = 1;
      goto Cleanup_BeforeMainLoop;
    }
  } else {
    const wchar_t *mftBaseline = g_Config.SrcPath;
    const wchar_t *mftPeer = g_Config.DstPath;
    if (g_Config.AuditOnly && g_Config.AuditMode == AUDIT_MODE_DST) {
      mftBaseline = g_Config.DstPath;
      mftPeer = g_Config.SrcPath;
    }
    BOOL useMft = (g_Config.UseMftScan || g_Config.UseMftRawScan) && IsUserAdmin() &&
        IsVolumeNTFS(mftBaseline) && !IsUncPath(mftBaseline) &&
        !g_Config.IsFtpSource && !g_Config.IsFtpDest;
    int mftPosted = -1;
    if (useMft) {
      mftPosted = g_Config.UseMftRawScan
          ? MftRawScanAndPostTasks(iocp, mftBaseline, mftPeer, FALSE)
          : MftScanAndPostTasks(iocp, mftBaseline, mftPeer, FALSE);
      if (mftPosted < 0) {
        useMft = FALSE;
        LogMessage(LOG_INFO, L"[MFT] Fallback to traditional scan (admin/NTFS required)\n");
      } else {
        LogMessage(LOG_INFO, L"[MFT] Enumerated %d items via USN\n", mftPosted);
        if (!g_Config.FastMode && g_DirMetaStack) {
          WIN32_FILE_ATTRIBUTE_DATA fad;
          if (GetFileAttributesExW(mftBaseline, GetFileExInfoStandard, &fad)) {
            DirMetaTask *dmt = AllocDirMetaTask();
            if (dmt) {
              size_t mftSrcLen = wcslen(mftBaseline);
              size_t mftDstLen = wcslen(mftPeer);
              dmt->SrcPath = StrDupWithLen(NULL, g_StringArena, mftBaseline, mftSrcLen);
              dmt->SrcLen = (uint32_t)mftSrcLen;
              dmt->DstPath = dmt->SrcPath ? StrDupWithLen(NULL, g_StringArena, mftPeer, mftDstLen) : NULL;
              dmt->DstLen = (uint32_t)mftDstLen;
              dmt->pathFlags = TASK_PATH_FLAG_SRC_ARENA | TASK_PATH_FLAG_DST_ARENA;
              if (dmt->SrcPath && dmt->DstPath) {
                dmt->CreationTime = fad.ftCreationTime;
                dmt->LastAccessTime = fad.ftLastAccessTime;
                dmt->LastWriteTime = fad.ftLastWriteTime;
                dmt->FileAttributes = fad.dwFileAttributes;
                InterlockedPushEntrySList(g_DirMetaStack, &dmt->ItemEntry);
              } else {
                FreeDirMetaTask(dmt);
              }
            }
          }
        }
      }
    }
    /* -audit full：Phase1 MFT 建基准索引后排空，Phase2 MFT 枚举目标卷抓 Extra（失败则回退末尾递归浅扫） */
    if (g_Config.AuditOnly && g_Config.AuditMode == AUDIT_MODE_FULL && useMft && mftPosted >= 0 &&
        !IsCanceling()) {
      AuditWaitDrainIocp();
      InterlockedExchange(&g_AuditHashFrozen, 1);
      MemoryBarrier();
      InterlockedExchange(&g_AuditPhase, 2);
      LogMessage(LOG_DEBUG, L"[AUDIT] Phase2 MFT root=%ls | peer=%ls | baselineRoot=%ls | peerRoot=%ls\n",
          g_Config.DstPath, g_Config.SrcPath, g_AuditBaselineRoot, g_AuditPeerRoot);
      BOOL canDstMft = (g_Config.UseMftScan || g_Config.UseMftRawScan) && IsUserAdmin() &&
          IsVolumeNTFS(g_Config.DstPath) && !IsUncPath(g_Config.DstPath) &&
          !g_Config.IsFtpSource && !g_Config.IsFtpDest;
      int mftExtra = -1;
      if (canDstMft) {
        mftExtra = g_Config.UseMftRawScan
            ? MftRawScanAndPostTasks(iocp, g_Config.DstPath, g_Config.SrcPath, TRUE)
            : MftScanAndPostTasks(iocp, g_Config.DstPath, g_Config.SrcPath, TRUE);
      }
      if (mftExtra >= 0) {
        InterlockedExchange(&g_AuditPhase2MftOk, 1);
        LogMessage(LOG_INFO, L"[AUDIT] Phase2 MFT Extra enumerated %d items on target volume\n", mftExtra);
      } else {
        InterlockedExchange(&g_AuditPhase, 1);
        InterlockedExchange(&g_AuditHashFrozen, 0);
        LogMessage(LOG_INFO, L"[AUDIT] Phase2 MFT unavailable; Extra will use end-of-run recursive scan\n");
      }
    }
    if (!useMft) {
    if (g_Config.BfsScan && !g_BfsScanQueue) {
      g_BfsScanQueue = (BfsScanQueue *)calloc(1, sizeof(BfsScanQueue));
      if (g_BfsScanQueue) {
        InitializeCriticalSection(&g_BfsScanQueue->cs);
        g_BfsScanQueue->hSem = CreateSemaphoreW(NULL, 0, 0x7FFFFFFF, NULL);
        if (!g_BfsScanQueue->hSem) {
          DeleteCriticalSection(&g_BfsScanQueue->cs);
          free(g_BfsScanQueue);
          g_BfsScanQueue = NULL;
          g_Config.BfsScan = FALSE;
        }
      } else
        g_Config.BfsScan = FALSE;
    }
    ScanTask *root = AllocScanTask();
    if (!root) {
      wprintf(L"Fatal: AllocScanTask failed\n");
      exitCode = 1;
      goto Cleanup_BeforeMainLoop;
    }
    const wchar_t *rootBaseline = g_Config.SrcPath;
    const wchar_t *rootPeer = g_Config.DstPath;
    if (g_Config.AuditOnly && g_Config.AuditMode == AUDIT_MODE_DST) {
      rootBaseline = g_Config.DstPath;
      rootPeer = g_Config.SrcPath;
    }
    size_t rootSrcLen = wcslen(rootBaseline);
    size_t rootDstLen = wcslen(rootPeer);
    root->SrcLen = (uint32_t)rootSrcLen;
    root->DstLen = (uint32_t)rootDstLen;
    if (rootSrcLen < MAX_PATH && rootDstLen < MAX_PATH) {
      StringCchCopyW(root->ShortSrc, MAX_PATH, rootBaseline);
      StringCchCopyW(root->ShortDst, MAX_PATH, rootPeer);
      root->SrcPath = root->ShortSrc;
      root->DstPath = root->ShortDst;
      root->pathFlags = TASK_PATH_FLAG_SRC_SHORT | TASK_PATH_FLAG_DST_SHORT;
    } else {
      root->SrcPath = StrDupWithLen(NULL, g_StringArena, rootBaseline, rootSrcLen);
      root->DstPath = root->SrcPath ? StrDupWithLen(NULL, g_StringArena, rootPeer, rootDstLen) : NULL;
      root->pathFlags = TASK_PATH_FLAG_SRC_ARENA | TASK_PATH_FLAG_DST_ARENA;
    }
    if (!root->SrcPath || !root->DstPath) {
      FreeScanTask(root);
      wprintf(L"Fatal: path setup failed for root\n");
      exitCode = 1;
      goto Cleanup_BeforeMainLoop;
    }
    if (!g_Config.FastMode && g_DirMetaStack) {
      WIN32_FILE_ATTRIBUTE_DATA fad;
      if (GetFileAttributesExW(rootBaseline, GetFileExInfoStandard, &fad)) {
        DirMetaTask *dmt = AllocDirMetaTask();
        if (dmt) {
          dmt->SrcPath = StrDupWithLen(NULL, g_StringArena, rootBaseline, rootSrcLen);
          dmt->SrcLen = (uint32_t)rootSrcLen;
          dmt->DstPath = dmt->SrcPath ? StrDupWithLen(NULL, g_StringArena, rootPeer, rootDstLen) : NULL;
          dmt->DstLen = (uint32_t)rootDstLen;
          dmt->pathFlags = TASK_PATH_FLAG_SRC_ARENA | TASK_PATH_FLAG_DST_ARENA;
          if (dmt->SrcPath && dmt->DstPath) {
            dmt->CreationTime = fad.ftCreationTime;
            dmt->LastAccessTime = fad.ftLastAccessTime;
            dmt->LastWriteTime = fad.ftLastWriteTime;
            dmt->FileAttributes = fad.dwFileAttributes;
            InterlockedPushEntrySList(g_DirMetaStack, &dmt->ItemEntry);
          } else {
            FreeDirMetaTask(dmt);
          }
        }
      }
    }
    InterlockedIncrement(&g_PendingActive);
    {
      wchar_t dispScan[MAX_PATH_EXT];
      if (g_Config.AuditOnly) {
        PathForDisplayW(rootBaseline, dispScan, MAX_PATH_EXT);
        LogMessage(LOG_INFO, L"[SCAN] Audit (read-only): enumerating baseline tree — %ls\n", dispScan);
      } else {
        PathForDisplayW(g_Config.SrcPath, dispScan, MAX_PATH_EXT);
        LogMessage(LOG_INFO, L"[SCAN] Traditional scan started for %ls\n", dispScan);
      }
    }
    /* 短暂让出 CPU，确保 CopierThread 已进入 GetQueuedCompletionStatusEx 等待，避免根任务无人消费 */
    Sleep(150);
    if (g_Config.BfsScan && g_BfsScanQueue) {
      PushBfsScanTask(root);
      PostQueuedCompletionStatus(iocp, 0, KEY_SCAN_TASK, NULL);
    } else
      PostQueuedCompletionStatus(iocp, 0, KEY_SCAN_TASK, (LPOVERLAPPED)root);
    }
  }
  g_PipelineStartTick = GetTickCount();        /* 必须先于 PipelineStarted，避免 Ctrl 处理器竞态读到 0 */
  InterlockedExchange(&g_PipelineStarted, 1); /* 流水线已启动，此后 Ctrl+C 才生效 */

  if (g_Config.ParentPid > 0) {
    g_bTelemetryEnabled = TRUE;
    InitTelemetryPipe();
    InitStopEvent();
    wprintf(L"[INFO] Parent watchdog: copy will cancel when process %lu exits (for GUI-spawned runs).\n",
        (unsigned long)g_Config.ParentPid);
    {
      DWORD shellParent = QueryParentProcessIdWin32(GetCurrentProcessId());
      if (shellParent != 0 && shellParent != g_Config.ParentPid)
        wprintf(L"[INFO] This process was started by PID %lu; -P differs — if you pasted a GUI command, "
                L"remove -P for standalone CMD or the watched PID may exit and stop the copy early.\n",
            (unsigned long)shellParent);
    }
    g_hParentWatcherThread = (HANDLE)_beginthreadex(NULL, 0, ParentWatcherThread,
        (void *)(UINT_PTR)g_Config.ParentPid, 0, NULL);
    if (g_hParentWatcherThread)
      CloseHandle(g_hParentWatcherThread); /* 线程独立运行，不持有引用 */
    g_hParentWatcherThread = NULL;
  }

  DWORD lastSpaceCheck = GetTickCount();
  DWORD lastCheckpointTick = GetTickCount();
  LONGLONG lastCheckpointBytes = 0;
  /* 无锁 Checkpoint：后台线程刷盘，主循环零 I/O 停顿 */
  if ((g_Config.CheckpointIntervalSec > 0 || g_Config.CheckpointIntervalGB > 0) && !g_Config.Preflight) {
    g_hCheckpointEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    g_hCheckpointStopEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (g_hCheckpointEvent && g_hCheckpointStopEvent)
      g_hCheckpointThread = (HANDLE)_beginthreadex(NULL, 0, CheckpointWriterThread, NULL, 0, NULL);
  }
  while (1) {
    if (READ_VOLATILE_32(&g_PendingActive) <= 0 || IsCanceling() || READ_VOLATILE_32(&g_InsufficientSpace)) {
      break;
    }
    if (CheckStopEvent()) {
      InterlockedExchange(&g_IsCanceling, 1);
      wprintf(L"\n[WARN] Stop event signaled by GUI, graceful shutdown...\n");
      break;
    }
#if USE_SHM_TELEMETRY
    /* Phase 8 cmd_Pause：V10 只读 s_cached_Pause，TokenBucketThread 唯一更新 */
    while (g_pTelemetryShared) {
      if (s_cached_Pause == 0) break;
      if (CheckStopEvent()) break;
      if (IsCanceling()) break;  /* GUI 暴毙时穿透暂停 */
      if (g_hPauseReleaseEvent)
        WaitForSingleObject(g_hPauseReleaseEvent, 100);
      else
        Sleep(100);
    }
#endif
    /* Phase 15：短 Sleep 分片，每 50ms 检查 Stop，避免 RefreshInterval=500 时停止响应延迟 */
    {
      DWORD interval = (DWORD)g_Config.RefreshInterval;
      DWORD chunk = (interval > 50) ? 50 : (interval > 0 ? interval : 50);
      for (DWORD slept = 0; slept < interval; slept += chunk) {
        DWORD toSleep = (slept + chunk <= interval) ? chunk : (interval - slept);
        if (toSleep > 0) Sleep(toSleep);
        if (CheckStopEvent()) {
          InterlockedExchange(&g_IsCanceling, 1);
          wprintf(L"\n[WARN] Stop event signaled by GUI, graceful shutdown...\n");
          goto main_loop_exit;
        }
      }
    }

    /* 断点续传：每 N 秒或每 N GB 写入 checkpoint */
    if ((g_Config.CheckpointIntervalSec > 0 || g_Config.CheckpointIntervalGB > 0) && !g_Config.Preflight) {
      DWORD now = GetTickCount();
      LONGLONG copied = g_NumThreadBuckets > 0 ? SumBucketBytes() : READ_VOLATILE_64(&g_TotalBytes);
      BOOL doCheckpoint = FALSE;
      if (g_Config.CheckpointIntervalSec > 0 &&
          (DWORD)(now - lastCheckpointTick) >= (DWORD)g_Config.CheckpointIntervalSec * 1000)
        doCheckpoint = TRUE;
      if (g_Config.CheckpointIntervalGB > 0 &&
          (copied - lastCheckpointBytes) >= g_Config.CheckpointIntervalGB * (1024LL * 1024 * 1024))
        doCheckpoint = TRUE;
      if (doCheckpoint) {
        if (g_hCheckpointThread) {
          DWORD *p = (DWORD *)g_CheckpointBuf;
          p[0] = CHECKPOINT_MAGIC;
          p[1] = CHECKPOINT_VERSION;
          LONGLONG *lp = (LONGLONG *)(g_CheckpointBuf + 8);
          lp[0] = READ_VOLATILE_64(&g_TotalFoundBytes);
          lp[1] = g_NumThreadBuckets > 0 ? SumBucketBytes() : READ_VOLATILE_64(&g_TotalBytes);
          lp[2] = (LONGLONG)READ_VOLATILE_32(&g_TotalFound);
          lp[3] = (LONGLONG)time(NULL);
          InterlockedExchange(&g_CheckpointPending, 1);
          SetEvent(g_hCheckpointEvent);
        } else {
          WriteCheckpointSync();
        }
        lastCheckpointTick = now;
        lastCheckpointBytes = copied;
      }
    }
    /* 前置容量预检：每 2 秒检查；若「剩余待拷」>「当前空闲 + DST_SPACE_PREFLIGHT_SLACK_BYTES」则退出。
     * remaining = 扫描累加总字节 − 已处理字节（含增量「跳过」视为已处理，会占用 copied）。
     * -C/-m/-D 下启动初 copied 可能仍为 0：宽限 15s，避免目标已镜像时误杀。
     * GetDiskFreeSpaceEx 的 lpFreeBytesAvailableToCaller 受 NTFS 配额等影响，可能与资源管理器「整卷」略有差异。 */
    if (!g_Config.SkipSpacePreflight && !g_Config.Preflight &&
        g_TotalFoundBytes > 0 && (GetTickCount() - lastSpaceCheck) >= 2000) {
      lastSpaceCheck = GetTickCount();
      ULARGE_INTEGER freeBytesAvailable, totalBytes, totalFreeBytes;
      if (GetDiskFreeSpaceExW(g_Config.DstPath, &freeBytesAvailable, &totalBytes, &totalFreeBytes)) {
        LONGLONG copied = g_NumThreadBuckets > 0 ? SumBucketBytes() : READ_VOLATILE_64(&g_TotalBytes);
        LONGLONG remainingToCopy = READ_VOLATILE_64(&g_TotalFoundBytes) - copied;
        BOOL incrementalMode =
            (g_Config.CompareMTime || g_Config.CompareSize || g_Config.CompareContent);
        DWORD sincePipe = GetTickCount() - g_PipelineStartTick;
        BOOL deferIncrementalWarmup =
            incrementalMode && sincePipe < 15000 &&
            READ_VOLATILE_32(&g_TotalCopied) < 1 && READ_VOLATILE_32(&g_TotalFound) > 0 &&
            remainingToCopy > 0;
        if (remainingToCopy > 0 && !deferIncrementalWarmup &&
            (LONGLONG)freeBytesAvailable.QuadPart + DST_SPACE_PREFLIGHT_SLACK_BYTES < remainingToCopy) {
          InterlockedExchange(&g_InsufficientSpace, 1);
          InterlockedExchange(&g_IsCanceling, 1);
          wprintf(L"\n[FATAL] Pre-flight: destination has insufficient space (engine estimate).\n");
          wprintf(L"  Remaining to copy: %.2f GB | Free (to this process): %.2f GB | Volume total free: %.2f GB\n",
                  (double)remainingToCopy / (1024.0 * 1024 * 1024),
                  (double)freeBytesAvailable.QuadPart / (1024.0 * 1024 * 1024),
                  (double)totalFreeBytes.QuadPart / (1024.0 * 1024 * 1024));
          wprintf(L"  Hint: If the destination already mirrors the source, add -C (same size) or -m (same mtime)\n");
          wprintf(L"        so unchanged files are skipped—required space drops after the first passes.\n");
          wprintf(L"        To force run anyway: -no_space_preflight (risky if the disk is actually full).\n");
          exitCode = 2;
        }
      }
    }
    SYSTEMTIME st;
    GetLocalTime(&st);
    int currentLimit = g_Config.ThreadCountIdle;
    if (g_Config.StartHour >= 0 && g_Config.EndHour >= 0) {
      BOOL inWindow = FALSE;
      if (g_Config.StartHour <= g_Config.EndHour)
        inWindow =
            (st.wHour >= g_Config.StartHour && st.wHour < g_Config.EndHour);
      else
        inWindow =
            (st.wHour >= g_Config.StartHour || st.wHour < g_Config.EndHour);
      if (inWindow)
        currentLimit = g_Config.ThreadCountNormal;
      else if (g_Config.RunHoursStrict) {
        /* -rh_strict: 时间窗口外完全暂停，每分钟检查 */
        InterlockedExchange(&g_ActiveCopierLimit, 0);
        Sleep(60000);
        continue;
      }
    } else {
      currentLimit = g_Config.ThreadCountNormal;
    }
    InterlockedExchange(&g_ActiveCopierLimit, currentLimit);
    PrintStats(0);
  }
main_loop_exit:
  for (int i = 0; i < numCopiers; i++)
    PostQueuedCompletionStatus(iocp, 0, KEY_TERMINATE, NULL);
  WaitForMultipleObjects(numCopiers, hW, TRUE, INFINITE);
  /* 须在 IOCP 线程退出后再取 Copied：SumBucketCopied 含各线程 copier_exit 中 FlushLocalCounters 刷入桶内的任务数。 */
  {
    LONG found = READ_VOLATILE_32(&g_TotalFound);
    LONG copied = g_NumThreadBuckets > 0 ? SumBucketCopied() : READ_VOLATILE_32(&g_TotalCopied);
    LONG failed = READ_VOLATILE_32(&g_TotalFailed);
    /* 异常退出时暂停 3 秒，便于在 CMD 中查看（窗口可能立即关闭） */
    if (found > 0 && (copied + failed) < found)
      Sleep(3000);
  }
  if (g_Config.Preflight) {
    wprintf(L"PREFLIGHT_TOTAL_BYTES=%lld\n", (long long)READ_VOLATILE_64(&g_TotalFoundBytes));
    wprintf(L"PREFLIGHT_FILE_COUNT=%ld\n", (long)READ_VOLATILE_32(&g_TotalFound));
    goto Cleanup_Threads_Done;
  }
  goto Cleanup_Threads_Done;

Cleanup_BeforeMainLoop:
  for (int i = 0; i < numCopiers; i++)
    PostQueuedCompletionStatus(iocp, 0, KEY_TERMINATE, NULL);
  WaitForMultipleObjects(numCopiers, hW, TRUE, INFINITE);

Cleanup_Threads_Done:
  if (g_hCheckpointStopEvent) {
    SetEvent(g_hCheckpointStopEvent);
    if (g_hCheckpointThread) {
      WaitForSingleObject(g_hCheckpointThread, 5000);
      CloseHandle(g_hCheckpointThread);
      g_hCheckpointThread = NULL;
    }
    CloseHandle(g_hCheckpointEvent);
    CloseHandle(g_hCheckpointStopEvent);
    g_hCheckpointEvent = NULL;
    g_hCheckpointStopEvent = NULL;
  }
  if (g_hOverflowFile != INVALID_HANDLE_VALUE) {
    if (g_hOverflowConsumer) {
      WaitForSingleObject(g_hOverflowConsumer, 10000);
      CloseHandle(g_hOverflowConsumer);
      g_hOverflowConsumer = NULL;
    }
    FlushOverflowBuffer();
    if (g_OverflowBuffer) {
      VirtualFree(g_OverflowBuffer, 0, MEM_RELEASE);
      g_OverflowBuffer = NULL;
    }
    CloseHandle(g_hOverflowFile);
    g_hOverflowFile = INVALID_HANDLE_VALUE;
    DeleteCriticalSection(&g_OverflowCs);
  }
  /* 【BUG-02 修复】正确收尾顺序：
     ① DLQ 并发重试（Verify 线程仍存活，可继续接收校验任务）
     ② 等待 Verify 彻底清空队列
     ③ 关闭 Verify 线程与 IOCP
     ④ DirMeta 恢复（所有文件 I/O 完成后最后写目录时间戳）          */

  /* -move 跨卷：自底向上删除源目录（路径越长越深） */
  if (g_MoveSourceDirsList && g_Config.IsMoveMode && !g_IsSameVolume) {
    MoveSourceDirEntry *arr = NULL;
    size_t n = 0, cap = 0;
    PSLIST_ENTRY e;
    EnterCriticalSection(&g_MoveSourceDirsCs);
    while ((e = InterlockedPopEntrySList(g_MoveSourceDirsList)) != NULL) {
      MoveSourceDirEntry *ent = (MoveSourceDirEntry *)e;
      if (n >= cap) {
        size_t newCap = (cap == 0) ? 4096 : cap * 2;
        MoveSourceDirEntry *narr = (MoveSourceDirEntry *)realloc(arr, newCap * sizeof(MoveSourceDirEntry));
        if (!narr) break;
        arr = narr;
        cap = newCap;
      }
      arr[n++] = *ent;
      free(ent);
    }
    LeaveCriticalSection(&g_MoveSourceDirsCs);
    if (arr && n > 0) {
      /* D9+N10 优化：预缓存路径长度后用 MoveSortKey 数组排序，qsort 比较函数零 wcslen。
       * 原始 MoveSourceDirCmp 在 O(N log N) 次比较中各调用两次 wcslen；
       * N10 改为一次 O(N) 预扫描 + O(N log N) 纯整数比较，100K 目录下节省 ~300M char 扫描。 */
      MoveSortKey *keys = (MoveSortKey *)malloc(n * sizeof(MoveSortKey));
      if (keys) {
        for (size_t i = 0; i < n; i++) {
          keys[i].Path = arr[i].Path;
          keys[i].Len  = wcslen(arr[i].Path);  /* 仅 O(N) 次 wcslen */
        }
        qsort(keys, n, sizeof(MoveSortKey), MoveSortKeyCmp);
        /* 将排序结果写回 arr */
        for (size_t i = 0; i < n; i++)
          arr[i].Path = keys[i].Path;
        free(keys);
      } else {
        /* 内存分配失败：退回 O(n²) 冒泡（保证正确性）*/
        for (size_t i = 0; i < n - 1; i++)
          for (size_t j = i + 1; j < n; j++)
            if (wcslen(arr[i].Path) < wcslen(arr[j].Path)) {
              MoveSourceDirEntry t = arr[i]; arr[i] = arr[j]; arr[j] = t;
            }
      }
      for (size_t i = 0; i < n; i++) {
        SetFileAttributesW(arr[i].Path, FILE_ATTRIBUTE_NORMAL);
        RemoveDirectoryW(arr[i].Path);
        free(arr[i].Path);
      }
      free(arr);
    }
    if (g_MoveSourceDirsList) {
      PB_ALIGNED_FREE(g_MoveSourceDirsList);
      g_MoveSourceDirsList = NULL;
    }
    DeleteCriticalSection(&g_MoveSourceDirsCs);
  }

  /* Preflight 模式：跳过 DLQ/Verify/DirMeta，仅输出汇总 */
  if (g_Config.Preflight) {
    for (int _v = 0; READ_VOLATILE_32(&g_PendingVerify) > 0; _v++) {
      Sleep(_v < 5 ? 50 : (_v < 15 ? 100 : 200));  /* 指数退避，降低 CPU 空转 */
    }
    g_VerifyThreadRunning = FALSE;
    if (g_hVerifyIocp && g_hVerifyThreads) {
      for (int i = 0; i < g_NumVerifyThreads; i++)
        PostQueuedCompletionStatus(g_hVerifyIocp, 0, KEY_TERMINATE, NULL);
      WaitForMultipleObjects((DWORD)g_NumVerifyThreads, g_hVerifyThreads, TRUE, 5000);
      for (int i = 0; i < g_NumVerifyThreads; i++)
        CloseHandle(g_hVerifyThreads[i]);
      free(g_hVerifyThreads);
      g_hVerifyThreads = NULL;
    }
    /* 清空 DirMeta 栈，不执行复制 */
    for (PSLIST_ENTRY e; g_DirMetaStack && (e = InterlockedPopEntrySList(g_DirMetaStack)) != NULL;) {
      DirMetaTask *dmt = (DirMetaTask *)e;
      FreeDirMetaTask(dmt);
    }
    /* Round5 P1-Bug1 + Round6 P1：Preflight 路径也须关闭 DLQ 后台线程 */
    if (g_hDLQBackgroundThread) {
      InterlockedExchange((volatile LONG *)&g_DLQBackgroundRun, FALSE);
      if (g_hDLQQuitEvent) SetEvent(g_hDLQQuitEvent);
      WaitForSingleObject(g_hDLQBackgroundThread, INFINITE);
      CloseHandle(g_hDLQBackgroundThread);
      g_hDLQBackgroundThread = NULL;
      if (g_hDLQQuitEvent) { CloseHandle(g_hDLQQuitEvent); g_hDLQQuitEvent = NULL; }
    }
    goto Cleanup_AfterDirMeta;
  }
  /* Round5 P1-Bug1 + Round6 P1：无条件停止 DLQ 后台线程。SetEvent 后 0ms 唤醒，INFINITE 确保彻底退出再 FreeAllPools。 */
  if (g_hDLQBackgroundThread) {
    InterlockedExchange((volatile LONG *)&g_DLQBackgroundRun, FALSE);
    if (g_hDLQQuitEvent) SetEvent(g_hDLQQuitEvent);  /* 瞬间唤醒，避免 1s Sleep 卡顿 */
    WaitForSingleObject(g_hDLQBackgroundThread, INFINITE);
    CloseHandle(g_hDLQBackgroundThread);
    g_hDLQBackgroundThread = NULL;
    if (g_hDLQQuitEvent) { CloseHandle(g_hDLQQuitEvent); g_hDLQQuitEvent = NULL; }
  }

  /* ① DLQ 并发重试：派生 min(numCopiers, 64) 个轻量线程，每线程无 Sleep 抢占执行
        g_NoDLQ=TRUE 防止重试失败的任务再次入队造成无限循环
        整体 5 分钟超时作为保险，超时后残留任务直接标记失败            */
  if (g_DeadLetterQueue && params && numCopiers > 0) {
    LONG dlqN = (LONG)QueryDepthSList(g_DeadLetterQueue);
    if (dlqN > 0) {
      g_NoDLQ = TRUE;
      int dlqW = numCopiers < MAXIMUM_WAIT_OBJECTS ? numCopiers : MAXIMUM_WAIT_OBJECTS;
      wprintf(L"\n[DLQ] Concurrent retry: %ld tasks / %d threads (5 min timeout)...\n",
              dlqN, dlqW);
      HANDLE *dlqH = (HANDLE *)malloc(dlqW * sizeof(HANDLE));
      if (dlqH) {
        int launched = 0;
        for (int i = 0; i < dlqW; i++) {
          dlqH[i] = (HANDLE)_beginthreadex(NULL, 0, DLQWorkerThread, params[i], 0, NULL);
          if (dlqH[i]) launched++;
        }
        if (launched > 0)
          WaitForMultipleObjects((DWORD)dlqW, dlqH, TRUE, 300000); /* 5 min */
        for (int i = 0; i < dlqW; i++)
          if (dlqH[i]) CloseHandle(dlqH[i]);
        free(dlqH);
      }
    }
  }
  /* 残留 DLQ：若已 Ctrl+C 则静默销毁并合并汇报，否则对每项执行 RetryDeadLetterTask */
  if (g_DeadLetterQueue && params && numCopiers > 0) {
    CopierParam *dlqParam = params[0];
    PSLIST_ENTRY eDlq;
    LONG abortedCount = 0;
    while ((eDlq = InterlockedPopEntrySList(g_DeadLetterQueue)) != NULL) {
      if (IsCanceling()) {
        abortedCount++;
        InterlockedIncrement(&g_TotalFailed);
        FreeCopyTask((CopyTask *)eDlq);
      } else {
        RetryDeadLetterTask((CopyTask *)eDlq, dlqParam);
      }
    }
    if (abortedCount > 0) {
      wprintf(L"\n[WARN] %ld pending tasks in DLQ were silently aborted due to Ctrl+C.\n", (long)abortedCount);
    }
  } else if (g_DeadLetterQueue) {
    PSLIST_ENTRY eDlq;
    LONG abortedCount = 0;
    while ((eDlq = InterlockedPopEntrySList(g_DeadLetterQueue)) != NULL) {
      abortedCount++;
      InterlockedIncrement(&g_TotalFailed);
      FreeCopyTask((CopyTask *)eDlq);
    }
    if (abortedCount > 0) {
      wprintf(L"\n[WARN] %ld pending tasks in DLQ were silently aborted due to Ctrl+C.\n", (long)abortedCount);
    }
  }

  /* ② DLQ 跑完后，彻底死等 Verify 线程清空所有积压任务；指数退避降低 CPU 空转 */
  for (int _v = 0; READ_VOLATILE_32(&g_PendingVerify) > 0; _v++) {
    Sleep(_v < 5 ? 50 : (_v < 15 ? 100 : 200));
  }

  /* ③ 最后安全关闭 Verify 线程与 IOCP */
  g_VerifyThreadRunning = FALSE;
  if (g_hVerifyIocp && g_hVerifyThreads) {
    for (int i = 0; i < g_NumVerifyThreads; i++)
      PostQueuedCompletionStatus(g_hVerifyIocp, 0, KEY_TERMINATE, NULL);
    WaitForMultipleObjects((DWORD)g_NumVerifyThreads, g_hVerifyThreads, TRUE, 30000);
    for (int i = 0; i < g_NumVerifyThreads; i++)
      CloseHandle(g_hVerifyThreads[i]);
    free(g_hVerifyThreads);
    g_hVerifyThreads = NULL;
    if (g_VerifyParams) {
      for (int i = 0; i < g_NumVerifyThreads; i++) {
        VerifyParam *vp = g_VerifyParams[i];
        if (vp) {
          if (vp->Xxh3State) { XXH3_freeState(vp->Xxh3State); vp->Xxh3State = NULL; }
          if (vp->HashBuffer) { VirtualFree(vp->HashBuffer, 0, MEM_RELEASE); vp->HashBuffer = NULL; }
          if (vp->hIoRingVerify && g_pCloseIoRing) { g_pCloseIoRing(vp->hIoRingVerify); vp->hIoRingVerify = NULL; }
          if (vp->IoRingSampleBuf) { VirtualFree(vp->IoRingSampleBuf, 0, MEM_RELEASE); vp->IoRingSampleBuf = NULL; }
          free(vp);
        }
      }
      free(g_VerifyParams);
      g_VerifyParams = NULL;
    }
    CloseHandle(g_hVerifyIocp);
    g_hVerifyIocp = NULL;
  }

  /* ④ DirMeta 恢复：所有文件 I/O 完成后，统一写入目录时间戳/属性 */
Cleanup_AfterDirMeta:
  if (g_DirMetaStack) {
    DirMetaTask **dirList = NULL;
    size_t dirCount = 0;
    PSLIST_ENTRY e;
    while ((e = InterlockedPopEntrySList(g_DirMetaStack)) != NULL) {
      DirMetaTask *dmt = (DirMetaTask *)e;
      DirMetaTask **nlist =
          (DirMetaTask **)realloc(dirList, (dirCount + 1) * sizeof(DirMetaTask *));
      if (!nlist) {
        if (dirCount > 1)
          qsort(dirList, dirCount, sizeof(DirMetaTask *), CompareDirMetaTaskByDstDepthDesc);
        for (size_t j = 0; j < dirCount; j++) {
          DirMetaTask *dmtj = dirList[j];
          CopyTask fake = {0};
          fake.CreationTime = dmtj->CreationTime;
          fake.LastAccessTime = dmtj->LastAccessTime;
          fake.LastWriteTime = dmtj->LastWriteTime;
          fake.FileAttributes = dmtj->FileAttributes;
          CopyFileSecurityAndAttributes(dmtj->SrcPath, dmtj->DstPath, &fake);
          FreeDirMetaTask(dmtj);
        }
        free(dirList);
        {
          CopyTask fake = {0};
          fake.CreationTime = dmt->CreationTime;
          fake.LastAccessTime = dmt->LastAccessTime;
          fake.LastWriteTime = dmt->LastWriteTime;
          fake.FileAttributes = dmt->FileAttributes;
          CopyFileSecurityAndAttributes(dmt->SrcPath, dmt->DstPath, &fake);
          FreeDirMetaTask(dmt);
        }
        while ((e = InterlockedPopEntrySList(g_DirMetaStack)) != NULL) {
          DirMetaTask *dmt2 = (DirMetaTask *)e;
          CopyTask fake = {0};
          fake.CreationTime = dmt2->CreationTime;
          fake.LastAccessTime = dmt2->LastAccessTime;
          fake.LastWriteTime = dmt2->LastWriteTime;
          fake.FileAttributes = dmt2->FileAttributes;
          CopyFileSecurityAndAttributes(dmt2->SrcPath, dmt2->DstPath, &fake);
          FreeDirMetaTask(dmt2);
        }
        goto DirMetaCleanupDone;
      }
      dirList = nlist;
      dirList[dirCount++] = dmt;
    }
    if (dirCount > 1)
      qsort(dirList, dirCount, sizeof(DirMetaTask *), CompareDirMetaTaskByDstDepthDesc);
    for (size_t i = 0; i < dirCount; i++) {
      DirMetaTask *dmt = dirList[i];
      CopyTask fake = {0};
      fake.CreationTime = dmt->CreationTime;
      fake.LastAccessTime = dmt->LastAccessTime;
      fake.LastWriteTime = dmt->LastWriteTime;
      fake.FileAttributes = dmt->FileAttributes;
      CopyFileSecurityAndAttributes(dmt->SrcPath, dmt->DstPath, &fake);
      FreeDirMetaTask(dmt);
    }
    free(dirList);
  }
DirMetaCleanupDone:
  ;
  for (int i = 0; i < numCopiers; i++) {
    CloseHandle(hW[i]);
    if (params[i]->hIoRing && g_pCloseIoRing)
      g_pCloseIoRing(params[i]->hIoRing);
    if (params[i]->Xxh3State)
      XXH3_freeState(params[i]->Xxh3State);
    if (params[i]->IoRingBuffer)
      VirtualFree(params[i]->IoRingBuffer, 0, MEM_RELEASE);
    if (params[i]->HashBuffer)
      VirtualFree(params[i]->HashBuffer, 0, MEM_RELEASE);
    free(params[i]->IoRingBatch);
    free(params[i]->IoRingBatchOk);
    free(params[i]->IoRingHandleSrc);
    free(params[i]->IoRingHandleDst);
    free(params[i]->IoRingBufs);
    free(params[i]->IoRingReadOk);
    free(params[i]->IoRingWriteOk);
    free(params[i]->IoRingRegHandles);
    free(params[i]->IoRingSrcHashes);
    if (params[i]->SdCacheBlob) free(params[i]->SdCacheBlob);
    PB_ALIGNED_FREE(params[i]);
  }
  g_CopierParams = NULL;
  g_NumCopierParams = 0;
  free(params);
  free(hW);

  // 关闭异步清理
  g_CleanupThreadRunning = FALSE;
  SetEvent(g_hCleanupEvent);
  if (g_hCleanupThread) {
    WaitForSingleObject(g_hCleanupThread, INFINITE);
    CloseHandle(g_hCleanupThread);
  }

  if (g_hTokenThread) {
    g_TokenThreadRunning = 0;
    WaitForSingleObject(g_hTokenThread, 2000);
    CloseHandle(g_hTokenThread);
    g_hTokenThread = NULL;
  }
  g_LogThreadRunning = FALSE;
  SetEvent(g_hLogEvent);
  if (g_hLogThread) {
    WaitForSingleObject(g_hLogThread, INFINITE);
    CloseHandle(g_hLogThread);
  }
  if (g_hOsTelemetryThread) {
    if (g_hOsTelemetryStopEvent) SetEvent(g_hOsTelemetryStopEvent);
    WaitForSingleObject(g_hOsTelemetryThread, 3000);
    CloseHandle(g_hOsTelemetryThread);
    g_hOsTelemetryThread = NULL;
  }
  if (g_hOsTelemetryStopEvent) { CloseHandle(g_hOsTelemetryStopEvent); g_hOsTelemetryStopEvent = NULL; }
  if (g_VerifyTaskPool) {
    PSLIST_ENTRY e;
    while ((e = InterlockedPopEntrySList(g_VerifyTaskPool)) != NULL) {
      VerifyTask *vt = (VerifyTask *)e;
      if (vt->DstPath && vt->DstPath != vt->ShortDst)
        free(vt->DstPath);
      PB_ALIGNED_FREE(vt);
    }
    PB_ALIGNED_FREE(g_VerifyTaskPool);
    g_VerifyTaskPool = NULL;
  }
  if (!exitCode)
    PrintStats(1);
  /* 发送最终遥测：通知 GUI 任务结束 */
#if USE_SHM_TELEMETRY
  if (g_pTelemetryShared) {
    ReadControlIfDirty();  /* 确保 ack 反映最终状态 */
    TelemetryData td = {0};
    td.magic = TELEMETRY_MAGIC;
    td.totalFiles = (uint64_t)READ_VOLATILE_32(&g_TotalFound);
    td.copiedFiles = (uint64_t)g_TotalCopied;
    td.totalBytes = (uint64_t)READ_VOLATILE_64(&g_TotalFoundBytes);
    td.copiedBytes = (uint64_t)g_TotalBytes;
    td.currentSpeedMBps = 0;
    td.activeThreads = 0;
    td.isFinished = (g_InsufficientSpace || g_TotalFailed > 0) ? 2 : 1;
    td.version = TELEMETRY_PROTOCOL_VERSION;
    td.ack_SpeedLimit = (uint8_t)(s_cached_SpeedLimit > 255 ? 255 : s_cached_SpeedLimit);
    td.ack_Pause = (uint8_t)s_cached_Pause;
    td.failedFiles = (uint32_t)READ_VOLATILE_32(&g_TotalFailed);  /* Round4：终态同步失败计数 */
    td.io_block_clone = (uint64_t)READ_VOLATILE_64(&g_IoStrategyStats[IOSTRAT_BLOCK_CLONE]);
    td.io_direct_big = (uint64_t)READ_VOLATILE_64(&g_IoStrategyStats[IOSTRAT_BIG_DIRECT_IO]);
    td.io_buffered_big = (uint64_t)READ_VOLATILE_64(&g_IoStrategyStats[IOSTRAT_BIG_BUFFERED]);
    BroadcastTelemetry(&td);
    UnmapViewOfFile(g_pTelemetryShared);
    CloseHandle(g_hTelemetryMapping);
    g_pTelemetryShared = NULL;
    g_hTelemetryMapping = NULL;
    if (g_hLogRingNotifyEvent) {
      CloseHandle(g_hLogRingNotifyEvent);
      g_hLogRingNotifyEvent = NULL;
    }
    if (g_pLogRing) {
      UnmapViewOfFile(g_pLogRing);
      CloseHandle(g_hLogRingMapping);
      g_pLogRing = NULL;
      g_hLogRingMapping = NULL;
    }
    if (g_pLogRingBuffer) {
      if (g_useMagicRingBuffer) {
        UnmapViewOfFile(g_pLogRingBuffer);
        UnmapViewOfFile((void *)((uint8_t *)g_pLogRingBuffer + LOG_RING_SIZE));
      } else {
        UnmapViewOfFile(g_pLogRingBuffer);
      }
      CloseHandle(g_hLogRingBufMapping);
      g_pLogRingBuffer = NULL;
      g_hLogRingBufMapping = NULL;
      g_useMagicRingBuffer = FALSE;
    }
  }
#else
  if (g_hTelemetryPipe != INVALID_HANDLE_VALUE) {
    TelemetryData td = {0};
    td.magic = TELEMETRY_MAGIC;
    td.totalFiles = (uint64_t)READ_VOLATILE_32(&g_TotalFound);
    td.copiedFiles = (uint64_t)g_TotalCopied;
    td.totalBytes = (uint64_t)READ_VOLATILE_64(&g_TotalFoundBytes);
    td.copiedBytes = (uint64_t)g_TotalBytes;
    td.currentSpeedMBps = 0;
    td.activeThreads = 0;
    td.isFinished = (g_InsufficientSpace || g_TotalFailed > 0) ? 2 : 1;
    td.version = TELEMETRY_PROTOCOL_VERSION;
    td.failedFiles = (uint32_t)READ_VOLATILE_32(&g_TotalFailed);  /* Round4：管道模式同步终态失败计数 */
    td.io_block_clone = (uint64_t)READ_VOLATILE_64(&g_IoStrategyStats[IOSTRAT_BLOCK_CLONE]);
    td.io_direct_big = (uint64_t)READ_VOLATILE_64(&g_IoStrategyStats[IOSTRAT_BIG_DIRECT_IO]);
    td.io_buffered_big = (uint64_t)READ_VOLATILE_64(&g_IoStrategyStats[IOSTRAT_BIG_BUFFERED]);
    BroadcastTelemetry(&td);
    CloseHandle(g_hTelemetryPipe);
    g_hTelemetryPipe = INVALID_HANDLE_VALUE;
  }
#endif
  if (g_hPauseReleaseEvent) {
    CloseHandle(g_hPauseReleaseEvent);
    g_hPauseReleaseEvent = NULL;
  }
  if (g_hStopEvent) {
    CloseHandle(g_hStopEvent);
    g_hStopEvent = NULL;
  }
  LARGE_INTEGER end;
  QueryPerformanceCounter(&end);
  double totalElapsed = 0.001;
  if (g_Freq.QuadPart != 0)
    totalElapsed =
        (double)(end.QuadPart - g_StartTime.QuadPart) / g_Freq.QuadPart;
  if (totalElapsed < 0.001)
    totalElapsed = 0.001;
  if (!exitCode) {
  LONG finalCopied = g_NumThreadBuckets > 0 ? SumBucketCopied() : g_TotalCopied;
  LONG64 finalBytes = g_NumThreadBuckets > 0 ? SumBucketBytes() : g_TotalBytes;

  // 获取结束时间
  SYSTEMTIME endSt;
  GetLocalTime(&endSt);

  PrintAndLog(L"\n--- COMPLETED [%04d-%02d-%02d %02d:%02d:%02d] ---\n", 
                endSt.wYear, endSt.wMonth, endSt.wDay, endSt.wHour, endSt.wMinute, endSt.wSecond);
  PrintAndLog(L"Time: %.2f s\n", totalElapsed);
  PrintAndLog(L"Total Files: %ld\n", finalCopied + g_TotalFailed);
  if (g_Config.AuditOnly)
    PrintAndLog(L"  - Verified OK: %ld\n", finalCopied);
  else
    PrintAndLog(L"  - Copied Files: %ld\n", finalCopied);
  PrintAndLog(L"  - Small (<1MB): %ld\n", g_SmallFiles);
  PrintAndLog(L"  - Medium (1-10MB): %ld\n", g_MediumFiles);
  PrintAndLog(L"  - Large (>10MB): %ld\n", g_LargeFiles);
  PrintAndLog(L"Total Size: %.2f GB | Avg: %.2f MB/s\n",
          (double)finalBytes / (1024.0 * 1024 * 1024),
          (double)finalBytes / (1024 * 1024) / totalElapsed);
  if (g_Config.AuditOnly) {
    if (g_Config.AuditMode == AUDIT_MODE_FULL && !READ_VOLATILE_32(&g_AuditPhase2MftOk))
      AuditScanTargetExtraRecursive(g_Config.DstPath, g_Config.DstPath);
    LONG srcTotal = READ_VOLATILE_32(&g_TotalFound);
    LONG dstTotal = READ_VOLATILE_32(&g_AuditDestFileCount);
    LONG miss = READ_VOLATILE_32(&g_AuditMissing);
    LONG szm = READ_VOLATILE_32(&g_AuditSizeMismatch);
    LONG tmm = READ_VOLATILE_32(&g_AuditTimeMismatch);
    LONG hsm = READ_VOLATILE_32(&g_AuditHashMismatch);
    LONG hse = READ_VOLATILE_32(&g_AuditHashError);
    LONG ext = READ_VOLATILE_32(&g_AuditExtra);
    if (g_Config.AuditMode == AUDIT_MODE_DST) {
      if (g_Config.AuditPrecount)
        PrintAndLog(L"[AUDIT] Baseline (target) files enumerated: %ld | Peer (source) files (initial count): %ld\n",
            srcTotal, g_AuditPeerCountInit);
      else
        PrintAndLog(L"[AUDIT] Baseline (target) files enumerated: %ld | Peer (source) initial count: N/A (use -precount for upfront tree total)\n",
            srcTotal);
      PrintAndLog(L"[AUDIT] Missing on source (peer absent): %ld | Extra@dst: n/a (dst-only mode) | Size: %ld | Time: %ld | Hash mismatch: %ld | Hash error: %ld\n",
          miss, szm, tmm, hsm, hse);
    } else {
      if (g_Config.AuditPrecount)
        PrintAndLog(L"[AUDIT] Baseline files enumerated: %ld | Target tree files (initial count): %ld\n",
            srcTotal, dstTotal);
      else
        PrintAndLog(L"[AUDIT] Baseline files enumerated: %ld | Target tree files (initial count): N/A (use -precount for upfront tree total)\n",
            srcTotal);
      if (g_Config.AuditMode == AUDIT_MODE_FULL)
        PrintAndLog(L"[AUDIT] Missing@dst: %ld | Extra@dst: %ld | Size: %ld | Time: %ld | Hash mismatch: %ld | Hash error: %ld\n",
            miss, ext, szm, tmm, hsm, hse);
      else
        PrintAndLog(L"[AUDIT] Missing@dst: %ld | Extra@dst: skipped (src mode) | Size: %ld | Time: %ld | Hash mismatch: %ld | Hash error: %ld\n",
            miss, szm, tmm, hsm, hse);
    }
    AuditReportLine(L"\n[SUMMARY]\n");
    if (g_Config.AuditMode == AUDIT_MODE_DST) {
      AuditReportLine(L"Baseline (target) files enumerated: %ld\n", srcTotal);
      if (g_Config.AuditPrecount)
        AuditReportLine(L"Peer (source) initial file count: %ld\n", g_AuditPeerCountInit);
      else
        AuditReportLine(L"Peer (source) initial file count: N/A (streaming; -precount for synchronous tree total)\n");
      AuditReportLine(L"Missing on source (peer path missing): %ld\n", miss);
      AuditReportLine(L"Extra on destination: n/a (dst-only audit)\n");
    } else {
      AuditReportLine(L"Baseline files enumerated: %ld\n", srcTotal);
      if (g_Config.AuditPrecount)
        AuditReportLine(L"Target tree file count (initial): %ld\n", dstTotal);
      else
        AuditReportLine(L"Target tree file count (initial): N/A (streaming; -precount for synchronous tree total)\n");
      AuditReportLine(L"Missing on destination: %ld\n", miss);
      if (g_Config.AuditMode == AUDIT_MODE_FULL)
        AuditReportLine(L"Extra on destination: %ld\n", ext);
      else
        AuditReportLine(L"Extra on destination: skipped (src mode)\n");
    }
    AuditReportLine(L"Size mismatch: %ld\n", szm);
    AuditReportLine(L"Time mismatch: %ld\n", tmm);
    AuditReportLine(L"Hash mismatch: %ld\n", hsm);
    AuditReportLine(L"Hash error: %ld\n", hse);
  }
  if (g_Config.CompareContent) {
    PrintAndLog(L"Hash Verify (%ls): %ld Success, %ld Fail\n",
            g_Config.UseXxh3 ? L"XXH3" : L"MD5", g_Md5Success, g_Md5Fail);
  }
  if (g_HardLinkCount > 0)
    wprintf(L"Hard Links: %ld (%.2f GB, zero-copy)\n", g_HardLinkCount,
            (double)g_HardLinkBytes / (1024.0 * 1024 * 1024));
  {
    LONG64 bc = READ_VOLATILE_64(&g_IoStrategyStats[IOSTRAT_BLOCK_CLONE]);
    LONG64 bd = READ_VOLATILE_64(&g_IoStrategyStats[IOSTRAT_BIG_DIRECT_IO]);
    LONG64 bb = READ_VOLATILE_64(&g_IoStrategyStats[IOSTRAT_BIG_BUFFERED]);
    if (bc > 0 || bd > 0 || bb > 0)
      PrintAndLog(L"IoStrategy (large path): block_clone=%lld direct_io=%lld buffered=%lld\n",
                  bc, bd, bb);
  }
  if (g_StateLonely > 0 || g_StateSame > 0 || g_StateOlder > 0 || g_StateTweaked > 0)
    wprintf(L"File States: Lonely=%ld Same=%ld Older=%ld Tweaked=%ld\n",
            (long)g_StateLonely, (long)g_StateSame, (long)g_StateOlder, (long)g_StateTweaked);
  }
  if (g_InsufficientSpace)
    exitCode = 2; /* 前置容量预检触发，优先于失败计数 */
  else if (g_TotalFailed > 0) {
    wprintf(L"  - Failed Files: %ld\n", g_TotalFailed);
    exitCode = 1;
  }
#if HAS_VSS
  CleanupVss(); /* 最后释放 VSS 快照，确保整个复制过程快照持续有效 */
#endif
  if (g_PdhQuery)
    PdhCloseQuery(g_PdhQuery);
  CloseHandle(g_hBigFileSemaphore);
  if (g_hMMFMapSemaphore) CloseHandle(g_hMMFMapSemaphore);
  CloseHandle(iocp);
  FreeAllPools();
  if (g_LogQueue)
    PB_ALIGNED_FREE(g_LogQueue);
  if (g_hLogEvent)
    CloseHandle(g_hLogEvent);
  AuditSrcPathFreeAll();
  AuditReportClose();
  if (g_hCleanupEvent)
    CloseHandle(g_hCleanupEvent);
  EmitIoStrategyJsonUtf8ToLog();
  if (g_fNormalLog)
    fclose(g_fNormalLog);
  if (g_fErrorLog)
    fclose(g_fErrorLog);
  DeleteCriticalSection(&g_PidCs);
  DeleteCriticalSection(&g_LogCs);
  timeEndPeriod(1);  /* 配对 timeBeginPeriod(1)，恢复系统默认定时器分辨率 */
  /* Round5 P3-架构1：释放 TLS 槽位，防止未来 DLL 化时槽位耗尽 */
  if (g_TlsTokenSlot != TLS_OUT_OF_INDEXES) { TlsFree(g_TlsTokenSlot); g_TlsTokenSlot = TLS_OUT_OF_INDEXES; }
  if (g_TlsArenaShardSlot != TLS_OUT_OF_INDEXES) { TlsFree(g_TlsArenaShardSlot); g_TlsArenaShardSlot = TLS_OUT_OF_INDEXES; }
  if (g_TlsCopierParamSlot != TLS_OUT_OF_INDEXES) { TlsFree(g_TlsCopierParamSlot); g_TlsCopierParamSlot = TLS_OUT_OF_INDEXES; }
  return exitCode;
}
// 提权辅助函数：用于激活管理员状态下的隐藏特权
BOOL EnablePrivilege(LPCWSTR lpszPrivilege) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    // 获取当前进程的令牌
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;
        
    // 查找特权对应的 LUID
    if (!LookupPrivilegeValueW(NULL, lpszPrivilege, &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return FALSE;
    }
    
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; // 核心：设为启用状态
    
    // 调整令牌特权
    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    CloseHandle(hToken);
    
    // AdjustTokenPrivileges 返回 TRUE 不代表完全成功，必须检查 GetLastError
    return (result && GetLastError() == ERROR_SUCCESS);
}

int main(void) {
  int argc;
  wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  if (!argv)
    return 1;
  int result = wmain(argc, argv);
  LocalFree(argv);
  return result;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
  UNREFERENCED_PARAMETER(hInstance);
  UNREFERENCED_PARAMETER(hPrevInstance);
  UNREFERENCED_PARAMETER(lpCmdLine);
  UNREFERENCED_PARAMETER(nCmdShow);
  return main();
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                    PWSTR pCmdLine, int nCmdShow) {
  UNREFERENCED_PARAMETER(hInstance);
  UNREFERENCED_PARAMETER(hPrevInstance);
  UNREFERENCED_PARAMETER(pCmdLine);
  UNREFERENCED_PARAMETER(nCmdShow);
  return main();
}
