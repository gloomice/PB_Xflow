/*
 * ipc_telemetry.h - PB X-Flow 跨进程二进制遥测协议
 * C/C++ 共用。第五轮：Shared Memory + Seqlock 替代命名管道，零内核切换。
 */
#pragma once

#ifndef USE_SHM_TELEMETRY
#define USE_SHM_TELEMETRY 1    /* 1=共享内存+Seqlock，0=命名管道（回退）；-D 可覆盖 */
#endif

#include <windows.h>  /* LONG: 与 InterlockedXxx 签名精确对齐；本头文件纯 Windows 平台专用 */
#include <stdint.h>   /* Round5 P3-架构3：移出 extern "C" 块，避免 MSVC <vcruntime.h> 链接冲突 */

#ifdef __cplusplus
extern "C" {
#endif

#define TELEMETRY_PIPE_PREFIX   L"\\\\.\\pipe\\PBXFlow_Telemetry_"
/* Local\\：同 Session 内 GUI↔引擎，无需 SeCreateGlobalPrivilege（非管理员也可 CreateFileMapping） */
#define TELEMETRY_SHM_PREFIX    L"Local\\PBXFlow_Telemetry_"
#define TELEMETRY_MAGIC         0x46415354  /* "FAST" */
#define TELEMETRY_STOP_EVENT    L"Local\\XFlow_Stop_Event_"
#define TELEMETRY_PAUSE_RELEASE_EVENT L"Local\\XFlow_PauseRelease_Event_"

/* 结构体必须 1 字节对齐，防止跨编译器填充差异
 * Phase 3：扩展至 72 字节，增加 eta_seconds；version=2
 * Round4：reserved_eta 重命名为 failedFiles，字节偏移不变，ABI 完全兼容 version=2 */
#pragma pack(push, 1)
typedef struct {
    uint32_t magic;             /* 校验魔数 TELEMETRY_MAGIC */
    uint64_t totalFiles;        /* 扫描到的总文件数 */
    uint64_t copiedFiles;       /* 已复制的文件数 */
    uint64_t totalBytes;        /* 总字节数 */
    uint64_t copiedBytes;       /* 已复制字节数 */
    uint32_t currentSpeedMBps;  /* 当前流速 (MB/s) */
    uint32_t activeThreads;     /* 当前活跃的 I/O 线程数 */
    uint32_t isFinished;        /* 0=运行中, 1=正常结束, 2=异常/取消 */
    uint16_t version;           /* 协议版本：1=基础, 2=含 eta_seconds + failedFiles */
    /* Phase 16 Ack Slots：引擎确权回执，GUI 绑定 ack 显示消除闪烁 */
    volatile uint8_t  ack_SpeedLimit; /* 引擎已应用的限速 MB/s，0=不限，>255 显示 255 */
    volatile uint8_t  ack_Pause;      /* 引擎已应用的暂停状态 0/1 */
    /* Phase 8 反向控制槽：纳秒级指令下发，引擎每轮循环 1 周期读取 */
    volatile uint32_t cmd_Pause;      /* 0=运行, 1=暂停 (WaitOnAddress) */
    volatile uint32_t cmd_SpeedLimit; /* 0=不限速, 其他=目标 MB/s */
    volatile uint32_t cmd_Cancel;     /* 1=请求优雅退出 */
    /* Phase 3 ETA + Round4 失败计数：与 eta_seconds 共占 8 字节，ABI 不变 */
    uint32_t eta_seconds;       /* 剩余秒数，0=未知/不适用，GUI 可直接显示 */
    uint32_t failedFiles;       /* 引擎原子计数的累计失败文件数（Single Source of Truth）*/
    /* v3：大文件 I/O 策略计数（企业遥测 / TSDB 归因；引擎 Interlocked 累加） */
    uint64_t io_block_clone;
    uint64_t io_direct_big;
    uint64_t io_buffered_big;
} TelemetryData;
#pragma pack(pop)
#define TELEMETRY_DATA_SIZE (sizeof(TelemetryData))

/* 第五轮：SharedTelemetry = Seqlock(seq) + TelemetryData；LONG 类型与 InterlockedXxx ABI 严格对齐
 * Phase 13 Dirty Flag：GUI 写 cmd_* 后置 isDirty=1，引擎仅当 isDirty 时读取，热路径 1 条 load
 * Phase 19 拓扑隔离：seq(Engine->GUI) 与 isDirty(GUI->Engine) 分置独立 Cache Line，消灭跨核缓存行乒乓
 * Round4 UB 修复：seq 改为 volatile LONG，与 InterlockedIncrement 签名精确匹配，消除 Strict Aliasing UB */
#pragma pack(push, 1)
typedef struct {
    /* Cache Line 1: 绝对单向 (Engine -> GUI)，seq 30Hz 写入 */
    volatile LONG seq;          /* 必须为 LONG：与 InterlockedIncrement/InterlockedAdd 签名一致，无需强制类型转换 */
    char _pad1[64 - sizeof(LONG)];

    /* Cache Line 2: 绝对单向 (GUI -> Engine)，isDirty 偶发写入 */
    volatile uint8_t isDirty;
    char _pad2[64 - sizeof(uint8_t)];

    /* Cache Line 3+: 数据载荷 (Engine -> GUI) */
    TelemetryData data;
} SharedTelemetry;
#pragma pack(pop)
#define SHARED_TELEMETRY_SIZE (sizeof(SharedTelemetry))
#if defined(__cplusplus)
/* C++: static_assert 内置 */
static_assert(sizeof(SharedTelemetry) == 224, "SharedTelemetry ABI");  /* 64+64+96 v3 */
static_assert(sizeof(TelemetryData) == 96, "TelemetryData v3 96B");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
/* C11: _Static_assert，GCC/Clang 支持；MSVC 需 /std:c11 */
_Static_assert(sizeof(SharedTelemetry) == 224, "SharedTelemetry ABI");
_Static_assert(sizeof(TelemetryData) == 96, "TelemetryData v3 96B");
#else
/* MSVC 默认 C 模式无 _Static_assert，用 typedef 触发编译期断言 */
typedef char _ct_assert_SharedTelemetry[(sizeof(SharedTelemetry) == 224) ? 1 : -1];
typedef char _ct_assert_TelemetryData[(sizeof(TelemetryData) == 96) ? 1 : -1];
#endif

#define TELEMETRY_PROTOCOL_VERSION 3

/* P3 遥测频率大一统：33ms ≈ 30Hz，C 引擎与 GUI 心跳共振，降低无效轮询与功耗 */
#ifndef TELEMETRY_THROTTLE_MS
#define TELEMETRY_THROTTLE_MS 33
#endif

/* Phase 8 零拷贝共享内存日志环：SPSC 无锁，引擎写 head，GUI 读 tail，零内核切换
 * 记录格式: [4B size][2B level][UTF-16 数据 null-term]，size 含头 6 字节
 * P2 Magic Ring：metadata 与 buffer 分离，buffer 独立双重映射，写入无分支
 * MapViewOfFileEx 要求偏移量为系统分配粒度(64KB)的整数倍 */
#define LOG_RING_SIZE (4ULL * 1024 * 1024)  /* 4MB，64 位寻址防截断 */
#define LOG_RING_ALLOC_GRANULARITY 65536
#if defined(__cplusplus)
static_assert(LOG_RING_SIZE % LOG_RING_ALLOC_GRANULARITY == 0, "LOG_RING_SIZE must be multiple of 64KB");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(LOG_RING_SIZE % LOG_RING_ALLOC_GRANULARITY == 0, "LOG_RING_SIZE must be multiple of 64KB");
#else
typedef char _ct_assert_LogRingSize[(LOG_RING_SIZE % LOG_RING_ALLOC_GRANULARITY == 0) ? 1 : -1];
#endif
#define LOG_RING_SHM_SUFFIX   L"_LogRing"   /* metadata 映射名 */
#define LOG_RING_BUF_SUFFIX   L"_LogRingBuf" /* buffer 映射名，独立双重映射 */
/* LogRing 唤醒：手动重置事件，GUI 创建 Local\\PBXFlow_LogRing_Event_<PID>，
 * 引擎 OpenEvent(EVENT_MODIFY_STATE) 后按需 SetEvent；消费者侧 Drain-and-Wait + ResetEvent + 二次检查 head/tail */
#define LOG_RING_EVENT_PREFIX L"Local\\PBXFlow_LogRing_Event_"
/* N18 注释：head 由引擎写（store），tail 由 GUI 读/写（load-store）。
 * x64 TSO 模型下 volatile uint32_t 的 store/load 已保证顺序可见性，当前代码正确。
 * 若将来移植到 ARM64（非 TSO）：
 *   - 引擎写 head 时需 __atomic_store_n(&head, val, __ATOMIC_RELEASE)
 *   - GUI 读 head 时需 __atomic_load_n(&head, __ATOMIC_ACQUIRE)
 *   - GUI 写 tail 时需 __atomic_store_n(&tail, val, __ATOMIC_RELEASE)
 *   - 引擎读 tail 时需 __atomic_load_n(&tail, __ATOMIC_ACQUIRE)
 * 当前 LIGHT_BARRIER() 在 x64 下为 _ReadWriteBarrier()（编译器屏障），
 * 在 ARM64 下为 MemoryBarrier()（DMB ISH），已覆盖需求，但代码意图不够清晰。 */
#pragma pack(push, 1)
typedef struct {
    volatile uint32_t head;     /* 引擎写入偏移：循环值 [0, LOG_RING_SIZE)，由引擎取模后写入；x64 TSO 安全 */
    char _pad1[60];             /* 独立 Cache Line，避免 head/tail 伪共享 */
    volatile uint32_t tail;     /* GUI 读取偏移：循环值 [0, LOG_RING_SIZE)，由 GUI 取模后写入；x64 TSO 安全 */
    char _pad2[60];
} SharedLogRingMeta;
#pragma pack(pop)
#define SHARED_LOG_RING_META_SIZE (sizeof(SharedLogRingMeta))
/* 兼容旧代码：SharedLogRing 别名，仅 metadata 部分 */
typedef SharedLogRingMeta SharedLogRing;
#define SHARED_LOG_RING_SIZE SHARED_LOG_RING_META_SIZE

#ifdef __cplusplus
}
#endif
