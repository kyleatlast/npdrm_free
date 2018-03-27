/* Copyright (C) 2011, 2012 The uOFW team
   See the file COPYING for copying permission.
*/

#define SCE_O_RDONLY    0x0001
#define SCE_O_WRONLY    0x0002
#define SCE_O_RDWR      (SCE_O_RDONLY | SCE_O_WRONLY)
#define SCE_O_NBLOCK    0x0004
#define SCE_O_DIROPEN   0x0008  // Internal use for dopen
#define SCE_O_APPEND    0x0100
#define SCE_O_CREAT     0x0200
#define SCE_O_TRUNC     0x0400
#define SCE_O_EXCL      0x0800
#define SCE_O_NOWAIT    0x8000
#define SCE_O_UNKNOWN0  0x04000000

/** user read/write/execute permission. */
#define SCE_STM_RWXU		00700
/** user read permission. */
#define SCE_STM_RUSR		00400
/** user write permission. */
#define SCE_STM_WUSR		00200
/** user execute permission. */
#define SCE_STM_XUSR		00100

/** group read/write/execute permission. */
#define SCE_STM_RWXG		00070
/** group read permission. */
#define SCE_STM_RGRP		00040
/** group write permission. */
#define SCE_STM_WGRP		00020
/** group execute permission. */
#define SCE_STM_XGRP		00010

/** other read/write/execute permission. */
#define SCE_STM_RWXO		00007
/** other read permission. */
#define SCE_STM_ROTH		00004
/** other write permission. */
#define SCE_STM_WOTH		00002
/** other execute permission. */
#define SCE_STM_XOTH		00001

/** user/group/other - read/write/execute. */
#define SCE_STM_RWXUGO	(SCE_STM_RWXU|SCE_STM_RWXG|SCE_STM_RWXO)
/** user/group/other - read. */
#define SCE_STM_RUGO	(SCE_STM_RUSR|SCE_STM_RGRP|SCE_STM_ROTH)
/** user/group/other - write. */
#define SCE_STM_WUGO	(SCE_STM_WUSR|SCE_STM_WGRP|SCE_STM_WOTH)
/** user/group/other - execute. */
#define SCE_STM_XUGO	(SCE_STM_XUSR|SCE_STM_XGRP|SCE_STM_XOTH)

#define SCE_SEEK_SET    0
#define SCE_SEEK_CUR    1
#define SCE_SEEK_END    2

struct SceIoDeviceArg;
typedef struct SceIoDeviceArg SceIoDeviceArg;
struct SceIoIob;
typedef struct SceIoIob SceIoIob;

typedef struct
{
    int (*IoInit)(SceIoDeviceArg *dev);
    int (*IoExit)(SceIoDeviceArg *dev);
    int (*IoOpen)(SceIoIob *iob, char *file, int flags, SceMode mode);
    int (*IoClose)(SceIoIob *iob);
    int (*IoRead)(SceIoIob *iob, char *data, int len);
    int (*IoWrite)(SceIoIob *iob, const char *data, int len);
    SceOff (*IoLseek)(SceIoIob *iob, SceOff ofs, int whence);
    int (*IoIoctl)(SceIoIob *iob, unsigned int cmd, void *indata, int inlen, void *outdata, int outlen);
    int (*IoRemove)(SceIoIob *iob, const char *name);
    int (*IoMkdir)(SceIoIob *iob, const char *name, SceMode mode);
    int (*IoRmdir)(SceIoIob *iob, const char *name);
    int (*IoDopen)(SceIoIob *iob, const char *dirname);
    int (*IoDclose)(SceIoIob *iob);
    int (*IoDread)(SceIoIob *iob, SceIoDirent *dir);
    int (*IoGetstat)(SceIoIob *iob, const char *file, SceIoStat *stat);
    int (*IoChstat)(SceIoIob *iob, const char *file, SceIoStat *stat, int bits);
    int (*IoRename)(SceIoIob *iob, const char *oldname, const char *newname);
    int (*IoChdir)(SceIoIob *iob, const char *dir);
    int (*IoMount)(SceIoIob *iob, const char *fs, const char *blockDev, int mode, void *unk1, int unk2);
    int (*IoUmount)(SceIoIob *iob, const char *blockDev);
    int (*IoDevctl)(SceIoIob *iob, const char *devname, unsigned int cmd, void *indata, int inlen, void *outdata, int outlen);
    int (*IoCancel)(SceIoIob *iob);
} SceIoDrvFuncs;

typedef struct
{
    const char *name;
    u32 dev_type;
    u32 unk2;
    const char *name2;
    SceIoDrvFuncs *funcs;
} SceIoDrv;

struct SceIoDeviceArg
{
    SceIoDrv *drv;
    void *argp;
    int openedFiles;
};

struct SceIoHookType;
typedef struct SceIoHookType SceIoHookType;

struct SceIoHook;
typedef struct SceIoHook SceIoHook;

typedef struct
{
    void (*Add)(SceIoHookType **hook);
    int unused4;
    int (*Preobe)(SceIoHook *hook, char *file, int flags, SceMode mode);
    int (*Open)(SceIoHook *hook, char *file, int flags, SceMode mode);
    int (*Close)(SceIoHook *hook);
    int (*Read)(SceIoHook *hook, void *data, SceSize size);
    int (*Write)(SceIoHook *hook, const void *data, SceSize size);
    SceOff (*Lseek)(SceIoHook *hook, SceOff ofs, int whence);
    int (*Ioctl)(SceIoHook *iob, unsigned int cmd, void *indata, int inlen, void *outdata, int outlen);
} SceIoHookFuncs;

struct SceIoHookType
{
    char *name;
    int unk4;
    int unk8;
    char *name2;
    SceIoHookFuncs *funcs;
};

typedef struct
{
    int size; // 0
    char name[32]; // 4
    int attribute; // 36
    int unk40; // 40
    const char *drvName; // 44
    int fsNum; // 48
    char *newPath; // 52
    int retAddr; // 56
    int curThread; // 60
    int asyncThread; // 64
    int isAsync; // 68
    int asyncCmd; // 72
    SceIoIob *iob; // 76
    int unk80; // 80
    int unk84; // 84
} SceIoFdDebugInfo;

typedef struct
{
    SceIoHookType *hook;
    void *argp;
} SceIoHookArg;

struct SceIoHook
{
    SceIoHookArg *arg;
    SceIoIob *iob;
    SceIoDrvFuncs *funcs;
};

struct SceIoIob
{
    int unk000; // some ID
    int fsNum; // 4
    SceIoDeviceArg *dev; // 8
    int dev_type; // 12
    int unk016; // 16
    int unk020; // 20
    int unk024; // 24
    int unk028; // 28
    int unk032; // 32
    int unk036; // 36
    int unk040; // 40
    SceUID curThread; // 44
    char userMode; // 48
    char powerLocked; // 49
    char unk050;
    char asyncPrio; // 51
    SceUID asyncThread; // 52
    SceUID asyncSema; // 56
    SceUID asyncEvFlag; // 60
    SceUID asyncCb; // 64
    void *asyncCbArgp; // 68
    int unused72; // 72
    int k1; // 76
    s64 asyncRet; // 80
    int asyncArgs[6]; // 88
    int asyncCmd; // 112
    int userLevel; // 116
    SceIoHook hook; // 120
    int unk132; // 132
    char *newPath; // 136
    int retAddr; // 140
};

/* IO-Assign mount mode flags. */
#define SCE_MT_RDWR	          0x00 /** Mount as read/write enabled. */
#define SCE_MT_RDONLY	      0x01 /** Mount as read-only. */
#define SCE_MT_ROBUST	      0x02 /** Mount in ROBUST mode. */
#define SCE_MT_ERRCHECK       0x04 /** Set an error if there is anythign abnormal in the file system when mounting. */