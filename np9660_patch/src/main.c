/*
 *  Copyright (C) 2014 qwikrazor87
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <pspkernel.h>
#include <pspsysmem_kernel.h>
#include <psputilsforkernel.h>
#include <pspiofilemgr.h>
#include <pspctrl.h>
#include <string.h>
#include "lib.h"
#include "license.h"
#include "sctrl.h"
#include "iofilemgr_kernel.h"
#include "pgd.h"

PSP_MODULE_INFO("npdrm_free", PSP_MODULE_KERNEL, 1, 0);
PSP_HEAP_SIZE_KB(0);

int sceNpDrmEdataSetupKey(SceUID);
int sceNpDrmEdataGetDataSize(SceUID);
int sceKernelQuerySystemCall(void *);
int sceKernelDevkitVersionForUser(void);

#if defined(CONFIG_661) || defined(CONFIG_660)

#define EBOOT_CALL 0x1D0
#define LICENSE_CALL 0xED8
#define ACT_CALL 0x1028
#define WUT_OFFSET 0xC8
#define FIND_MODULE_BY_ADDRESS _sceKernelFindModuleByAddress_660
#define FIND_MODULE_BY_NAME _sceKernelFindModuleByName_660
#define SUB_000000C8_PATCH_OFFSET 0x40
#define STRCMP_PATCH_OFFSET 0xF2C

#elif defined(CONFIG_620)

#define EBOOT_CALL 0x1B8
#define LICENSE_CALL 0xEB4
#define ACT_CALL 0x1004
#define WUT_OFFSET 0xB0
#define FIND_MODULE_BY_ADDRESS _sceKernelFindModuleByAddress_620
#define FIND_MODULE_BY_NAME _sceKernelFindModuleByName_620
#define SUB_000000C8_PATCH_OFFSET 0x38
#define STRCMP_PATCH_OFFSET 0xF08

#else

#error "Please specify your firmware version with CONFIG_6xx"

#endif

static STMOD_HANDLER previous = NULL;
u32 np_text_addr = 0, np_text_size = 0;
int attempt = 0;
SceCtrlData pad;
char g_drmpath[256];
u8 g_drmkey[256];
u32 g_drmsize;
u8 g_pgdbuf[1024];
SceUID g_main_fd = -1;
int load_flag = 0;
char g_main_name[32];
u32 UserNpDrmEdataSetupKey = 0;
u32 UserNpDrmEdataGetDataSize = 0;
u32 UserIoOpen = 0;
u32 UserIoRead = 0;
u32 UserIoClose = 0;
int sceNp9660_driver_loaded = 0;

u32 g_has_version_key = 0;
u8 g_version_key[0x10];

int sceKernelStoreSyscall(void *func, u32 addr)
{
	int ret = sceKernelQuerySystemCall(func);

	if (ret > 0) {
		_sw(0x03E00008, addr);
		_sw(((ret << 6) | 12) & 0x03FFFFFF, addr + 4);

		sceKernelDcacheWritebackInvalidateRange((const void *)addr, 8);
		sceKernelIcacheInvalidateRange((const void *)addr, 8);
	}

	return ret;
}

void logracall(u32 ra)
{
	lprintf(NF_LOG_FULL, "\nsceNp9660_driver + 0x%08X\n", ra - np_text_addr - 8);
}

int npNpDrmGetVersionKey(u8 *version_key, u8 *act_buf, u8 *rif_buf, u32 type)
{
	logracall(pspGetRa());

	memcpy(rif_buf + 8, act_buf + 8, 8);

	int ret = sceNpDrmGetVersionKey(version_key, act_buf, rif_buf, type);

    if (g_has_version_key) {
        memcpy(version_key, g_version_key, 0x10);
    }

	lprintf(NF_LOG_FULL, "sceNpDrmGetVersionKey(0x%08X, 0x%08X, 0x%08X, 0x%08X);\nret: 0x%08X\n", version_key, act_buf, rif_buf, type, ret);

	return 0;
}

SceUID npIoOpen(const char *path, int flags, SceMode mode)
{
	u32 ra = pspGetRa();

	logracall(ra);

	SceUID ret = sceIoOpen(path, flags, mode);

	if ((ret >= 0) && ((ra - np_text_addr - 8) == EBOOT_CALL)) {
        SceUID ebootfd = ret;

        u32 psar_offset;
        sceIoLseek32(ebootfd, 0x24, PSP_SEEK_SET);
        sceIoRead(ebootfd, &psar_offset, 4);

        u8 buffer[0xC0];
        sceIoLseek32(ebootfd, psar_offset, PSP_SEEK_SET);
        sceIoRead(ebootfd, buffer, 0xC0);
        sceIoLseek32(ebootfd, 0, PSP_SEEK_SET);

        MAC_KEY mkey;
        u8 *mkey_p = (u8*) &mkey;
        sceDrmBBMacInit(mkey_p, 3);
        sceDrmBBMacUpdate(mkey_p, buffer, 0xC0);
        get_version_key(ebootfd, mkey_p, g_version_key);
        g_has_version_key = 1;
    }

	if ((u32)ret == 0x80010002) {
		u32 license_call = 0, act_call = 0;

        license_call = LICENSE_CALL;
        act_call = ACT_CALL;

		if ((ra - np_text_addr - 8) == license_call) {	//.rif license
			ret = sceIoOpen(path, PSP_O_CREAT | PSP_O_WRONLY | PSP_O_TRUNC, 0777);
			sceIoWrite(ret, psp_license, sizeof(psp_license));
			sceIoClose(ret);

			ret = sceIoOpen(path, flags, mode);
		} else if ((ra - np_text_addr - 8) == act_call) {	//act.dat
			sceIoUnassign("flash2:");
			sceIoAssign("flash2:", "lflash0:0,2", "flashfat2:", IOASSIGN_RDWR, NULL, 0);

			ret = sceIoOpen("flash2:/act.dat", PSP_O_CREAT | PSP_O_WRONLY | PSP_O_TRUNC | 0x04000000, 0777);
			sceIoWrite(ret, fake_act_dat, sizeof(fake_act_dat));
			sceIoClose(ret);

			sceIoUnassign("flash2:");
			sceIoAssign("flash2:", "lflash0:0,2", "flashfat2:", IOASSIGN_RDONLY, NULL, 0);

			ret = sceIoOpen(path, flags, mode);
		}
	}

	lprintf(NF_LOG_FULL, "sceIoOpen(\"%s\", 0x%X, 0x%X);\nret: 0x%08X\n", path, flags, mode, ret);

	return ret;
}

int sub_000000C8(const char *eboot, u32 a1)
{
	logracall(pspGetRa());

	int (* wut)(const char *, u32) = (void *)0;

    wut = (void *)(np_text_addr + WUT_OFFSET);

	int ret = wut(eboot, a1);

	lprintf(NF_LOG_FULL, "sub_000000C8(\"%s\", 0x%08X);\nret: 0x%08X\n", eboot, a1, ret);

	return ret;
}

void patch_np9660(u32 text_addr, u32 text_size)
{
	sceNp9660_driver_loaded = 1;

    _sceKernelFindModuleByAddress = (void *)FIND_MODULE_BY_ADDRESS ;
    _sceKernelFindModuleByName = (void *)FIND_MODULE_BY_NAME ;

	sceCtrlPeekBufferPositive(&pad, 1);

    init_log(NF_LOG_DISABLED);
	//if (pad.Buttons & PSP_CTRL_CROSS) {
    //    init_log(NF_LOG_FULL);
    //} else {
    //    init_log(NF_LOG_DISABLED);
    //}

	np_text_addr = text_addr;
	np_text_size = text_size;

	const char *sceNp9660_driver = "sceNp9660_driver";

	u32 _IoOpen = FindImportByModule(sceNp9660_driver, "IoFileMgrForKernel", 0x109F50BC);
	_sw(MAKE_JUMP(npIoOpen), _IoOpen);
	u32 _NpDrmGetVersionKey = FindImportByModule(sceNp9660_driver, "scePspNpDrm_driver", 0x0F9547E6);
	_sw(MAKE_JUMP(npNpDrmGetVersionKey), _NpDrmGetVersionKey);

    _sw(MAKE_CALL(sub_000000C8), np_text_addr + SUB_000000C8_PATCH_OFFSET);

	//patch strcmp check on license name
    _sw(0x24020000, np_text_addr + STRCMP_PATCH_OFFSET);  //li $v0, 0

	ClearCaches();
}

int sceNpDrmFreeEdataSetupKey(SceUID fd)
{
	int ret = sceNpDrmEdataSetupKey(fd);

	if (ret < 0) {
		u32 k1 = pspSdkSetK1(0);

		SceUID g_fd = sceIoOpen(g_drmpath, PSP_O_RDONLY, 0777);

		u8 header[8];

		sceIoRead(g_fd, header, 8);

		if (!memcmp(header, "\0PSPEDAT", 8)) {
			sceIoLseek(g_fd, 0x80, PSP_SEEK_SET);

			sceIoRead(g_fd, header, 4);

			if (!memcmp(header, "\0PGD", 4)) {
				u32 size = sceIoLseek(g_fd, 0, PSP_SEEK_END) - 0x80;

				sceIoLseek(g_fd, 0x80, PSP_SEEK_SET);

				sceIoRead(g_fd, g_pgdbuf, size);

				g_drmsize = pgd_decrypt(g_pgdbuf, size, 2, NULL);

				if (g_drmsize > 0) {
					memcpy(g_drmkey, g_pgdbuf + 0x90, g_drmsize);

					ret = 0;
				}
			}
		}

		sceIoClose(g_fd);

		pspSdkSetK1(k1);
	}

	return ret;
}

int sceNpDrmFreeEdataGetDataSize(SceUID fd)
{
	int ret = sceNpDrmEdataGetDataSize(fd);

	if (ret < 0)
		ret = g_drmsize;

	return ret;
}

SceUID sceNpDrmFreeOpen(const char *path, int flags, SceMode mode)
{
	SceUID fd = sceIoOpen(path, flags, mode);

	if ((flags & 0x40000000) && (fd > 0)) {
		strcpy(g_drmpath, path);
		g_main_fd = fd;
	}

	return fd;
}

int sceNpDrmFreeRead(SceUID fd, void *data, SceSize size)
{
	int ret = sceIoRead(fd, data, size);

	if ((ret < 0) && (fd == g_main_fd)) {
		memcpy(data, g_drmkey, g_drmsize);

		ret = g_drmsize;
	}

	return ret;
}

int sceNpDrmFreeClose(SceUID fd)
{
	if (fd == g_main_fd)
		g_main_fd = -1;

	return sceIoClose(fd);
}

void patch_main_module()
{
	if (!UserNpDrmEdataSetupKey)
		UserNpDrmEdataSetupKey = FindImportByModule(g_main_name, "scePspNpDrm_user", 0x08D98894);

	if (UserNpDrmEdataSetupKey)
		sceKernelStoreSyscall(sceNpDrmFreeEdataSetupKey, UserNpDrmEdataSetupKey);

	if (!UserNpDrmEdataGetDataSize)
		UserNpDrmEdataGetDataSize = FindImportByModule(g_main_name, "scePspNpDrm_user", 0x219EF5CC);

	if (UserNpDrmEdataGetDataSize)
		sceKernelStoreSyscall(sceNpDrmFreeEdataGetDataSize, UserNpDrmEdataGetDataSize);

	if (UserNpDrmEdataSetupKey) {
		if (!UserIoOpen)
			UserIoOpen = FindImportByModule(g_main_name, "IoFileMgrForUser", 0x109F50BC);

		if (UserIoOpen)
			sceKernelStoreSyscall(sceNpDrmFreeOpen, UserIoOpen);

		if (!UserIoRead)
			UserIoRead = FindImportByModule(g_main_name, "IoFileMgrForUser", 0x6A638D83);

		if (UserIoRead)
			sceKernelStoreSyscall(sceNpDrmFreeRead, UserIoRead);

		if (!UserIoClose)
			UserIoClose = FindImportByModule(g_main_name, "IoFileMgrForUser", 0x810C4BC3);

		if (UserIoClose)
			sceKernelStoreSyscall(sceNpDrmFreeClose, UserIoClose);
	}

	ClearCaches();
}

int module_start_handler(SceModule2 * module)
{
	int ret = previous ? previous(module) : 0;

	if (load_flag >= 1) {
		if (load_flag == 1) {
			strcpy(g_main_name, module->modname);
			load_flag = 2;
		}

		patch_main_module();
	}

	if (!strcmp(module->modname, "sceNp9660_driver"))
		patch_np9660(module->text_addr, module->text_size);
	else if ((sceNp9660_driver_loaded == 1) && !strcmp(module->modname, "sceKernelLibrary"))
		load_flag = 1;

	return ret;
}

int thread_start(SceSize args __attribute__((unused)), void *argp __attribute__((unused)))
{
	previous = sctrlHENSetStartModuleHandler(module_start_handler);

	return 0;
}

int module_start(SceSize args, void *argp)
{
	SceUID thid = sceKernelCreateThread("npdrm_free", thread_start, 0x22, 0x2000, 0, NULL);

	if (thid >= 0)
		sceKernelStartThread(thid, args, argp);

	return 0;
}

int module_stop(SceSize args __attribute__((unused)), void *argp __attribute__((unused)))
{
	return 0;
}
