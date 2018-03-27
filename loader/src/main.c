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
#include <string.h>
#include "lib.h"
#include "sctrl.h"
#include "np9660_patch.h"
#include "pgd.h"

PSP_MODULE_INFO("npdrm_free", PSP_MODULE_KERNEL, 1, 0);
PSP_HEAP_SIZE_KB(0);

#if defined(CONFIG_661) || defined(CONFIG_660)

#define sceKernelQuerySystemCall sceKernelQuerySystemCall_660
#define GAME_PATCH1_OFFSET1 0x2ADE4
#define GAME_PATCH1_OFFSET2 0x2ADEC
#define GAME_PATCH2_OFFSET1 0x159E8
#define GAME_PATCH2_OFFSET2 0x159E4
#define GAME_PATCH3_OFFSET1 0x15A74
#define GAME_PATCH3_OFFSET2 0x15A70
#define VSH_PATCH_OFFSET1 0x12000
#define VSH_PATCH_OFFSET2 0x11FFC

#elif defined(CONFIG_620)

#define sceKernelQuerySystemCall sceKernelQuerySystemCall_620
#define GAME_PATCH1_OFFSET1 0x28E68
#define GAME_PATCH1_OFFSET2 0x28E70
#define GAME_PATCH2_OFFSET1 0x146C4
#define GAME_PATCH2_OFFSET2 0x146C0
#define GAME_PATCH3_OFFSET1 0x14750
#define GAME_PATCH3_OFFSET2 0x1474C
#define VSH_PATCH_OFFSET1 0x11A1C
#define VSH_PATCH_OFFSET2 0x11A18

#else

#error "Please specify your firmware version with CONFIG_6xx"

#endif

static STMOD_HANDLER previous = NULL;

char g_drmpath[256];
u8 g_drmkey[8];
u8 g_pgdbuf[0xC0];
SceUID g_fd;
int g_drmsize;

int sceNpDrmEdataSetupKey(SceUID);
int sceNpDrmEdataGetDataSize(SceUID);
int sceKernelQuerySystemCall_660(void *);
int sceKernelQuerySystemCall_620(void *);
int sceKernelDevkitVersionForUser(void);

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

int sceNpDrmFreeEdataSetupKey(SceUID fd)
{
	int ret = sceNpDrmEdataSetupKey(fd);

	if (ret < 0) {
		u32 k1 = pspSdkSetK1(0);

		g_fd = sceIoOpen(g_drmpath, PSP_O_RDONLY, 0777);

		u8 header[8];

		sceIoRead(g_fd, header, 8);

		if (!memcmp(header, "\0PSPEDAT", 8)) {
			sceIoLseek(g_fd, 0x80, PSP_SEEK_SET);

			sceIoRead(g_fd, header, 4);

			if (!memcmp(header, "\0PGD", 4)) {
				sceIoLseek(g_fd, 0x80, PSP_SEEK_SET);

				sceIoRead(g_fd, g_pgdbuf, 0xC0);

				g_drmsize = pgd_decrypt(g_pgdbuf, 0xC0, 2, NULL);

				if (g_drmsize > 0) {
					memcpy(g_drmkey, g_pgdbuf + 0x90, 8);

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

int sceNpDrmFreeOpen(const char *path, int flags, SceMode mode)
{
	strcpy(g_drmpath, path);

	return sceIoOpen(path, flags, mode);
}

int sceNpDrmFreeRead(SceUID fd, void *data, SceSize size)
{
	int ret = sceIoRead(fd, data, size);

	if (ret < 0) {
		memcpy(data, g_drmkey, 8);

		ret = 8;
	}

	return ret;
}

void patch_game_plugin_module(u32 text_addr)
{
    sceKernelStoreSyscall(sceNpDrmFreeEdataSetupKey, text_addr + GAME_PATCH1_OFFSET1);
    sceKernelStoreSyscall(sceNpDrmFreeEdataGetDataSize, text_addr + GAME_PATCH1_OFFSET2);

	int syscall = sceKernelQuerySystemCall(sceNpDrmFreeOpen);

    _sw(_lw(text_addr + GAME_PATCH2_OFFSET1), text_addr + GAME_PATCH2_OFFSET2);
    _sw(((syscall << 6) | 12) & 0x03FFFFFF, text_addr + GAME_PATCH2_OFFSET1);

    sceKernelDcacheWritebackInvalidateRange((const void *)(text_addr + GAME_PATCH2_OFFSET2), 8);
    sceKernelIcacheInvalidateRange((const void *)(text_addr + GAME_PATCH2_OFFSET2), 8);

	syscall = sceKernelQuerySystemCall(sceNpDrmFreeRead);

    _sw(_lw(text_addr + GAME_PATCH3_OFFSET1), text_addr + GAME_PATCH3_OFFSET2);
    _sw(((syscall << 6) | 12) & 0x03FFFFFF, text_addr + GAME_PATCH3_OFFSET1);

    sceKernelDcacheWritebackInvalidateRange((const void *)(text_addr + GAME_PATCH3_OFFSET2), 8);
    sceKernelIcacheInvalidateRange((const void *)(text_addr + GAME_PATCH3_OFFSET2), 8);
}

void *vshCheckBootable(void *dst, const void *src, int size)
{
	SFO *sfo = (SFO *)src;

	int i;

	for (i = 0; i < sfo->entries; i++) {
		if (!strcmp((char *)((u32)src + sfo->label + sfo->sfotable[i].label_offset), "BOOTABLE")) {
			if (_lw((u32)src + sfo->data + sfo->sfotable[i].data_offset) == 2)
				_sw(1, (u32)src + sfo->data + sfo->sfotable[i].data_offset);

			break;
		}
	}

	return memcpy(dst, src, size);
}

void patch_vsh_module(u32 text_addr)
{
	int syscall = sceKernelQuerySystemCall(vshCheckBootable);

    _sw(_lw(text_addr + VSH_PATCH_OFFSET1), text_addr + VSH_PATCH_OFFSET2);
    _sw(((syscall << 6) | 12) & 0x03FFFFFF, text_addr + VSH_PATCH_OFFSET1);

    sceKernelDcacheWritebackInvalidateRange((const void *)(text_addr + VSH_PATCH_OFFSET2), 8);
    sceKernelIcacheInvalidateRange((const void *)(text_addr + VSH_PATCH_OFFSET2), 8);
}

int module_start_handler(SceModule2 * module)
{
	int ret = previous ? previous(module) : 0;

	if (!strcmp(module->modname, "game_plugin_module"))
		patch_game_plugin_module(module->text_addr);
	else if (!strcmp(module->modname, "vsh_module"))
		patch_vsh_module(module->text_addr);

	return ret;
}

int thread_start(SceSize args __attribute__((unused)), void *argp __attribute__((unused)))
{
	previous = sctrlHENSetStartModuleHandler(module_start_handler);

	SceUID blockid = sceKernelAllocPartitionMemory(1, "kernel_module", PSP_SMEM_Low, size_np9660_patch, NULL);
	void *modbuf = sceKernelGetBlockHeadAddr(blockid);

	if (blockid >= 0) {
		memcpy(modbuf, np9660_patch, size_np9660_patch);
		sctrlHENLoadModuleOnReboot("/kd/np9660.prx", modbuf, size_np9660_patch, BOOTLOAD_UMDEMU);
	}

	SceIoStat stat;

	if (sceIoGetstat("ms0:/PSP/LICENSE", &stat) < 0)
		sceIoMkdir("ms0:/PSP/LICENSE", 0777);

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
