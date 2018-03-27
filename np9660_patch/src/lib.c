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
#include <psputilsforkernel.h>
#include <string.h>
#include <stdio.h>
#include "lib.h"
#include "sctrl.h"


static char logbuf[256];
static u32 g_log_level;

static void logstr(const char *str)
{
	SceUID fd = sceIoOpen("ms0:/npdrmlog.txt", 0x302, 0777);
	sceIoWrite(fd, str, strlen(str));
	sceIoClose(fd);
}

void init_log(u32 log_level)
{
    g_log_level = log_level;
    if (log_level > NF_LOG_DISABLED) {
		SceUID fd = sceIoOpen("ms0:/npdrmlog.txt", 0x602, 0777);
		sceIoClose(fd);
	}
}

void _lprintf(const u32 log_level, const char *fmt, u32 a2, u32 a3, u32 t0, u32 t1, u32 t2, u32 t3, u32 t4, u32 t5, u32 t6, u32 t7)
{
	if (log_level <= g_log_level) {
		sprintf(logbuf, fmt, a2, a3, t0, t1, t2, t3, t4, t5, t6, t7);
		logstr(logbuf);
	}
}

void (* lprintf)(const u32 log_level, const char *, ...) = (void *)&_lprintf;

void ClearCaches(void)
{
	sceKernelDcacheWritebackInvalidateAll();
	sceKernelIcacheInvalidateAll();
}

u32 FindTextAddrByName(const char *module)
{
	u32 kaddr;
	for (kaddr = 0x88000000; kaddr < 0x88400000; kaddr += 4) {
		if (strcmp((const char *)kaddr, module) == 0) {
			if ((*(u32*)(kaddr + 0x64) == *(u32*)(kaddr + 0x78)) && \
				(*(u32*)(kaddr + 0x68) == *(u32*)(kaddr + 0x88))) {
				if (*(u32*)(kaddr + 0x64) && *(u32*)(kaddr + 0x68))
					return *(u32*)(kaddr + 0x64);
			}
		}
	}
	return 0;
}

u32 FindExport(const char *module, const char *library, u32 nid)
{
	u32 addr = FindTextAddrByName(module);

	if (addr) {
		u32 maxaddr = 0x88400000;

		if (addr >= 0x08800000 && addr < 0x0A000000)
			maxaddr = 0x0A000000;
		else if (addr >= 0x08400000 && addr < 0x08800000)
			maxaddr = 0x08800000;

		for (; addr < maxaddr; addr += 4) {
			if (strcmp(library, (const char *)addr) == 0) {
				u32 libaddr = addr;

				while (*(u32*)(addr -= 4) != libaddr);

				u32 exports = (u32)(*(u16*)(addr + 10) + *(u8*)(addr + 9));
				u32 jump = exports * 4;

				addr = *(u32*)(addr + 12);

				while (exports--) {
					if (*(u32*)addr == nid)
						return *(u32*)(addr + jump);

					addr += 4;
				}

				return 0;
			}
		}
	}

	return 0;
}

void fillvram(u32 color)
{
	u32 vram;

	for (vram = 0x44000000; vram < 0x44200000; vram += 4)
		_sw(color, vram);
}

void dumpfile(const char *path, const void *data, SceSize size)
{
	SceUID fd = sceIoOpen(path, PSP_O_CREAT | PSP_O_WRONLY | PSP_O_TRUNC, 0777);
	sceIoWrite(fd, data, size);
	sceIoClose(fd);
}

u32 FindImportByModule(const char *module, const char *lib, u32 nid)
{
	SceModule2 *mod = _sceKernelFindModuleByName(module);

	if (mod) {
		u32 i, j, k;

		for (i = mod->text_addr; i < (mod->text_addr + mod->text_size); i += 4) {
			j = _lw(i);

			if (((j & 3) == 0) && (j > mod->text_addr) && (j < (mod->text_addr + mod->text_size))) {
				if (!strcmp((char *)j, lib)) {
					SceLibStubTable *stub = (SceLibStubTable *)i;

					if (stub->stubtable) {
						for (k = 0; k < stub->stubcount; k++) {
							if (stub->nidtable[k] == nid)
								return (u32)&stub->stubtable[k * 2];
						}
					}
				}
			}
		}
	}

	return 0;
}
