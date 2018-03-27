ifeq ($(CONFIG_620), 1)
FW_FLAG = CONFIG_620=1
endif

ifeq ($(CONFIG_660), 1)
FW_FLAG = CONFIG_660=1
endif

ifeq ($(CONFIG_661), 1)
FW_FLAG = CONFIG_661=1
endif

all:
	@cd np9660_patch; make $(FW_FLAG); \
		bin2c npdrm_free.prx np9660_patch.h np9660_patch; \
		mv np9660_patch.h ../loader/src/np9660_patch.h;
	@cd loader; make $(FW_FLAG); mv npdrm_free.prx ../npdrm_free.prx;

clean:
	@cd np9660_patch; make clean;
	@cd loader; make clean;
	rm -rf npdrm_free.prx
