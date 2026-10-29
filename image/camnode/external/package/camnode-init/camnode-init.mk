################################################################################
#
# camnode-init
#
################################################################################

CAMNODE_INIT_VERSION = 1
CAMNODE_INIT_SITE = $(BR2_EXTERNAL_CAMNODE_PATH)/package/camnode-init
CAMNODE_INIT_SITE_METHOD = local
CAMNODE_INIT_LICENSE = Apache-2.0
CAMNODE_INIT_DEPENDENCIES = host-cpio
CAMNODE_INIT_INSTALL_TARGET = NO
CAMNODE_INIT_INSTALL_IMAGES = YES

define CAMNODE_INIT_BUILD_CMDS
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_LDFLAGS) -static -Wall -Wextra -Werror \
		-o $(@D)/camnode-init $(@D)/camnode-init.c
	$(TARGET_STRIP) $(@D)/camnode-init
endef

# The initramfs is the init alone and the four directories it mounts on, owned by root, with
# file times clamped to SOURCE_DATE_EPOCH, so the same source gives the same bytes.
define CAMNODE_INIT_INSTALL_IMAGES_CMDS
	rm -rf $(@D)/cpio && mkdir -p $(@D)/cpio/dev $(@D)/cpio/proc $(@D)/cpio/root $(@D)/cpio/sys
	$(INSTALL) -m 0755 $(@D)/camnode-init $(@D)/cpio/init
	find $(@D)/cpio -exec touch -h -d @$(SOURCE_DATE_EPOCH) {} +
	cd $(@D)/cpio && find . -mindepth 1 | LC_ALL=C sort | \
		$(HOST_DIR)/bin/cpio --quiet -o -H newc --reproducible -R 0:0 > $(BINARIES_DIR)/camnode-initramfs.cpio
endef

# Buildroot's systemd package turns IPv6 on in the kernel after the board's fragments are merged;
# this tree's fixups run after it, so the node's kernel keeps no IPv6 (CAM-image-9).
define CAMNODE_INIT_LINUX_CONFIG_FIXUPS
	$(call KCONFIG_DISABLE_OPT,CONFIG_IPV6)
endef

$(eval $(generic-package))
