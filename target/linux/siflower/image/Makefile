# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2012-2015 OpenWrt.org
# Copyright (C) 2016-2017 LEDE project

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/image.mk

KERNEL_LOADADDR := 0x80100000

define Device/Default
  PROFILES := Default
  BLOCKSIZE := 64k
  FILESYSTEMS := squashfs
  DEVICE_DTS_DIR := ../dts
  KERNEL := kernel-bin | append-dtb | lzma | uImage lzma
  KERNEL_INITRAMFS := kernel-bin | append-dtb | lzma | uImage lzma
  IMAGES := sysupgrade.bin
  IMAGE/sysupgrade.bin = append-kernel | pad-to $$$$(BLOCKSIZE) | \
	append-rootfs | pad-rootfs | append-metadata
endef

define Device/siflower_sf19a2890-evb
  DEVICE_VENDOR := Siflower
  DEVICE_MODEL := SF19A2890 EVB
  BOARD_NAME := siflower,sf19a2890-evb
  DEVICE_DTS := sf19a2890_evb
  DEVICE_PACKAGES := kmod-switch-rtl8367b swconfig
endef
TARGET_DEVICES += siflower_sf19a2890-evb
# default all platform image(fit) build
define Device/Default
  PROFILES = Default $$(DEVICE_NAME)
  KERNEL = kernel-bin | lzma
  KERNEL_INITRAMFS = append-kernel | fit lzma $$(KDIR)/image-$$(firstword $$(DEVICE_DTS)).dtb with-initrd
  FILESYSTEMS := squashfs
  DEVICE_DTS_DIR := $(DTS_DIR)
  IMAGES := sysupgrade.itb
  IMAGE/sysupgrade.itb = append-kernel | fit lzma $$(KDIR)/image-$$(firstword $$(DEVICE_DTS)).dtb external-static-with-rootfs | \
	pad-rootfs | append-metadata
endef

include $(SUBTARGET).mk

define Image/Build
	$(call Image/Build/$(1),$(1))
endef

$(eval $(call BuildImage))
