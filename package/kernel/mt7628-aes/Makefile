#
# Copyright (C) 2006-2017 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=mtk_aes
PKG_RELEASE:=1.2

include $(INCLUDE_DIR)/package.mk

define Package/crypto-hw-mtk-aes/Default
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Cryptographic API modules
endef

define KernelPackage/crypto-hw-mtk-aes
  $(call Package/crypto-hw-mtk-aes/Default)
  SECTION:=kernel
  DEPENDS:=@TARGET_ramips_mt76x8
  TITLE:=Kernel driver for Mediatek MT76x8 aes engine.
  FILES:=$(PKG_BUILD_DIR)/crypto-hw-mtk-aes.ko
  AUTOLOAD:=$(call AutoProbe,crypto-hw-mtk-aes)
  $(call AddDepends/crypto)
endef

define KernelPackage/crypto-hw-mtk-aes/config
	select CRYPTO_HW
endef

define KernelPackage/crypto-hw-mt7628-aes/description
 Kernel module to enable AES HW Crypto Engine on the Mediatek MT76x8
 (AES-128/192/256 EBC/CBC).
endef
  
define Build/Compile
	+$(MAKE) $(PKG_JOBS) -C "$(LINUX_DIR)" \
        CROSS_COMPILE="$(TARGET_CROSS)" \
        ARCH="$(LINUX_KARCH)" \
        SUBDIRS="$(PKG_BUILD_DIR)" \
        EXTRA_CFLAGS="$(BUILDFLAGS)" \
        modules
endef

$(eval $(call KernelPackage,crypto-hw-mtk-aes))
