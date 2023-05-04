#
# Copyright (C) 2022 LGA1150
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=nf-deaf
PKG_RELEASE:=1

PKG_LICENSE:=GPL-2.0
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel-defaults.mk

define KernelPackage/nf-deaf
  SUBMENU:=Netfilter Extensions
  TITLE:=Netfilter DEAF module
  FILES:=$(PKG_BUILD_DIR)/nf_deaf.ko
  AUTOLOAD:=$(call AutoProbe,nf_deaf)
endef

define KernelPackage/nf-deaf/description
  Netfilter: Desynchronizing Evasion Against Filters
endef

define Build/Compile
	$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)" \
	EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
	$(PKG_EXTRA_KCONFIG) \
	modules
endef

$(eval $(call KernelPackage,nf-deaf))
