#
# Copyright (C) 2019 LGA1150
#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=cmfw
PKG_RELEASE:=1
PKG_VERSION:=1.0

PKG_LICENSE:=GPL-2.0

include $(INCLUDE_DIR)/package.mk

define Package/iptables-mod-cmfw
  SUBMENU:=Firewall
  SECTION:=net
  CATEGORY:=Network
  TITLE:=CMFW xtables extension
  DEPENDS:=+iptables +kmod-ipt-cmfw
endef

define Package/iptables-mod-cmfw/install
	$(INSTALL_DIR) $(1)/usr/lib/iptables
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libipt_CMFW.so $(1)/usr/lib/iptables
endef

define KernelPackage/ipt-cmfw
  SUBMENU:=Netfilter Extensions
  TITLE:=CMFW netfilter module
  DEPENDS:=+kmod-ipt-core +kmod-nf-conntrack
  FILES:=$(PKG_BUILD_DIR)/xt_CMFW.ko
# AUTOLOAD:=$(call AutoProbe,xt_CMFW)
endef

include $(INCLUDE_DIR)/kernel-defaults.mk

define Build/Compile
	+$(MAKE) $(PKG_JOBS) -C "$(LINUX_DIR)" \
        CROSS_COMPILE="$(TARGET_CROSS)" \
        ARCH="$(LINUX_KARCH)" \
        SUBDIRS="$(PKG_BUILD_DIR)" \
        EXTRA_CFLAGS="$(BUILDFLAGS)" \
        modules
	$(call Build/Compile/Default)
endef

$(eval $(call BuildPackage,iptables-mod-cmfw))
$(eval $(call KernelPackage,ipt-cmfw))
