#
# Copyright (C) 2018 LGA1150
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=spooftcp
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_DATE:=2020-06-02
PKG_SOURCE_URL:=https://github.com/LGA1150/netfilter-spooftcp.git
PKG_SOURCE_VERSION:=a9a32e992a1bc447467fcdf3537a4fb2a6ab217f

PKG_LICENSE:=GPL-2.0
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk

define Package/iptables-mod-spooftcp
  SUBMENU:=Firewall
  SECTION:=net
  CATEGORY:=Network
  TITLE:=SPOOFTCP xtables extension
  DEPENDS:=+iptables +IPV6:ip6tables +kmod-ipt-spooftcp
endef

define Package/iptables-mod-spooftcp/install
	$(INSTALL_DIR) $(1)/usr/lib/iptables
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libxt_SPOOFTCP.so $(1)/usr/lib/iptables
endef

define KernelPackage/ipt-spooftcp
  SUBMENU:=Netfilter Extensions
  TITLE:=SPOOFTCP netfilter module
  DEPENDS:=+kmod-ipt-core +kmod-nf-conntrack
  FILES:=$(PKG_BUILD_DIR)/xt_SPOOFTCP.ko
# AUTOLOAD:=$(call AutoProbe,xt_SPOOFTCP)
endef

include $(INCLUDE_DIR)/kernel-defaults.mk

define Build/Prepare
	$(call Build/Prepare/Default)
	$(CP) ./files/Makefile $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)" \
	EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
	$(PKG_EXTRA_KCONFIG) \
	modules
	$(call Build/Compile/Default)
endef

$(eval $(call BuildPackage,iptables-mod-spooftcp))
$(eval $(call KernelPackage,ipt-spooftcp))
