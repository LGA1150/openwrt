include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-chinadns-ng
PKG_VERSION:=1.0
PKG_RELEASE:=5

LUCI_DEPENDS:=+luci-compat +chinadns-ng

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
	SECTION:=luci
	CATEGORY:=LuCI
	SUBMENU:=3. Applications
	TITLE:=LuCI support for chinadns-ng
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
