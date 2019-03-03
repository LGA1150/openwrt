include $(TOPDIR)/rules.mk

PKG_NAME:=phytool
PKG_VERSION:=2
PKG_RELEASE:=1

PKG_RELEASE=$(PKG_SOURCE_VERSION)

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.xz
PKG_SOURCE_URL:=https://github.com/wkz/phytool/releases/download/v$(PKG_VERSION)
PKG_HASH:=9901a14e8c6af02b7333c60b21ff81f50620e8326d54827185e5617ff9b11d21

PKG_LICENSE:=GPL-2.0+
PKG_LICENSE_FILES:=LICENSE

PKG_MAINTAINER:=Christian Lamparter <chunkeey@gmail.com>

include $(INCLUDE_DIR)/package.mk

define Package/phytool
  SECTION:=net
  CATEGORY:=Utilities
  TITLE:=phytool Linux MDIO register access
  URL:=https://github.com/wkz/phytool.git
endef

define Package/phytool/description
   Linux MDIO register access
endef

define Build/Configure
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS) -Wall" \
		LDFLAGS="$(TARGET_LDFLAGS)"
endef

define Package/phytool/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/phytool $(1)/usr/bin/
endef

$(eval $(call BuildPackage,phytool))
