include $(TOPDIR)/rules.mk

PKG_NAME:=zddns
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_LICENSE:=GPLv3
PKG_LICENSE_FILES:=COPYING
PKG_MAINTAINER:=Lixin Zheng<lixin.zhenglx@gmail.com>

PKG_USE_MIPS16:=0
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/zddns
	SECTION:=net
	CATEGORY:=Network
	TITLE:=Dynamic DNS
	DEPENDS:=+libcurl +libopenssl +cJSON
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS+="$(TARGET_CPPFLAGS) $(TARGET_CFLAGS)" \
		LDFLAGS+="$(TARGET_LDFLAGS) -L$(STAGING_DIR)/usr/lib"
endef


define Package/zddns/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/zddns $(1)/usr/bin/
endef

$(eval $(call BuildPackage,zddns))
