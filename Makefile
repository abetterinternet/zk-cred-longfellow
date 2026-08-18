# zk-cred-longfellow Makefile — UniFFI binding generation & cross-compilation
#
# Mirrors siros-wscd-manager's Makefile (same org, same UniFFI/cross-compile
# shape) - see that repo's Makefile for the original template this is
# adapted from.
#
# Targets:
#   make bindings       — generate Swift + Kotlin bindings from the host library
#   make ios            — cross-compile for iOS (aarch64-apple-ios + simulator)
#   make xcframework    — build XCFramework from iOS static libraries
#   make android        — cross-compile for Android (arm64, armv7, x86_64)
#   make aar            — package Android AAR (requires android/ layout)
#   make publish-local  — build AAR + POM and install to ~/.m2 (mavenLocal)
#   make go-cabi        — build the plain C-ABI cdylib/staticlib for Go's
#                          cgo verifier (default features, NOT
#                          --features uniffi), staged alongside the
#                          hand-written C header
#   make clean          — remove build artifacts

CRATE_NAME := zk_cred_longfellow
LIB_NAME   := lib$(CRATE_NAME)
UNAME_S    := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  HOST_LIB_EXT := dylib
else
  HOST_LIB_EXT := so
endif
VERSION    := $(shell cargo metadata --no-deps --format-version 1 | python3 -c "import sys,json; print(json.load(sys.stdin)['packages'][0]['version'])")

# Directories
BUILD_DIR      := target
BINDINGS_DIR   := bindings
SWIFT_DIR      := $(BINDINGS_DIR)/swift
KOTLIN_DIR     := $(BINDINGS_DIR)/kotlin
XCFRAMEWORK    := $(BUILD_DIR)/$(CRATE_NAME).xcframework
GO_CABI_DIR    := $(BUILD_DIR)/go-cabi

# iOS targets
IOS_TARGETS      := aarch64-apple-ios
IOS_SIM_TARGETS  := aarch64-apple-ios-sim x86_64-apple-ios

# Minimum iOS deployment target - matches siros-wscd-manager's own pin.
export IPHONEOS_DEPLOYMENT_TARGET ?= 16.0

# Android targets (via cargo-ndk)
ANDROID_TARGETS := aarch64-linux-android armv7-linux-androideabi x86_64-linux-android

.PHONY: all bindings bindings-swift bindings-kotlin ios android xcframework aar pom publish-local clean check-bindings go-cabi

all: bindings

# ── Binding generation ───────────────────────────────────────────────

bindings: bindings-swift bindings-kotlin

bindings-swift: $(BUILD_DIR)/release/$(LIB_NAME).$(HOST_LIB_EXT)
	@mkdir -p $(SWIFT_DIR)
	cargo run --release --features uniffi --bin uniffi-bindgen -- generate \
		--library $(BUILD_DIR)/release/$(LIB_NAME).$(HOST_LIB_EXT) \
		--language swift \
		--out-dir $(SWIFT_DIR)
	@echo "Swift bindings generated in $(SWIFT_DIR)"

bindings-kotlin: $(BUILD_DIR)/release/$(LIB_NAME).$(HOST_LIB_EXT)
	@mkdir -p $(KOTLIN_DIR)
	cargo run --release --features uniffi --bin uniffi-bindgen -- generate \
		--library $(BUILD_DIR)/release/$(LIB_NAME).$(HOST_LIB_EXT) \
		--language kotlin \
		--out-dir $(KOTLIN_DIR)
	@echo "Kotlin bindings generated in $(KOTLIN_DIR)"

$(BUILD_DIR)/release/$(LIB_NAME).$(HOST_LIB_EXT):
	cargo build --release --features uniffi

# ── Go (cgo) plain C-ABI build ───────────────────────────────────────
#
# `src/go_ffi.rs` exports a hand-written, ordinary `extern "C"` ABI for a
# Go verifier service to call via cgo — separate from the UniFFI/RustBuffer
# ABI in `ffi_api.rs` used by the Swift/Kotlin bindings above. UniFFI
# doesn't target Go, and its RustBuffer wire protocol isn't cgo-friendly,
# hence the separate hand-written ABI + header here.
#
# This target intentionally builds with the crate's *default* features
# (no `--features uniffi`): the go_ffi module is always compiled in, and
# building without uniffi keeps this artifact free of UniFFI's scaffolding
# and its extra dependency graph, which Go/cgo callers have no use for.
go-cabi: $(GO_CABI_DIR)/$(LIB_NAME).$(HOST_LIB_EXT) $(GO_CABI_DIR)/$(LIB_NAME).a $(GO_CABI_DIR)/zk_cred_longfellow_go.h
	@echo "Go C-ABI library + header staged in $(GO_CABI_DIR)"

$(GO_CABI_DIR)/$(LIB_NAME).$(HOST_LIB_EXT): $(GO_CABI_DIR)/zk_cred_longfellow_go.h
	cargo build --release
	@mkdir -p $(GO_CABI_DIR)
	cp $(BUILD_DIR)/release/$(LIB_NAME).$(HOST_LIB_EXT) $(GO_CABI_DIR)/

$(GO_CABI_DIR)/$(LIB_NAME).a: $(GO_CABI_DIR)/zk_cred_longfellow_go.h
	cargo build --release
	@mkdir -p $(GO_CABI_DIR)
	cp $(BUILD_DIR)/release/$(LIB_NAME).a $(GO_CABI_DIR)/

$(GO_CABI_DIR)/zk_cred_longfellow_go.h: include/zk_cred_longfellow_go.h
	@mkdir -p $(GO_CABI_DIR)
	cp include/zk_cred_longfellow_go.h $(GO_CABI_DIR)/

# ── iOS cross-compilation (must run on macOS with Xcode toolchains) ─

ios: $(foreach t,$(IOS_TARGETS) $(IOS_SIM_TARGETS),ios-$(t))

ios-%:
	cargo build --release --target $* --features uniffi

# ── XCFramework ─────────────────────────────────────────────────────

xcframework: ios bindings-swift
	@rm -rf $(XCFRAMEWORK)
	# Create fat simulator library
	@mkdir -p $(BUILD_DIR)/ios-sim-universal
	lipo -create \
		$(foreach t,$(IOS_SIM_TARGETS),$(BUILD_DIR)/$(t)/release/$(LIB_NAME).a) \
		-output $(BUILD_DIR)/ios-sim-universal/$(LIB_NAME).a
	# Plain "module", not "framework module": this XCFramework is built
	# from static libraries (-library/-headers), not real .framework
	# bundles - "framework module" fails to resolve at import time.
	#
	# Headers are nested under $(CRATE_NAME)FFI/, not placed directly at
	# Headers/ root: when an app links two or more static-archive
	# XCFrameworks at once (e.g. this one alongside siros-wscd-manager's),
	# Xcode's own ProcessXCFramework build step copies each one's Headers/
	# contents into the SAME shared per-product `include/` directory - a
	# flat `Headers/module.modulemap` from each XCFramework collides at
	# that fixed destination ("Multiple commands produce
	# .../include/module.modulemap"), regardless of the module's own name
	# inside the map. Nesting under a per-module subdirectory here
	# preserves that subdirectory through the copy, so the destination
	# becomes include/$(CRATE_NAME)FFI/module.modulemap - unique per
	# framework. Confirmed via a real xcodebuild of an app product linking
	# both this XCFramework and siros-wscd-manager's together.
	@rm -rf $(BUILD_DIR)/Headers
	@mkdir -p $(BUILD_DIR)/Headers/$(CRATE_NAME)FFI
	@cp $(SWIFT_DIR)/$(CRATE_NAME)FFI.h $(BUILD_DIR)/Headers/$(CRATE_NAME)FFI/
	@echo "module $(CRATE_NAME)FFI { header \"$(CRATE_NAME)FFI.h\" export * }" \
		> $(BUILD_DIR)/Headers/$(CRATE_NAME)FFI/module.modulemap
	xcodebuild -create-xcframework \
		-library $(BUILD_DIR)/aarch64-apple-ios/release/$(LIB_NAME).a \
		-headers $(BUILD_DIR)/Headers \
		-library $(BUILD_DIR)/ios-sim-universal/$(LIB_NAME).a \
		-headers $(BUILD_DIR)/Headers \
		-output $(XCFRAMEWORK)
	@echo "XCFramework created at $(XCFRAMEWORK)"

# ── Android cross-compilation (requires cargo-ndk + Android NDK) ────

android: $(foreach t,$(ANDROID_TARGETS),android-$(t))

android-%:
	cargo ndk --target $* --platform 28 -- build --release --features uniffi

# ── AAR packaging ───────────────────────────────────────────────────

AAR_DIR := $(BUILD_DIR)/aar

aar: android
	@mkdir -p $(AAR_DIR)/jni/arm64-v8a $(AAR_DIR)/jni/armeabi-v7a $(AAR_DIR)/jni/x86_64
	cp $(BUILD_DIR)/aarch64-linux-android/release/$(LIB_NAME).so $(AAR_DIR)/jni/arm64-v8a/
	cp $(BUILD_DIR)/armv7-linux-androideabi/release/$(LIB_NAME).so $(AAR_DIR)/jni/armeabi-v7a/
	cp $(BUILD_DIR)/x86_64-linux-android/release/$(LIB_NAME).so $(AAR_DIR)/jni/x86_64/
	@echo '<?xml version="1.0" encoding="utf-8"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.siros.zkcredlongfellow"/>' \
		> $(AAR_DIR)/AndroidManifest.xml
	# The AAR only ships the native .so libraries; the UniFFI Kotlin bindings
	# are consumed as vendored source by the SDK, so an empty classes.jar
	# (required by the AAR layout) is sufficient. JNA is provided
	# transitively via the POM.
	@mkdir -p $(BUILD_DIR)/aar-classes/META-INF
	@printf 'Manifest-Version: 1.0\n' > $(BUILD_DIR)/aar-classes/META-INF/MANIFEST.MF
	cd $(BUILD_DIR)/aar-classes && zip -qr ../aar/classes.jar .
	cd $(AAR_DIR) && zip -r ../$(CRATE_NAME)-$(VERSION).aar .
	@echo "AAR created at $(BUILD_DIR)/$(CRATE_NAME)-$(VERSION).aar"

# ── Maven POM (for publishing the AAR by coordinates) ───────────────
MAVEN_GROUP    := org.siros
MAVEN_ARTIFACT := zk-cred-longfellow

pom:
	@mkdir -p $(BUILD_DIR)
	@printf '%s\n' \
	  '<?xml version="1.0" encoding="UTF-8"?>' \
	  '<project xmlns="http://maven.apache.org/POM/4.0.0"' \
	  '         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"' \
	  '         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">' \
	  '  <modelVersion>4.0.0</modelVersion>' \
	  '  <groupId>$(MAVEN_GROUP)</groupId>' \
	  '  <artifactId>$(MAVEN_ARTIFACT)</artifactId>' \
	  '  <version>$(VERSION)</version>' \
	  '  <packaging>aar</packaging>' \
	  '  <dependencies>' \
	  '    <dependency>' \
	  '      <groupId>net.java.dev.jna</groupId>' \
	  '      <artifactId>jna</artifactId>' \
	  '      <version>5.14.0</version>' \
	  '      <type>aar</type>' \
	  '    </dependency>' \
	  '  </dependencies>' \
	  '</project>' \
	  > $(BUILD_DIR)/$(MAVEN_ARTIFACT)-$(VERSION).pom
	@echo "POM written to $(BUILD_DIR)/$(MAVEN_ARTIFACT)-$(VERSION).pom"

# ── Local Maven install (mavenLocal / ~/.m2) ────────────────────────
# Coordinate: org.siros:zk-cred-longfellow:<version>
MAVEN_LOCAL_DIR := $(HOME)/.m2/repository/$(subst .,/,$(MAVEN_GROUP))/$(MAVEN_ARTIFACT)/$(VERSION)

publish-local: aar pom
	@mkdir -p $(MAVEN_LOCAL_DIR)
	cp $(BUILD_DIR)/$(CRATE_NAME)-$(VERSION).aar \
	   $(MAVEN_LOCAL_DIR)/$(MAVEN_ARTIFACT)-$(VERSION).aar
	cp $(BUILD_DIR)/$(MAVEN_ARTIFACT)-$(VERSION).pom \
	   $(MAVEN_LOCAL_DIR)/$(MAVEN_ARTIFACT)-$(VERSION).pom
	@echo "Installed to $(MAVEN_LOCAL_DIR)"

# ── CI helper: verify bindings are up-to-date ───────────────────────

check-bindings: bindings
	@git diff --exit-code $(BINDINGS_DIR) || \
		(echo "ERROR: Generated bindings are out of date. Run 'make bindings' and commit." && exit 1)

# ── Clean ────────────────────────────────────────────────────────────

clean:
	cargo clean
	rm -rf $(BINDINGS_DIR) $(BUILD_DIR)/aar $(BUILD_DIR)/ios-sim-universal $(BUILD_DIR)/Headers $(GO_CABI_DIR)
