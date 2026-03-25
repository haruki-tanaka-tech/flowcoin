# macOS / Darwin host configuration

darwin_CC = clang
darwin_CXX = clang++
darwin_AR = ar
darwin_RANLIB = ranlib
darwin_STRIP = strip
darwin_NM = nm
darwin_OBJCXX = clang++ -x objective-c++

darwin_CFLAGS = -pipe
darwin_CXXFLAGS = $(darwin_CFLAGS) -std=c++20 -stdlib=libc++
darwin_LDFLAGS = -stdlib=libc++

# Deployment target
darwin_OSX_MIN_VERSION = 11.0
darwin_CFLAGS += -mmacosx-version-min=$(darwin_OSX_MIN_VERSION)
darwin_LDFLAGS += -mmacosx-version-min=$(darwin_OSX_MIN_VERSION)

# Architecture-specific
ifeq ($(host_arch),x86_64)
darwin_CFLAGS += -arch x86_64
darwin_LDFLAGS += -arch x86_64
endif

ifeq ($(host_arch),arm64)
darwin_CFLAGS += -arch arm64
darwin_LDFLAGS += -arch arm64
endif

# Universal binary (both architectures)
ifdef UNIVERSAL
darwin_CFLAGS += -arch x86_64 -arch arm64
darwin_LDFLAGS += -arch x86_64 -arch arm64
endif

# Security hardening
darwin_CFLAGS += -fstack-protector-strong
darwin_LDFLAGS += -Wl,-headerpad_max_install_names
darwin_LDFLAGS += -Wl,-dead_strip

# Required frameworks
darwin_FRAMEWORKS = -framework Foundation -framework SystemConfiguration
darwin_FRAMEWORKS += -framework IOKit -framework CoreFoundation

# Code signing (ad-hoc for development, proper cert for release)
darwin_CODESIGN = codesign --sign - --force --timestamp=none
ifdef RELEASE_SIGN_IDENTITY
darwin_CODESIGN = codesign --sign "$(RELEASE_SIGN_IDENTITY)" --force --timestamp
endif
