# Linux host configuration

linux_CC = gcc
linux_CXX = g++
linux_AR = ar
linux_RANLIB = ranlib
linux_STRIP = strip
linux_NM = nm

linux_CFLAGS = -pipe -fPIC
linux_CXXFLAGS = $(linux_CFLAGS) -std=c++20
linux_LDFLAGS = -Wl,-z,relro -Wl,-z,now

# Security hardening
linux_CFLAGS += -fstack-protector-strong -D_FORTIFY_SOURCE=2
linux_LDFLAGS += -Wl,-z,noexecstack

# Architecture-specific optimizations
ifeq ($(host_arch),x86_64)
linux_CFLAGS += -march=x86-64 -mtune=generic
endif

ifeq ($(host_arch),aarch64)
linux_CFLAGS += -march=armv8-a
endif

ifeq ($(host_arch),armv7l)
linux_CFLAGS += -march=armv7-a -mfpu=neon-vfpv4 -mfloat-abi=hard
endif

# Required system libraries
linux_SYSTEM_LIBS = -lpthread -ldl -lm

# Static linking preference for release builds
ifdef STATIC
linux_LDFLAGS += -static
linux_SYSTEM_LIBS += -lrt
endif
