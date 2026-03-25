# Windows / MinGW cross-compilation host configuration

mingw32_CC = $(HOST)-gcc
mingw32_CXX = $(HOST)-g++
mingw32_AR = $(HOST)-ar
mingw32_RANLIB = $(HOST)-ranlib
mingw32_STRIP = $(HOST)-strip
mingw32_NM = $(HOST)-nm
mingw32_WINDRES = $(HOST)-windres

mingw32_CFLAGS = -pipe -std=c11
mingw32_CXXFLAGS = -pipe -std=c++20
mingw32_LDFLAGS =

# Static linking (default for Windows builds)
mingw32_CFLAGS += -static-libgcc
mingw32_CXXFLAGS += -static-libgcc -static-libstdc++
mingw32_LDFLAGS += -static

# Windows version targeting (Windows 7+)
mingw32_CFLAGS += -D_WIN32_WINNT=0x0601 -DWINVER=0x0601
mingw32_CXXFLAGS += -D_WIN32_WINNT=0x0601 -DWINVER=0x0601
mingw32_CFLAGS += -DWIN32_LEAN_AND_MEAN -DNOMINMAX

# Security hardening
mingw32_CFLAGS += -fstack-protector-strong
mingw32_LDFLAGS += -Wl,--dynamicbase -Wl,--nxcompat
mingw32_LDFLAGS += -Wl,--high-entropy-va

# Architecture-specific
ifeq ($(host_arch),x86_64)
mingw32_CFLAGS += -march=x86-64 -mtune=generic
mingw32_LDFLAGS += -Wl,--large-address-aware
endif

# Required Windows libraries
mingw32_SYSTEM_LIBS = -lws2_32 -lmswsock -liphlpapi
mingw32_SYSTEM_LIBS += -lshlwapi -ladvapi32 -lole32
mingw32_SYSTEM_LIBS += -lbcrypt -lcrypt32 -luser32

# Resource compilation
mingw32_RESFLAGS = -D_WIN32_WINNT=0x0601
