# Cross-compilation dependency builder
# Usage: make HOST=x86_64-linux-gnu

.PHONY: all clean

HOST ?= $(shell gcc -dumpmachine)
PREFIX = $(CURDIR)/$(HOST)

# Detect host platform
host_os = $(word 3,$(subst -, ,$(HOST)))
host_arch = $(word 1,$(subst -, ,$(HOST)))

all: $(PREFIX)/share/toolchain.cmake
	@echo "Toolchain ready: $(PREFIX)/share/toolchain.cmake"
	@echo "Configure with: cmake -DCMAKE_TOOLCHAIN_FILE=$(PREFIX)/share/toolchain.cmake .."

clean:
	rm -rf $(PREFIX)

# Linux toolchain
ifneq ($(findstring linux,$(HOST)),)
$(PREFIX)/share/toolchain.cmake:
	@mkdir -p $(PREFIX)/share
	@echo "Generating Linux toolchain for $(HOST)..."
	@echo '# Auto-generated toolchain for $(HOST)' > $@
	@echo 'set(CMAKE_SYSTEM_NAME Linux)' >> $@
	@echo 'set(CMAKE_SYSTEM_PROCESSOR $(host_arch))' >> $@
	@echo '' >> $@
	@echo '# Compilers' >> $@
	@echo 'set(CMAKE_C_COMPILER $(HOST)-gcc)' >> $@
	@echo 'set(CMAKE_CXX_COMPILER $(HOST)-g++)' >> $@
	@echo 'set(CMAKE_AR $(HOST)-ar)' >> $@
	@echo 'set(CMAKE_RANLIB $(HOST)-ranlib)' >> $@
	@echo 'set(CMAKE_STRIP $(HOST)-strip)' >> $@
	@echo '' >> $@
	@echo '# Search paths' >> $@
	@echo 'set(CMAKE_FIND_ROOT_PATH $(PREFIX))' >> $@
	@echo 'set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)' >> $@
	@echo 'set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)' >> $@
	@echo 'set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)' >> $@
	@echo 'set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)' >> $@
	@echo '' >> $@
	@echo '# Flags' >> $@
	@echo 'set(CMAKE_C_FLAGS_INIT "-fPIC")' >> $@
	@echo 'set(CMAKE_CXX_FLAGS_INIT "-fPIC")' >> $@
endif

# macOS / Darwin toolchain
ifneq ($(findstring darwin,$(HOST)),)
$(PREFIX)/share/toolchain.cmake:
	@mkdir -p $(PREFIX)/share
	@echo "Generating Darwin toolchain for $(HOST)..."
	@echo '# Auto-generated toolchain for $(HOST)' > $@
	@echo 'set(CMAKE_SYSTEM_NAME Darwin)' >> $@
	@echo 'set(CMAKE_SYSTEM_PROCESSOR $(host_arch))' >> $@
	@echo '' >> $@
	@echo '# Compilers' >> $@
	@echo 'set(CMAKE_C_COMPILER $(HOST)-clang)' >> $@
	@echo 'set(CMAKE_CXX_COMPILER $(HOST)-clang++)' >> $@
	@echo '' >> $@
	@echo '# Deployment target' >> $@
	@echo 'set(CMAKE_OSX_DEPLOYMENT_TARGET 11.0)' >> $@
	@echo '' >> $@
	@echo '# Search paths' >> $@
	@echo 'set(CMAKE_FIND_ROOT_PATH $(PREFIX))' >> $@
	@echo 'set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)' >> $@
	@echo 'set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)' >> $@
	@echo 'set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)' >> $@
	@echo 'set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)' >> $@
endif

# Windows / MinGW toolchain
ifneq ($(findstring mingw,$(HOST)),)
$(PREFIX)/share/toolchain.cmake:
	@mkdir -p $(PREFIX)/share
	@echo "Generating MinGW toolchain for $(HOST)..."
	@echo '# Auto-generated toolchain for $(HOST)' > $@
	@echo 'set(CMAKE_SYSTEM_NAME Windows)' >> $@
	@echo 'set(CMAKE_SYSTEM_PROCESSOR $(host_arch))' >> $@
	@echo '' >> $@
	@echo '# Compilers' >> $@
	@echo 'set(CMAKE_C_COMPILER $(HOST)-gcc)' >> $@
	@echo 'set(CMAKE_CXX_COMPILER $(HOST)-g++)' >> $@
	@echo 'set(CMAKE_RC_COMPILER $(HOST)-windres)' >> $@
	@echo '' >> $@
	@echo '# Search paths' >> $@
	@echo 'set(CMAKE_FIND_ROOT_PATH $(PREFIX))' >> $@
	@echo 'set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)' >> $@
	@echo 'set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)' >> $@
	@echo 'set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)' >> $@
	@echo 'set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)' >> $@
	@echo '' >> $@
	@echo '# Windows-specific' >> $@
	@echo 'set(CMAKE_C_FLAGS_INIT "-static-libgcc")' >> $@
	@echo 'set(CMAKE_CXX_FLAGS_INIT "-static-libgcc -static-libstdc++")' >> $@
	@echo 'set(CMAKE_EXE_LINKER_FLAGS_INIT "-static -lws2_32 -lmswsock")' >> $@
endif
