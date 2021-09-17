CC ?= clang
CXX ?= clang++
DEBUG=-g
CFLAGS=-c -g
SANITIZE_FLAGS=-fsanitize=integer,bounds,address,undefined,null -rtlib=compiler-rt -lgcc_s
LFLAGS=-lpthread -lm
LD ?= clang
INCLUDE_MAIN=-DINCLUDEMAIN
OMITBAD=-DOMITBAD
OMITGOOD=-DOMITGOOD

INCLUDES=-I ../../testcasesupport

C_SUPPORT_PATH=../../testcasesupport/
C_SUPPORT_FILES=$(C_SUPPORT_PATH)io.c $(C_SUPPORT_PATH)std_thread.c
C_SUPPORT_OBJECTS_32=io_32.o std_thread_32.o
C_SUPPORT_OBJECTS_64=io_64.o std_thread_64.o
C_SUPPORT_OBJECTS_32_SAN=io_32_san.o std_thread_32_san.o
C_SUPPORT_OBJECTS_64_SAN=io_64_san.o std_thread_64_san.o
FILTER_OUT=$(wildcard s*/CWE*w32*.c*) $(wildcard s*/CWE*wchar_t*.c*) $(wildcard CWE*w32*.c*) $(wildcard CWE*wchar_t*.c*)

# only grab the .c files without "w32" or "wchar_t" in the name
C_SOURCES=$(filter-out $(FILTER_OUT),$(wildcard CWE*.c) $(wildcard s*/CWE*.c))

# only grab the .cpp files without "w32" or "wchar_t" in the name
CPP_SOURCES=$(filter-out $(FILTER_OUT),$(wildcard CWE*.cpp) $(wildcard s*/CWE*.cpp))

SIMPLES=$(filter-out $(FILTER_OUT), $(wildcard CWE*0.c*) $(wildcard CWE*1.c*) $(wildcard CWE*2.c*) $(wildcard CWE*3.c*) $(wildcard CWE*4.c*)) \
        $(filter-out $(FILTER_OUT), $(wildcard CWE*5.c*) $(wildcard CWE*6.c*) $(wildcard CWE*7.c*) $(wildcard CWE*8.c*) $(wildcard CWE*9.c*)) \
        $(filter-out $(FILTER_OUT), $(wildcard s*/CWE*0.c*) $(wildcard s*/CWE*1.c*) $(wildcard s*/CWE*2.c*) $(wildcard s*/CWE*3.c*) $(wildcard s*/CWE*4.c*)) \
        $(filter-out $(FILTER_OUT), $(wildcard s*/CWE*5.c*) $(wildcard s*/CWE*6.c*) $(wildcard s*/CWE*7.c*) $(wildcard s*/CWE*8.c*) $(wildcard s*/CWE*9.c*))
SIMPLES_C=$(filter-out $(CPP_SOURCES), $(SIMPLES))
SIMPLES_CPP=$(filter-out $(C_SOURCES), $(SIMPLES))

LETTEREDS=$(filter-out $(FILTER_OUT), $(wildcard CWE*a.c*) $(wildcard CWE*a.c*) $(wildcard s*/CWE*a.c*) $(wildcard s*/CWE*a.c*))
LETTEREDS_C=$(subst a.,.,$(filter-out $(CPP_SOURCES), $(LETTEREDS)))
LETTEREDS_CPP=$(subst a.,.,$(filter-out $(C_SOURCES), $(LETTEREDS)))

GOOD1S=$(filter-out $(FILTER_OUT), $(wildcard CWE*_good1.cpp) $(wildcard s*/CWE*_good1.cpp))
BADS=$(subst _good1.,_bad.,$(GOOD1S))

BIN_C=$(sort $(subst .c,,$(SIMPLES_C) $(LETTEREDS_C)))
BIN_CPP=$(sort $(subst .cpp,,$(SIMPLES_CPP) $(LETTEREDS_CPP) $(BADS) $(GOOD1S)))

INDIVIDUAL_C=$(BIN_C)
INDIVIDUALS_CPP=$(BIN_CPP)

ifndef BUILD_ALL
INDIVIDUALS_C=$(foreach v,$(BIN_C),$(if $(or $(findstring fscanf,$(v)),$(findstring fgets,$(v))),$(v),))
INDIVIDUALS_CPP=$(foreach v,$(BIN_CPP),$(if $(or $(findstring fscanf,$(v)),$(findstring fgets,$(v))),$(v),))
else
ifeq ($(BUILD_ALL),0)
INDIVIDUALS_C=$(foreach v,$(BIN_C),$(if $(or $(findstring fscanf,$(v)),$(findstring fgets,$(v))),$(v),))
INDIVIDUALS_CPP=$(foreach v,$(BIN_CPP),$(if $(or $(findstring fscanf,$(v)),$(findstring fgets,$(v))),$(v),))
endif
endif

all: $(INDIVIDUALS_C) $(INDIVIDUALS_CPP)

$(INDIVIDUALS_C): $(C_SUPPORT_OBJECTS_32) $(C_SUPPORT_OBJECTS_64) $(C_SUPPORT_OBJECTS_32_SAN) $(C_SUPPORT_OBJECTS_64_SAN)
	$(shell mkdir -p ../../bin/bin32/$(notdir $(shell pwd))/$(dir $@))
	$(shell mkdir -p ../../bin/bin64/$(notdir $(shell pwd))/$(dir $@))
	$(CC) $(INCLUDES) $(INCLUDE_MAIN) $(OMITBAD) -g -m32 -o ../../bin/bin32/$(notdir $(shell pwd))/$@_good $(wildcard $@*.c) $(C_SUPPORT_OBJECTS_32) $(LFLAGS)
	$(CC) $(INCLUDES) $(INCLUDE_MAIN) $(OMITGOOD) -g -m32 -o ../../bin/bin32/$(notdir $(shell pwd))/$@_bad $(wildcard $@*.c) $(C_SUPPORT_OBJECTS_32) $(LFLAGS)
	$(CC) $(INCLUDES) $(INCLUDE_MAIN) $(OMITGOOD) $(SANITIZE_FLAGS) -m32 -o ../../bin/bin32/$(notdir $(shell pwd))/$(addsuffix _bad_san, $@) $(wildcard $@*.c) $(C_SUPPORT_OBJECTS_32_SAN) $(LFLAGS)
	$(CC) $(INCLUDES) $(INCLUDE_MAIN) $(OMITBAD) -g -m64 -o ../../bin/bin64/$(notdir $(shell pwd))/$@_good $(wildcard $@*.c) $(C_SUPPORT_OBJECTS_64) $(LFLAGS)
	$(CC) $(INCLUDES) $(INCLUDE_MAIN) $(OMITGOOD) -g -m64 -o ../../bin/bin64/$(notdir $(shell pwd))/$@_bad $(wildcard $@*.c) $(C_SUPPORT_OBJECTS_64) $(LFLAGS)
	$(CC) $(INCLUDES) $(INCLUDE_MAIN) $(OMITGOOD) $(SANITIZE_FLAGS) -m64 -o ../../bin/bin64/$(notdir $(shell pwd))/$(addsuffix _bad_san, $@) $(wildcard $@*.c) $(C_SUPPORT_OBJECTS_64_SAN) $(LFLAGS)

$(INDIVIDUALS_CPP): $(C_SUPPORT_OBJECTS_32) $(C_SUPPORT_OBJECTS_64) $(C_SUPPORT_OBJECTS_32_SAN) $(C_SUPPORT_OBJECTS_64_SAN)
	$(shell mkdir -p ../../bin/bin32/$(notdir $(shell pwd))/$(dir $@))
	$(shell mkdir -p ../../bin/bin64/$(notdir $(shell pwd))/$(dir $@))
	$(CXX) $(INCLUDES) $(INCLUDE_MAIN) $(OMITBAD) -g -m32 -o ../../bin/bin32/$(notdir $(shell pwd))/$@_good $(wildcard $(subst .out,,$@)*.cpp) $(C_SUPPORT_OBJECTS_32) $(LFLAGS)
	$(CXX) $(INCLUDES) $(INCLUDE_MAIN) $(OMITGOOD) -g -m32 -o ../../bin/bin32/$(notdir $(shell pwd))/$@_bad $(wildcard $(subst .out,,$@)*.cpp) $(C_SUPPORT_OBJECTS_32) $(LFLAGS)
	$(CXX) $(INCLUDES) $(INCLUDE_MAIN) $(OMITGOOD) $(SANITIZE_FLAGS) -m32 -o ../../bin/bin32/$(notdir $(shell pwd))/$(addsuffix _bad_san, $@) $(wildcard $@*.cpp) $(C_SUPPORT_OBJECTS_32_SAN) $(LFLAGS)
	$(CXX) $(INCLUDES) $(INCLUDE_MAIN) $(OMITBAD) -g -m64 -o ../../bin/bin64/$(notdir $(shell pwd))/$@_good $(wildcard $(subst .out,,$@)*.cpp) $(C_SUPPORT_OBJECTS_64) $(LFLAGS)
	$(CXX) $(INCLUDES) $(INCLUDE_MAIN) $(OMITGOOD) -g -m64 -o ../../bin/bin64/$(notdir $(shell pwd))/$@_bad $(wildcard $(subst .out,,$@)*.cpp) $(C_SUPPORT_OBJECTS_64) $(LFLAGS)
	$(CXX) $(INCLUDES) $(INCLUDE_MAIN) $(OMITGOOD) $(SANITIZE_FLAGS) -m64 -o ../../bin/bin64/$(notdir $(shell pwd))/$(addsuffix _bad_san, $@) $(wildcard $@*.cpp) $(C_SUPPORT_OBJECTS_64_SAN) $(LFLAGS)

$(C_SUPPORT_OBJECTS_32) : $(C_SUPPORT_FILES)
	$(CC) $(CFLAGS) -m32 $(INCLUDES) $(C_SUPPORT_PATH)$(subst _32,,$(@:.o=.c)) -o $@

$(C_SUPPORT_OBJECTS_32_SAN) : $(C_SUPPORT_FILES)
	$(CC) $(CFLAGS) $(SANITIZE_FLAGS) -m32 $(INCLUDES) $(C_SUPPORT_PATH)$(subst _32_san,,$(@:.o=.c)) -o $@

$(C_SUPPORT_OBJECTS_64) : $(C_SUPPORT_FILES)
	$(CC) $(CFLAGS) -m64 $(INCLUDES) $(C_SUPPORT_PATH)$(subst _64,,$(@:.o=.c)) -o $@

$(C_SUPPORT_OBJECTS_64_SAN) : $(C_SUPPORT_FILES)
	$(CC) $(CFLAGS) $(SANITIZE_FLAGS) -m64 $(INCLUDES) $(C_SUPPORT_PATH)$(subst _64_san,,$(@:.o=.c)) -o $@

clean:
	rm -rf *.o ../../bin
