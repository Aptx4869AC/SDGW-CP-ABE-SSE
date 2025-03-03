# control Enclave


######## SGX SDK Settings ########
SGX_MODE ?= HW
SGX_ARCH ?= x64
ENCLAVE_DIR=Enclave
#ENCLAVE_DIR must be directly followed by the assigned value, representing the path of trusted files.

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	$(error x86 build is not supported, only x64!!)
else
	SGX_COMMON_CFLAGS := -m64 -Wall
	ifeq ($(LINUX_SGX_BUILD), 1)
		include ../../../../../buildenv.mk
		SGX_LIBRARY_PATH := $(BUILD_DIR)
		SGX_ENCLAVE_SIGNER := $(BUILD_DIR)/sgx_sign
		SGX_EDGER8R := $(BUILD_DIR)/sgx_edger8r
		SGX_SDK_INC := $(COMMON_DIR)/inc
		LIBCXX_INC := $(LINUX_SDK_DIR)/tlibcxx/include
	else ifeq ($(LINUX_SGX_BUILD), 2)
                include ../../../../../QuoteGeneration/buildenv.mk
                SGX_EDGER8R := $(SERVTD_ATTEST_STD_LIB_PATH)/sgx_edger8r
                SGX_SDK_INC := $(SERVTD_ATTEST_STD_INC_PATH)
                LIBCXX_INC := $(SERVTD_ATTEST_LINUX_TRUNK_ROOT_PATH)/sdk/tlibcxx/include
	else
		SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
		SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
		SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
		SGX_SDK_INC := $(SGX_SDK)/include
		LIBCXX_INC := $(SGX_SDK)/include/libcxx
	endif

endif

ifeq ($(DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

# Added to build with SgxSSL libraries
TSETJMP_LIB := -lsgx_tsetjmp
OPENSSL_LIBRARY_PATH := $(PACKAGE_LIB)/


ifeq "20" "$(word 1, $(sort 20 $(SGXSDK_INT_VERSION)))"
        TSETJMP_LIB:=
endif

ifeq ($(DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
		SGXSSL_Library_Name := sgx_tsgxssld
		OpenSSL_Crypto_Library_Name := sgx_tsgxssl_cryptod
else
        SGX_COMMON_CFLAGS += -O2 -D_FORTIFY_SOURCE=2
		SGXSSL_Library_Name := sgx_tsgxssl
		OpenSSL_Crypto_Library_Name := sgx_tsgxssl_crypto
endif


ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

ifeq ($(SGX_MODE), HW)
ifndef DEBUG
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif

Enclave_Cpp_Files := $(wildcard $(ENCLAVE_DIR)/*.cpp) $(wildcard $(ENCLAVE_DIR)/tests/*.cpp) $(wildcard $(ENCLAVE_DIR)/TrustedLibrary/*.cpp)
Enclave_C_Files := $(wildcard $(ENCLAVE_DIR)/*.c) $(wildcard $(ENCLAVE_DIR)/tests/*.c) $(wildcard $(ENCLAVE_DIR)/TrustedLibrary/*.c)

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)
Enclave_C_Objects := $(Enclave_C_Files:.c=.o)

Enclave_Include_Paths := -I. -I$(ENCLAVE_DIR) -I$(SGX_SDK_INC) -I$(SGX_SDK_INC)/tlibc -I$(LIBCXX_INC) -I$(PACKAGE_INC) 

Common_C_Cpp_Flags := -DOS_ID=$(OS_ID) $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpic -fpie -fstack-protector -fno-builtin-printf -Wformat -Wformat-security $(Enclave_Include_Paths) -include "tsgxsslio.h"
Enclave_C_Flags := $(Common_C_Cpp_Flags) -Wno-implicit-function-declaration -std=c11
Enclave_Cpp_Flags :=  $(Common_C_Cpp_Flags) -std=c++11 -nostdinc++

SgxSSL_Link_Libraries := -L$(OPENSSL_LIBRARY_PATH) -Wl,--whole-archive -l$(SGXSSL_Library_Name) -Wl,--no-whole-archive \
						 -l$(OpenSSL_Crypto_Library_Name)
Security_Link_Flags := -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -pie

Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
	$(Security_Link_Flags) \
	$(SgxSSL_Link_Libraries) -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group  -lsgx_tstdc -lsgx_pthread -lsgx_tcxx -lsgx_tcrypto $(TSETJMP_LIB) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=$(ENCLAVE_DIR)/Enclave.lds

Enclave_Test_Key := $(ENCLAVE_DIR)/Enclave_private.pem

.PHONY: all test

all: Enclave.signed.so
# usually release mode don't sign the enclave, but here we want to run the test also in release mode
# this is not realy a release mode as the XML file don't disable debug - we can't load real release enclaves (white list)

test: all


######## Enclave Objects ########

$(ENCLAVE_DIR)/Enclave_t.c: $(SGX_EDGER8R) $(ENCLAVE_DIR)/Enclave.edl
	@cd $(ENCLAVE_DIR) && $(SGX_EDGER8R) --trusted Enclave.edl --search-path $(PACKAGE_INC) --search-path $(SGX_SDK_INC)
	@echo "GEN  =>  $@"

$(ENCLAVE_DIR)/Enclave_t.o: $(ENCLAVE_DIR)/Enclave_t.c
	$(VCC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(ENCLAVE_DIR)/%.o: $(ENCLAVE_DIR)/%.cpp $(ENCLAVE_DIR)/Enclave_t.c
	$(VCXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(ENCLAVE_DIR)/%.o: $(ENCLAVE_DIR)/%.c $(ENCLAVE_DIR)/Enclave_t.c
	$(VCC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

$(ENCLAVE_DIR)/tests/%.o: $(ENCLAVE_DIR)/tests/%.c $(ENCLAVE_DIR)/Enclave_t.c
	$(VCC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

Enclave.so: $(ENCLAVE_DIR)/Enclave_t.o $(Enclave_Cpp_Objects) $(Enclave_C_Objects)
	$(VCXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

Enclave.signed.so: Enclave.so
ifeq ($(wildcard $(Enclave_Test_Key)),)
	@echo "There is no enclave test key<Enclave_private_test.pem>."
	@echo "The project will generate a key<Enclave_private_test.pem> for test."
	@openssl genrsa -out $(Enclave_Test_Key) -3 3072
endif
	@$(SGX_ENCLAVE_SIGNER) sign -key $(Enclave_Test_Key) -enclave Enclave.so -out $@ -config $(ENCLAVE_DIR)/Enclave.config.xml
	@echo "SIGN =>  $@"

clean:
	@rm -f Enclave.* $(ENCLAVE_DIR)/Enclave_t.* $(Enclave_Cpp_Objects) $(Enclave_C_Objects) $(Enclave_Test_Key) enclave.token

