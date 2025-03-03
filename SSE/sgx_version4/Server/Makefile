include ../buildenv.mk

# 构建并编译
all:
	@$(MAKE) -f sgx_u.mk LINUX_SGX_BUILD=$(LINUX_SGX_BUILD) all
	@$(MAKE) -f sgx_t.mk LINUX_SGX_BUILD=$(LINUX_SGX_BUILD) all

# 运行
test: all
	@$(MAKE) -f sgx_u.mk test

# 清除
clean:
	@$(MAKE) -f sgx_u.mk clean
	@$(MAKE) -f sgx_t.mk clean

