#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <stdlib.h>
#include <assert.h>

#define TEST_CHECK(status)	\
{	\
	if (status != SGX_SUCCESS) {	\
		printf("OCALL status check failed %s(%d), status = %d\n", __FUNCTION__, __LINE__, status);	\
		abort();	\
	}	\
}

#if defined(__cplusplus)
extern "C" {
#endif

int printf(const char* fmt, ...);

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */
