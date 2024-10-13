#include <stdlib.h>

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) \
    returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
    returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) \
    returnType(*name)

#include "../third_party/pkcs11/pkcs11.h"