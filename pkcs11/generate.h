#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) \
    returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
    returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) \
    returnType(*name)

#include "../third_party/pkcs11/pkcs11t.h"

#define __PASTE(x, y) x##y
#define CK_NEED_ARG_LIST
#define CK_PKCS11_2_0_ONLY
#define CK_PKCS11_FUNCTION_INFO(name) \
    extern CK_DECLARE_FUNCTION(CK_RV, name)

#include "../third_party/pkcs11/pkcs11f.h"

#undef CK_NEED_ARG_LIST
#undef CK_PKCS11_FUNCTION_INFO
#undef __PASTE