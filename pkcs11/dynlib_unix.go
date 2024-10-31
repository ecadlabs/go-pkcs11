// Copyright 2021 Google LLC
// Copyright 2024 ECAD Labs Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux || darwin || freebsd

package pkcs11

/*
#cgo linux LDFLAGS: -ldl

#include <dlfcn.h>

#include "platform.h"

#define CKR_DLOPEN (CKR_VENDOR_DEFINED | 1UL)
#define CKR_DLSYM (CKR_VENDOR_DEFINED | 2UL)

CK_RV open_library(const char *path, void **module, CK_FUNCTION_LIST **p) {
	*module = dlopen(path, RTLD_LAZY);
	if (*module == NULL) {
		return CKR_DLOPEN;
	}
	CK_C_GetFunctionList getFunctionList = dlsym(*module, "C_GetFunctionList");
	if (getFunctionList == NULL) {
		return CKR_DLSYM;
	}
	return getFunctionList(p);
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

type unixDynLibrary struct {
	mod unsafe.Pointer
}

func (l unixDynLibrary) close() error {
	if C.dlclose(l.mod) != 0 {
		return fmt.Errorf("pkcs11: dlclose error: %s", C.GoString(C.dlerror()))
	}
	return nil
}

func openLibrary(path string) (*functionList, dynLibrary, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	var (
		module unsafe.Pointer
		funcs  *functionList
	)

	ret := C.open_library(cPath, &module, &funcs)
	if ret != C.CKR_OK {
		if ret == C.CKR_DLOPEN {
			return nil, nil, fmt.Errorf("pkcs11: error opening library %s: %s", path, C.GoString(C.dlerror()))
		}
		if module != nil {
			C.dlclose(module)
		}
		if ret == C.CKR_DLSYM {
			return nil, nil, fmt.Errorf("pkcs11: can't resolve symbol")
		}
		return nil, nil, &Error{fnName: "C_GetFunctionList", code: ret}
	}
	return funcs, unixDynLibrary{mod: module}, nil
}
