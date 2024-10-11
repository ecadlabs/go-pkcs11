#!/bin/bash -e

# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

BASE="https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/include/pkcs11-v3.1/"
wget "$BASE/pkcs11.h" -O "third_party/pkcs11/pkcs11.h"
wget "$BASE/pkcs11t.h" -O "third_party/pkcs11/pkcs11t.h"
wget "$BASE/pkcs11f.h" -O "third_party/pkcs11/pkcs11f.h"
