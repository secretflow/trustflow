// Copyright 2025 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace trustflow {
namespace attestation {
namespace utils {

// Convert binary (as char array) to UTF-8 escaped string as std::string.
// - ASCII printable characters (0x20-0x7E): used as-is (except \ and " which are escaped)
// - Control characters (0x00-0x1F): escaped as \uXXXX
// - Non-ASCII bytes (0x80-0xFF): escaped as \uXXXX
// This allows non-UTF-8 bytes to be stored in protobuf string fields.
//
// Note: The format of Intel's PCS Collateral CRLs are determined by the collateral version.
//       Collateral version 1.0 (PCS/PCCS API V1 or V2): PEM (string)
//       Collateral version 3.0 (PCS/PCCS API V3): Base16 encoded DER (hex string)
//       Collateral version 3.1 (PCS/PCCS API V3): Raw binary DER (binary data)
inline void CharArrayBinaryToEscapedString(const uint8_t* data, size_t size, std::string& result) {
  result.clear();
  result.reserve(size * 6);  // Worst case: each byte becomes \uXXXX (6 chars)
  
  for (size_t i = 0; i < size; ++i) {
    uint8_t byte = data[i];
    
    if (byte >= 0x20 && byte <= 0x7E) {
      // ASCII printable characters: use as-is
      // Escape special JSON characters
      if (byte == '\\' || byte == '"') {
        result += '\\';
        result += static_cast<char>(byte);
      } else {
        result += static_cast<char>(byte);
      }
    } else {
      // Control characters (0x00-0x1F), DEL (0x7F), and non-ASCII bytes (0x80-0xFF): escape as \uXXXX
      char hex[7];
      snprintf(hex, sizeof(hex), "\\u%04X", static_cast<unsigned int>(byte));
      result += hex;
    }
  }
}

// Convert escaped string (\uXXXX sequences) back to binary (as char array).
// If add_null_terminator is true, appends a null byte at the end for C string compatibility.
inline std::vector<uint8_t> EscapedStringToCharArrayBinary(const std::string& escaped_str, bool add_null_terminator = false) {
  std::vector<uint8_t> binary;
  binary.reserve(escaped_str.size() + (add_null_terminator ? 1 : 0));  // Approximate size
  
  for (size_t i = 0; i < escaped_str.size(); ++i) {
    if (escaped_str[i] == '\\' && i + 1 < escaped_str.size()) {
      if (escaped_str[i + 1] == 'u' && i + 5 < escaped_str.size()) {
        // \uXXXX sequence (6 chars: \uXXXX)
        std::string hex = escaped_str.substr(i + 2, 4);
        char* endptr = nullptr;
        unsigned long val = std::strtoul(hex.c_str(), &endptr, 16);
        if (endptr == hex.c_str() + 4 && val <= 0xFF) {
          binary.push_back(static_cast<uint8_t>(val));
          i += 5;  // Skip \uXXXX (6 chars total: i, i+1, i+2, i+3, i+4, i+5)
          continue;
        }
      } else if (escaped_str[i + 1] == '\\' || escaped_str[i + 1] == '"') {
        // Escaped backslash or quote
        binary.push_back(static_cast<uint8_t>(escaped_str[i + 1]));
        i += 1;  // Skip escape char
        continue;
      }
      // If escape sequence is not recognized, treat backslash as regular character
    }
    // Regular character
    binary.push_back(static_cast<uint8_t>(escaped_str[i]));
  }
  
  if (add_null_terminator) {
    binary.push_back(0);  // Add null terminator
  }
  
  return binary;
}

}  // namespace utils
}  // namespace attestation
}  // namespace trustflow
