/*
 * Copyright 2024 cxxzsh
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "keyx/crypto/base64.h"

#include <vector>

#include "openssl/bio.h"
#include "openssl/buffer.h"
#include "openssl/evp.h"

namespace keyx {
namespace crypto {

constexpr const char* kEmptyString = "";

std::string Base64::Encode(std::string_view raw) {
  BIO* bio = BIO_new(BIO_f_base64());
  BIO* bmem = BIO_new(BIO_s_mem());
  bio = BIO_push(bio, bmem);

  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(bio, raw.data(), static_cast<int>(raw.length()));
  BIO_flush(bio);

  BUF_MEM* buffer = nullptr;
  BIO_get_mem_ptr(bio, &buffer);
  std::string output{buffer->data, buffer->length};

  BIO_free_all(bio);

  return output;
}

std::string Base64::Decode(std::string_view encoded) {
  BIO* bio = BIO_new(BIO_f_base64());
  BIO* bmem = BIO_new_mem_buf(encoded.data(), -1);

  bio = BIO_push(bio, bmem);

  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

  size_t output_length = (encoded.size() * 3) / 4 + 1;

  std::vector<char> buffer(output_length);
  int decoded_length =
      BIO_read(bio, buffer.data(), static_cast<int>(output_length));

  BIO_free_all(bio);

  if (decoded_length <= 0) {
    return kEmptyString;
  }

  return std::string{buffer.begin(), buffer.begin() + decoded_length};
}

}  // namespace crypto
}  // namespace keyx
