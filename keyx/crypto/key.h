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

#pragma once

#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/pem.h"

#include "keyx/global.h"

namespace keyx {

class Key {
 public:
  Key() = default;

  virtual ~Key() noexcept {
    if (key_) {
      EVP_PKEY_free(key_);
    }
  }

  Key(Key&& other) noexcept { std::swap(key_, other.key_); }

  Key& operator=(Key&& other) noexcept {
    if (this != &other) {
      if (key_) {
        EVP_PKEY_free(key_);
      }

      std::swap(key_, other.key_);
    }

    return *this;
  }

  virtual bool LoadFromFile(const fs::path& file) = 0;
  virtual bool SaveToFile(const fs::path& file) = 0;

  virtual bool LoadFromPEM(std::string_view pem) = 0;
  virtual std::string ToPEM() = 0;

  bool IsValid() const noexcept { return key_ != nullptr; }
  const std::string& GetLastError() const noexcept { return last_error_; }

 protected:
  EVP_PKEY* key_ = nullptr;
  std::string last_error_;

  static std::string GetOpenSSLError() {
    BIO* bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char* buf;
    size_t len = BIO_get_mem_data(bio, &buf);
    std::string result(buf, len);
    BIO_free(bio);
    return result;
  }
};

}  // namespace keyx
