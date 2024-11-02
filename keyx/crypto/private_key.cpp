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

#include "keyx/crypto/private_key.h"

namespace keyx::crypto {

PrivateKey::PrivateKey(PrivateKey&& other) noexcept : Key(std::move(other)) {}

PrivateKey& PrivateKey::operator=(PrivateKey&& other) noexcept {
  Key::operator=(std::move(other));

  return *this;
}

bool PrivateKey::LoadFromFile(const fs::path& file) {
  try {
    auto fp = std::unique_ptr<FILE, decltype(&fclose)>{
        fopen(file.string().c_str(), "r"), fclose};

    if (!fp) {
      last_error_ = "Failed to open file";
      return false;
    }

    if (key_) {
      EVP_PKEY_free(key_);
      key_ = nullptr;
    }

    key_ = PEM_read_PrivateKey(fp.get(), nullptr, nullptr, nullptr);
    if (!key_) {
      last_error_ = GetOpenSSLError();
      return false;
    }

    return true;

  } catch (const std::exception& e) {
    last_error_ = e.what();
    return false;
  }
}

bool PrivateKey::SaveToFile(const fs::path& file) {
  if (!key_) {
    last_error_ = "No private key loaded";
    return false;
  }

  try {
    auto fp = std::unique_ptr<FILE, decltype(&fclose)>(
        fopen(file.string().c_str(), "w"), fclose);

    if (!fp) {
      last_error_ = "Failed to open file for writing";
      return false;
    }

    if (!PEM_write_PrivateKey(fp.get(), key_, nullptr, nullptr, 0, nullptr,
                              nullptr)) {
      last_error_ = GetOpenSSLError();
      return false;
    }

    return true;

  } catch (const std::exception& e) {
    last_error_ = e.what();
    return false;
  }
}

bool PrivateKey::LoadFromPEM(std::string_view pem) {
  auto bio = std::unique_ptr<BIO, decltype(&BIO_free)>(
      BIO_new_mem_buf(pem.data(), pem.size()), BIO_free);

  if (!bio) {
    last_error_ = "Failed to create BIO";
    return false;
  }

  if (key_) {
    EVP_PKEY_free(key_);
    key_ = nullptr;
  }

  key_ = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
  if (!key_) {
    last_error_ = GetOpenSSLError();
    return false;
  }

  return true;
}

std::string PrivateKey::ToPEM() {
  if (!key_) {
    last_error_ = "No private key loaded";
    return {};
  }

  try {
    auto bio = std::unique_ptr<BIO, decltype(&BIO_free)>(BIO_new(BIO_s_mem()),
                                                         BIO_free);
    if (!bio) {
      last_error_ = "Failed to create BIO";
      return {};
    }

    if (!PEM_write_bio_PrivateKey(bio.get(), key_, nullptr, nullptr, 0, nullptr,
                                  nullptr)) {
      last_error_ = "Failed to write private key";
      return {};
    }

    BUF_MEM* mem;
    BIO_get_mem_ptr(bio.get(), &mem);

    return std::string(mem->data, mem->length);

  } catch (const std::exception& e) {
    last_error_ = e.what();
    return {};
  }
}

PublicKey PrivateKey::GeneratePublicKey() {
  if (!key_) {
    last_error_ = "No key data";
    return PublicKey{};
  }

  try {
    PublicKey pub_key;
    EVP_PKEY* pub = EVP_PKEY_dup(key_);
    if (!pub) {
      last_error_ = "Failed to generate public key";
      return PublicKey{};
    }

    pub_key.TakeOwnership(pub);
    return pub_key;

  } catch (const std::exception& e) {
    last_error_ = e.what();
    return PublicKey{};
  }
}

}  // namespace keyx::crypto
