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

#include "keyx/crypto/public_key.h"

namespace keyx::crypto {

PublicKey::PublicKey(PublicKey&& other) noexcept : Key(std::move(other)) {}

PublicKey& PublicKey::operator=(PublicKey&& other) noexcept {
  Key::operator=(std::move(other));

  return *this;
}

bool PublicKey::LoadFromFile(const fs::path& file) {
  try {
    auto fp = std::unique_ptr<FILE, decltype(&fclose)>(
        fopen(file.string().c_str(), "r"), fclose);
    if (!fp) {
      last_error_ = "Failed to open file";
      return false;
    }

    if (key_) {
      EVP_PKEY_free(key_);
      key_ = nullptr;
    }

    key_ = PEM_read_PUBKEY(fp.get(), nullptr, nullptr, nullptr);
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

bool PublicKey::SaveToFile(const fs::path& file) {
  if (!key_) {
    last_error_ = "No public key loaded";
    return false;
  }

  try {
    auto fp = std::unique_ptr<FILE, decltype(&fclose)>(
        fopen(file.string().c_str(), "w"), fclose);
    if (!fp) {
      last_error_ = "Failed to open file for writing";
      return false;
    }

    if (PEM_write_PUBKEY(fp.get(), key_) != 1) {
      last_error_ = GetOpenSSLError();
      return false;
    }

    return true;
  } catch (const std::exception& e) {
    last_error_ = e.what();
    return false;
  }
}

bool PublicKey::LoadFromPEM(std::string_view pem) {
  auto bio = std::unique_ptr<BIO, decltype(&BIO_free)>(
      BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);

  if (!bio) {
    last_error_ = "Failed to create BIO";
    return false;
  }

  if (key_) {
    EVP_PKEY_free(key_);
    key_ = nullptr;
  }

  key_ = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
  if (!key_) {
    last_error_ = GetOpenSSLError();
    return false;
  }

  return true;
}

std::string PublicKey::ToPEM() {
  if (!key_) {
    last_error_ = "No public key available";
    return {};
  }

  auto bio =
      std::unique_ptr<BIO, decltype(&BIO_free)>(BIO_new(BIO_s_mem()), BIO_free);

  if (!bio) {
    last_error_ = "Failed to create BIO";
    return {};
  }

  if (PEM_write_bio_PUBKEY(bio.get(), key_) != 1) {
    last_error_ = GetOpenSSLError();
    return {};
  }

  char* data = nullptr;  // needn't to free mannulay
  long len = BIO_get_mem_data(bio.get(), &data);
  if (len <= 0 || !data) {
    last_error_ = "Failed to get PEM data";
    return {};
  }

  return std::string{data, static_cast<size_t>(len)};
}

auto PublicKey::Encrypt(std::span<const uint8_t> data)
    -> std::optional<std::vector<uint8_t>> {
  if (!key_) {
    last_error_ = "No public key available";
    return std::nullopt;
  }

  try {
    auto ctx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(
        EVP_PKEY_CTX_new(key_, nullptr), EVP_PKEY_CTX_free);

    if (!ctx) {
      last_error_ = "Failed to create encryption context";
      return std::nullopt;
    }

    if (EVP_PKEY_encrypt_init(ctx.get()) <= 0) {
      last_error_ = "Failed to initialize encryption";
      return std::nullopt;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0) {
      last_error_ = "Failed to set padding";
      return std::nullopt;
    }

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx.get(), nullptr, &outlen, data.data(),
                         data.size()) <= 0) {
      last_error_ = "Failed to determine output length";
      return std::nullopt;
    }

    std::vector<uint8_t> encrypted(outlen);

    if (EVP_PKEY_encrypt(ctx.get(), encrypted.data(), &outlen, data.data(),
                         data.size()) <= 0) {
      last_error_ = "Encryption failed";
      return std::nullopt;
    }

    encrypted.resize(outlen);
    return encrypted;

  } catch (const std::exception& e) {
    last_error_ = e.what();
    return std::nullopt;
  }

  return std::nullopt;
}

bool PublicKey::VerifySignature(std::span<const uint8_t> data,
                                std::span<const uint8_t> signature) {
  if (!key_) {
    last_error_ = "No public key available";
    return false;
  }

  try {
    auto md_ctx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>(
        EVP_MD_CTX_new(), EVP_MD_CTX_free);

    if (!md_ctx) {
      last_error_ = "Failed to create verification context";
      return false;
    }

    if (EVP_DigestVerifyInit(md_ctx.get(), nullptr, EVP_sha256(), nullptr,
                             key_) != 1) {
      last_error_ = "Failed to initialize verification";
      return false;
    }

    if (EVP_DigestVerifyUpdate(md_ctx.get(), data.data(), data.size()) != 1) {
      last_error_ = "Failed to update verification";
      return false;
    }

    int verify_result =
        EVP_DigestVerifyFinal(md_ctx.get(), signature.data(), signature.size());

    if (verify_result < 0) {
      last_error_ = "Verification failed with error";
      return false;
    }

    return verify_result == 1;

  } catch (const std::exception& e) {
    last_error_ = e.what();
    return false;
  }
}

void PublicKey::TakeOwnership(EVP_PKEY*& public_key) {
  if (key_) {
    EVP_PKEY_free(key_);
    key_ = nullptr;
  }

  key_ = public_key;
  public_key = nullptr;
}

}  // namespace keyx::crypto
