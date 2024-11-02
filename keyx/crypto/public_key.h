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

#include <span>

#include "keyx/crypto/key.h"

namespace keyx {
namespace crypto {

class PublicKey : public Key {
 public:
  DISABLE_COPY_AND_ASSIGN(PublicKey)

  PublicKey() = default;
  ~PublicKey() noexcept override = default;

  PublicKey(PublicKey&& other) noexcept;
  PublicKey& operator=(PublicKey&& other) noexcept;

  bool LoadFromFile(const fs::path& file) override;
  bool SaveToFile(const fs::path& file) override;

  bool LoadFromPEM(std::string_view pem) override;
  std::string ToPEM() override;

  auto Encrypt(std::span<const uint8_t> data)
      -> std::optional<std::vector<uint8_t>>;

  bool VerifySignature(std::span<const uint8_t> data,
                       std::span<const uint8_t> signature);

  void TakeOwnership(EVP_PKEY*& public_key);
};

}  // namespace crypto
}  // namespace keyx