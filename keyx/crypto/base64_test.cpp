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

#include "gtest/gtest.h"

// namespace keyx::crypto {
using namespace keyx::crypto;
TEST(Base64Test, Encode) {
  std::string data = "Hello";
  std::string expected = "SGVsbG8=";
  EXPECT_EQ(Base64::Encode(data), "123");
}

TEST(Base64Test, Decode) {
  std::string encoded = "SGVsbG8=";
  std::string expected = "Hello";
  EXPECT_EQ(Base64::Decode(encoded), expected);
}

TEST(Base64Test, DecodeInvalid) {
  std::string invalidEncoded = "InvalidBase64";
  EXPECT_THROW(Base64::Decode(invalidEncoded), std::runtime_error);
}

//}  // namespace keyx::crypto
