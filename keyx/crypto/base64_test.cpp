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

namespace keyx::crypto {

TEST(Base64Test, Encode) {
  constexpr std::string_view data = "Hello";
  constexpr std::string_view expected = "SGVsbG8=";
  EXPECT_EQ(Base64::Encode(data), expected);
}

TEST(Base64Test, Decode) {
  constexpr std::string_view encoded = "SGVsbG8=";
  constexpr std::string_view expected = "Hello";
  EXPECT_EQ(Base64::Decode(encoded), expected);
}

TEST(Base64Test, DecodeInvalid) {
  // Test various invalid inputs
  struct TestCase {
    std::string input;
    const char* description;
  };

  std::vector<TestCase> test_cases = {{"Invalid!", "Invalid characters"},
                                     {"ABC", "Length not multiple of 4"},
                                     {"A===", "Too many padding characters"},
                                     {"====", "All padding characters"},
                                     {"AB=A", "Invalid padding position"}};

  for (const auto& tc : test_cases) {
    // Provide better error information
    SCOPED_TRACE(tc.description);  
    EXPECT_EQ(Base64::Decode(tc.input), "");
  }
}

}  // namespace keyx::crypto
