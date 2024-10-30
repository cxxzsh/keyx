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

class Base64Test : public ::testing::Test {
 protected:
  void SetUp() override {}
  void TearDown() override {}

  const char* kEmptyString = "";
};

TEST_F(Base64Test, Encode) {
  EXPECT_EQ(Base64::Encode("Hello"), "SGVsbG8=");
  EXPECT_EQ(Base64::Encode(""), "");
  EXPECT_NE(
      Base64::Encode(
          R"(This is line one\nThis is line two\nThis is line three\nAnd so on...\n)"),
      R"(VGhpcyBpcyBsaW5lIG9uZQpUaGlzIGlzIGxpbmUgdHdvClRoaXMgaXMgbGlu\nZSB0aHJlZQpBbmQgc28gb24uLi4K\n)");
}

TEST_F(Base64Test, Decode) {
  EXPECT_EQ(Base64::Decode("SGVsbG8="), "Hello");
  EXPECT_EQ(Base64::Decode(""), "");
}

TEST_F(Base64Test, DecodeInvalid) {
  // Test various invalid inputs
  struct TestCase {
    std::string input;
    const char* description;
  };

  const std::vector<TestCase> test_cases = {
      {"Invalid!", "Invalid characters"},
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

// Basic encoding and decoding test
TEST_F(Base64Test, BasicEncodeDecode) {
  std::string original = "Hello, World!";
  std::string encoded = Base64::Encode(original);
  std::string decoded = Base64::Decode(encoded);
  EXPECT_EQ(original, decoded);
  EXPECT_EQ(encoded, "SGVsbG8sIFdvcmxkIQ==");
}

// Empty string test
TEST_F(Base64Test, EmptyString) {
  std::string empty;
  EXPECT_EQ(Base64::Encode(empty), "");
  EXPECT_EQ(Base64::Decode(""), "");
}

// Test with special characters
TEST_F(Base64Test, SpecialCharacters) {
  std::string special = "!@#$%^&*()_+{}:\"|<>?~`-=[]\\;',./";
  std::string encoded = Base64::Encode(special);
  std::string decoded = Base64::Decode(encoded);
  EXPECT_EQ(special, decoded);
}

// Binary data test
TEST_F(Base64Test, BinaryData) {
  std::string binary;
  binary.push_back('\0');
  binary.push_back('\1');
  binary.push_back('\255');
  binary.push_back('\254');
  std::string encoded = Base64::Encode(binary);
  std::string decoded = Base64::Decode(encoded);
  EXPECT_EQ(binary, decoded);
}

// Test different input lengths
TEST_F(Base64Test, DifferentLengths) {
  // 1 byte - Requires 2 equal sign fills
  EXPECT_EQ(Base64::Encode("a"), "YQ==");
  // 2 bytes - Requires 1 equal sign padding
  EXPECT_EQ(Base64::Encode("ab"), "YWI=");
  // 3 bytes - No filler required
  EXPECT_EQ(Base64::Encode("abc"), "YWJj");
}

// Unicode characters test
TEST_F(Base64Test, UnicodeCharacters) {
  std::string unicode = "Hello, 世界! 🌍";
  std::string encoded = Base64::Encode(unicode);
  std::string decoded = Base64::Decode(encoded);
  EXPECT_EQ(unicode, decoded);
}

// Long string test
TEST_F(Base64Test, LongString) {
  std::string long_str(10000, 'A');
  std::string encoded = Base64::Encode(long_str);
  std::string decoded = Base64::Decode(encoded);
  EXPECT_EQ(long_str, decoded);
}

// Padding test
TEST_F(Base64Test, Padding) {
  EXPECT_EQ(Base64::Decode("YQ=="), "a");
  EXPECT_EQ(Base64::Decode("YWI="), "ab");
  EXPECT_EQ(Base64::Decode("YWJj"), "abc");
}

// Invalid input test
TEST_F(Base64Test, InvalidInput) {
  // Decode illegal characters
  EXPECT_EQ(Base64::Decode("!@#$"), kEmptyString);
  // Decode length is not a multiple of 4
  EXPECT_EQ(Base64::Decode("YWJjZA="), kEmptyString);
  // Decode fill error
  EXPECT_EQ(Base64::Decode("YQ="), kEmptyString);
  EXPECT_EQ(Base64::Decode("YWI=="), kEmptyString);
}

// Repeated codec test
TEST_F(Base64Test, RepeatedCodec) {
  std::string original = "Test String";
  std::string encoded1 = Base64::Encode(original);
  std::string encoded2 = Base64::Encode(encoded1);
  std::string decoded2 = Base64::Decode(encoded2);
  std::string decoded1 = Base64::Decode(decoded2);
  EXPECT_EQ(original, decoded1);
}

// Boundary conditions test
TEST_F(Base64Test, BoundaryCases) {
  // All possible values for a single byte
  for (int i = 0; i < 256; ++i) {
    std::string single;
    single.push_back(static_cast<char>(i));
    std::string encoded = Base64::Encode(single);
    std::string decoded = Base64::Decode(encoded);
    EXPECT_EQ(single, decoded);
  }
}

// URL security character test
TEST_F(Base64Test, URLSecurityCharacters) {
  std::string url = "https://www.example.com/path?param=value";
  std::string encoded = Base64::Encode(url);
  std::string decoded = Base64::Decode(encoded);
  EXPECT_EQ(url, decoded);
}

// Consecutive null bytes test
TEST_F(Base64Test, ConsecutiveNullBytes) {
  std::string nulls;
  nulls.append(5, '\0');
  std::string encoded = Base64::Encode(nulls);
  std::string decoded = Base64::Decode(encoded);
  EXPECT_EQ(nulls.size(), decoded.size());
  EXPECT_EQ(nulls, decoded);
}

}  // namespace keyx::crypto
