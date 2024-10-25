#include <iostream>

#include <openssl/err.h>
#include <openssl/ssl.h>

int main() {
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();

  std::cout << "OpenSSL initialized successfully!" << std::endl;

  EVP_cleanup();
  return 0;
}