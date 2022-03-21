/* Copyright (c) 2022, All Rights Reserved

The software is provided "AS IS", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability,
fitness for a particular purpose and noninfringement. In no event shall the
authors or copyright holders be liable for any claim, damages or other
liability, whether in an action of contract, tort or otherwise, arising from,
out of or in connection with the software or the use or other dealings in
the software. */

#include "password_breach_check.h"

#include <algorithm> /* std::transform */
#include <chrono>    /* std::chrono::seconds(1) */
#include <iomanip>   /* std::setfill */
#include <thread>    /* std::this_thread::sleep_for */

#include <curl/curl.h> /* CURL functions */

#include <openssl/err.h> /* ERR_* functions */
#include <openssl/evp.h> /* EVP_MD_* functions */

namespace password_breach_check {

/** Maximum password length supported */
const size_t MAX_LENGTH = 512;

/** SHA1 digest size */
const size_t SHA1_HASH_SIZE = 20;

/** URL to check for password breach information */
const char *URL_PREFIX = "https://api.pwnedpasswords.com/range/";

/** Wait time(in seconds) between two CURL requests */
const unsigned int WAIT = 2;

/** Init CURL */
void Breach_checker::init_environment() {
  curl_global_init(CURL_GLOBAL_DEFAULT);
}

/** Deinit CURL */
void Breach_checker::deinit_environment() { curl_global_cleanup(); }

/**
  Constructor used by password_breach_check function

  @param [in] password  Password to be checked
*/
Breach_checker::Breach_checker(const char *password)
    : ready_{true}, password_{password ? password : ""}, retry_{3} {}

/**
  Constructor used by validate_password APIs

  @param [in] password  Password to be checked
*/
Breach_checker::Breach_checker(my_h_string password) : password_{}, retry_{3} {
  char buffer[MAX_LENGTH];

  /* Convert incoming password to UTF8 format */
  if (mysql_service_mysql_string_converter->convert_to_buffer(
          password, buffer, sizeof(buffer), "utf8")) {
    raise_error("Failed to convert password to 'utf8' format.", ERROR_LEVEL);
    return;
  }
  password_.assign(buffer, strlen(buffer));
  ready_ = true;
}

/**
  Check password against password breach data

  @returns Number of times the password appeared in breach
*/
long long Breach_checker::check() const {
  long long count = MAX_RETVAL;

  /* 1. Sanity checks */
  if (!ready_ || password_.length() == 0) return count;

  /* 2. Generate SHA1 hash */
  std::string sha1_digest{};
  if (generate_digest(sha1_digest) == true) return count;

  /* 3. Retrieve breached password hash list */
  auto prefix = sha1_digest.substr(0, 5);
  auto suffix = sha1_digest.substr(5);

  std::string out_data{};
  if (password_breach_data(prefix, out_data) == true) return count;

  /* 4. Search for the hash suffix */
  size_t pos = out_data.find(suffix);

  if (pos != std::string::npos) {
    /*
      We found the partial hash. Now, get the count
      to know how many times it appeared in breaches.

      Entries will be in following format

      <sha1_hash_suffix_1>:count_1\r\n
      <sha1_hash_suffix_2>:count_2\r\n
      ...
      ...
      <sha1_hash_suffix_n>:count_n

      count_* implies number of times a given pass
    */
    pos = out_data.find(":", pos);
    auto nl = out_data.find("\r\n", pos);
    if (nl != std::string::npos) {
      count = std::stoll(out_data.substr(pos + 1, nl - pos - 1));
    } else {
      /* Last entry in the list. There is no new line at the end of the list. */
      count = std::stoll(out_data.substr(pos + 1));
    }
    std::stringstream error_message;
    error_message << "The password with SHA1 prefix '" << prefix
                  << "' has appeared " << count
                  << " times in password breaches.";
    raise_error(error_message.str().c_str(), WARNING_LEVEL);
  } else {
    /* Password does not appear in any breach */
    count = 0;
  }

  return count;
}

/**
  Function to generated SHA1 digest

  @param [out] digest Generated SHA1 digest

  @returns status of the operation
    @retval true  Error
    @retval false Success
*/
bool Breach_checker::generate_digest(std::string &digest) const {
  auto error_out = [&]() {
    char error_buffer[512]{0};
    ERR_error_string(ERR_get_error(), error_buffer);
    std::stringstream error_message;
    error_message << "Received error from OpenSSL: " << error_buffer;
    raise_error(error_message.str().c_str(), ERROR_LEVEL);
  };

  EVP_MD_CTX *ctx = EVP_MD_CTX_create();
  if (ctx == nullptr) return true;
  auto ctx_cleanup = [&]() {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    EVP_MD_CTX_free(ctx);
#else
    EVP_MD_CTX_destroy(ctx);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
    ctx = nullptr;
    ERR_clear_error();
  };

  if (EVP_DigestInit(ctx, EVP_sha1()) != 1) {
    error_out();
    ctx_cleanup();
    return true;
  }

  if (EVP_DigestUpdate(ctx, password_.c_str(), password_.length()) != 1) {
    error_out();
    ctx_cleanup();
    return true;
  }

  char out[SHA1_HASH_SIZE];
  if (EVP_DigestFinal(ctx, reinterpret_cast<unsigned char *>(out), nullptr) !=
      1) {
    error_out();
    ctx_cleanup();
    return true;
  }

  ctx_cleanup();
  digest.assign(out, SHA1_HASH_SIZE);

  /* Convert the digest to hex format */
  std::stringstream hexstream;
  for (auto const &character : digest) {
    hexstream << std::setw(2) << std::setfill('0') << std::hex << std::uppercase
              << (int)(unsigned char)character;
  }
  digest.assign(hexstream.str());

  return false;
}

/** Structure used to process GET data */
struct Result {
  std::stringstream body;
};

/** Writer callback for CURL */
static size_t writer_callback(void *contents, size_t size, size_t nmemb,
                              void *userp) {
  /*
    As per https://haveibeenpwned.com/API/v2#PwnedPasswords,
    maximum number of entries returned by a range search is
    584. Assuming that a password has appeared, 1M times in
    breaches, each line would have:
    35 chars in hash suffix + : + 7 chars in count + CRLF = 45 chars

    So we are looking at ~25kb of data in worst case
  */
  std::stringstream *ss = static_cast<std::stringstream *>(userp);
  ss->write(static_cast<char *>(contents), size * nmemb);
  return size * nmemb;
}

/**
  Get password breach data

  @param [in]  prefix  SHA1 digest prefix - first 5 characters
  @param [out] out     SHA1 digest suffix of all breached password along
                       with the count representating how many times each
                       one appears in data breach

  @returns status of the operation
    @retval true  Failure
    @retval false Success
*/
bool Breach_checker::password_breach_data(const std::string prefix,
                                          std::string &out) const {
  /* 1. Setup CURL */
  std::string url{URL_PREFIX};
  url.append(prefix);
  auto retry = retry_;

  CURLcode res;

  while (retry > 0) {
    Result result;
    CURL *curl = curl_easy_init();

    if (curl == nullptr) return true;

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writer_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result.body);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "mysql/1.0");

    /* 2. Call API */
    res = curl_easy_perform(curl);

    /* 3. Process and return the result */
    if (res != CURLE_OK) {
      std::stringstream error_message;
      error_message << "Error making GET request. CURL returned: "
                    << curl_easy_strerror(res);
      raise_error(error_message.str().c_str(), ERROR_LEVEL);
      error_message.str("");
      if (retry > 0) {
        error_message << "Retrying " << retry << " times before giving up.";
      } else {
        error_message << "Tried " << retry_
                      << " times. Giving up. Please verify that "
                         "https://api.pwnedpasswords.com/range is accessible "
                         "(Should show 'Invalid API query' as response).";
      }
      raise_error(error_message.str().c_str(), WARNING_LEVEL);
    } else {
      /* Populate the output buffer */
      out.assign(result.body.str());
      break;
    }
    curl_easy_cleanup(curl);
    retry--;
    std::this_thread::sleep_for(std::chrono::seconds(WAIT));
  }
  return (res != CURLE_OK);
}

}  // namespace password_breach_check
