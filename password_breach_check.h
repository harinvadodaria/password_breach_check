/* MIT License

Copyright (c) 2024, Harin Vadodaria

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE. */

#ifndef PASSWORD_BREACH_CHECK_H_INCLUDED
#define PASSWORD_BREACH_CHECK_H_INCLUDED

#include <mysql/components/component_implementation.h>
#include <mysql/components/service_implementation.h>
#include <mysql/components/services/log_builtins.h>
#include <mysql/components/services/mysql_string.h>
#include <mysql/components/services/udf_registration.h>
#include <mysql/components/services/validate_password.h>
#include <mysql/components/services/security_context.h>
#include <mysql/components/services/mysql_current_thread_reader.h>


#include <sstream> /* std::stringstream */
#include <string>  /* std::string */

/* Service placeholders */
extern REQUIRES_SERVICE_PLACEHOLDER(log_builtins);
extern REQUIRES_SERVICE_PLACEHOLDER(log_builtins_string);
extern REQUIRES_SERVICE_PLACEHOLDER(mysql_string_converter);
extern REQUIRES_SERVICE_PLACEHOLDER(udf_registration);
extern REQUIRES_SERVICE_PLACEHOLDER(mysql_thd_security_context);
extern REQUIRES_SERVICE_PLACEHOLDER(mysql_security_context_options);
extern REQUIRES_SERVICE_PLACEHOLDER(mysql_current_thread_reader);

namespace password_breach_check {

extern const long long MAX_RETVAL;

/** A class that helps check given password against password breach database */
class Breach_checker {
 public:
  static void init_environment();
  static void deinit_environment();

 public:
  Breach_checker(const char *password);

  Breach_checker(my_h_string password);

  ~Breach_checker() {}

  long long check() const;

 private:
  bool generate_digest(std::string &digest) const;

  bool password_breach_data(const std::string prefix, std::string &out) const;

 private:
  /* Status */
  bool ready_{false};
  /* Password to be checked */
  std::string password_;
  /* Retry count */
  unsigned int retry_;
};

/**
  Password validation service and password_breach_check function
  implementation
*/
class Password_validation {
 public:
  static DEFINE_BOOL_METHOD(validate, (void *, my_h_string password));

  static DEFINE_BOOL_METHOD(get_strength, (void *, my_h_string password,
                                           unsigned int *strength));

  static bool password_breach_check_init(UDF_INIT *initid, UDF_ARGS *args,
                                         char *message);

  static void password_breach_check_deinit(UDF_INIT *initid);

  static long long password_breach_check(UDF_INIT *initid, UDF_ARGS *args,
                                         unsigned char *is_null,
                                         unsigned char *error);

  static bool register_functions();
  static bool unregister_functions();
};

void raise_error(const char *error_message, loglevel level);

}  // namespace password_breach_check
#endif /* PASSWORD_BREACH_CHECK_H_INCLUDED */
