/* Copyright (c) 2022, All Rights Reserved

The software is provided "AS IS", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability,
fitness for a particular purpose and noninfringement. In no event shall the
authors or copyright holders be liable for any claim, damages or other
liability, whether in an action of contract, tort or otherwise, arising from,
out of or in connection with the software or the use or other dealings in
the software. */

#ifndef PASSWORD_BREACH_CHECK_H_INCLUDED
#define PASSWORD_BREACH_CHECK_H_INCLUDED

#include <mysql/components/component_implementation.h>
#include <mysql/components/service_implementation.h>
#include <mysql/components/services/log_builtins.h>
#include <mysql/components/services/mysql_string.h>
#include <mysql/components/services/udf_registration.h>
#include <mysql/components/services/validate_password.h>

#include <string>    /* std::string */
#include <sstream>   /* std::stringstream */

/* Service placeholders */
extern REQUIRES_SERVICE_PLACEHOLDER(log_builtins);
extern REQUIRES_SERVICE_PLACEHOLDER(log_builtins_string);
extern REQUIRES_SERVICE_PLACEHOLDER(mysql_string_converter);
extern REQUIRES_SERVICE_PLACEHOLDER(udf_registration);

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
