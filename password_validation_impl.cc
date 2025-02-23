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

#include <algorithm>

#include <mysql/components/services/validate_password.h>
#include "components/libservicebroadcast/service_broadcast.h"
#include "password_breach_check.h"

namespace password_breach_check {
/** Function registered by this component */
const char *FUNCTION_NAME = "password_breach_check";

/** Arbitrary large value indicating that empty string is not a good password */
const long long MAX_RETVAL = 1000000;

/**
  Helper function to raise error.

  @param [in] error_message  Error message to be logged
  @param [in] level          Severity of error
*/
void raise_error(const char *error_message, loglevel level) {
  std::stringstream ss;
  ss << "password_breach_check component reported: " << error_message;
  LogEvent()
      .type(LOG_TYPE_ERROR)
      .prio(level)
      .message(ss.str().c_str(), error_message);
}

bool Password_validation::register_functions() {
  if (mysql_service_udf_registration->udf_register(
          FUNCTION_NAME, Item_result::INT_RESULT,
          (Udf_func_any)Password_validation::password_breach_check,
          Password_validation::password_breach_check_init,
          Password_validation::password_breach_check_deinit)) {
    raise_error("Failed to register password_breach_check function.",
                ERROR_LEVEL);
    return true;
  }
  return false;
}

bool Password_validation::unregister_functions() {
  int was_present = 0;
  if (mysql_service_udf_registration->udf_unregister(FUNCTION_NAME,
                                                     &was_present) &&
      was_present) {
    raise_error("Failed to unregister password_breach_check function.",
                WARNING_LEVEL);
    return true;
  }
  return false;
}

/**
  Validates the strength of given password.

  @param password Given Password

  @return Status of performed operation
    @retval false Success
    @retval true  Failure
*/
DEFINE_BOOL_METHOD(Password_validation::validate,
                   (void *thd, my_h_string password)) {
  Breach_checker breach_checker(password);
  long long count = breach_checker.check();
  if (count == 0) {
    if (service_broadcast::broadcast([&thd, &password](
                                         const my_h_service *service_handle) {
          auto service = reinterpret_cast<SERVICE_TYPE(validate_password) *>(
              *service_handle);
          return service->validate(thd, password);
        }))
      return true;
  }
  return count != 0;
}

/**
  Gets the password strength between (0-100)

  @param password Given Password
  @param [out] strength pointer to handle the strength of the given password.
               in the range of [0-100], where 0 is week password and
               100 is strong password
  @return Status of performed operation
    @retval false Success
    @retval true  Failure
*/
DEFINE_BOOL_METHOD(Password_validation::get_strength,
                   (void *thd, my_h_string password, unsigned int *strength)) {
  *strength = 0;
  Breach_checker breach_checker(password);
  long long count = breach_checker.check();
  if (count == 0) *strength = 100;

  if (count == 0) {
    if (service_broadcast::broadcast([&thd, &password, &strength](
                                         const my_h_service *service_handle) {
          auto service = reinterpret_cast<SERVICE_TYPE(validate_password) *>(
              *service_handle);
          unsigned int auto_strength = 0;
          if (service->get_strength(thd, password, &auto_strength)) return true;
          *strength = std::min(*strength, auto_strength);
          return false;
        }))
      return true;
  }
  return false;
}

/**
  Init function for password_breach_check

  @param [in, out] initid  Structure to hold data to be passed to main
  function
  @param [in]      args    Argument metadata
  @param [out]     message Buffer to store error message

  @returns Status of checks
    @retval true  Error
    @retval false Success
*/
bool Password_validation::password_breach_check_init(UDF_INIT *initid,
                                                     UDF_ARGS *args,
                                                     char *message
                                                     [[maybe_unused]]) {
  initid->ptr = nullptr;

  if (args->arg_count != 1) {
    sprintf(message,
            "Mismatch in expected arguments to the function. Expected 1 "
            "argument of string typei.");
    return true;
  }

  if (args->arg_type[0] != STRING_RESULT) {
    sprintf(message,
            "Mismatch in type of argument. Expected string argument for "
            "password.");
    return true;
  }

  initid->maybe_null = false;
  return false;
}

/** Deinit function for password_breach_check - Nothing to see here */
void Password_validation::password_breach_check_deinit(UDF_INIT *initid
                                                       [[maybe_unused]]) {
  return;
}

/**
  Main function for password_breach_check

  @param [in]  initid   Unused
  @param [in]  args     UDF arguments
  @param [out] is_null  Flag indicating whether output is null or not
  @param [out] error    Flag indicating error
*/
long long Password_validation::password_breach_check(
    UDF_INIT *initid [[maybe_unused]], UDF_ARGS *args [[maybe_unused]],
    unsigned char *is_null [[maybe_unused]],
    unsigned char *error [[maybe_unused]]) {
  *error = 1;
  *is_null = 0;
  long long count = MAX_RETVAL;
  if (!args->args[0]) {
    raise_error(
        "Provide an non-empty password value to password_breach_check "
        "function.",
        ERROR_LEVEL);
    return count;
  }

  Breach_checker breach_checker(args->args[0]);
  count = breach_checker.check();
  *error = 0;
  return count;
}

}  // namespace password_breach_check
