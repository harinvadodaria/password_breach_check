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

#include "components/libservicebroadcast/service_broadcast.h"
#include "password_breach_check.h"

/* Service placeholders */
REQUIRES_SERVICE_PLACEHOLDER(log_builtins);
REQUIRES_SERVICE_PLACEHOLDER(log_builtins_string);
REQUIRES_SERVICE_PLACEHOLDER(mysql_string_converter);
REQUIRES_SERVICE_PLACEHOLDER(udf_registration);
REQUIRES_SERVICE_PLACEHOLDER(mysql_current_thread_reader);
REQUIRES_SERVICE_PLACEHOLDER(mysql_thd_security_context);
REQUIRES_SERVICE_PLACEHOLDER(mysql_security_context_options);
ADD_BROADCAST_SERVICE_PLACEHOLDERS

SERVICE_TYPE(log_builtins) * log_bi;
SERVICE_TYPE(log_builtins_string) * log_bs;

namespace password_breach_check {
const char *component_name = "password_breach_check";
const char *service_name = "validate_password";

using namespace service_broadcast;

/**
  Initialization entry method for the component

  @return Status of initialization
    @retval true  failure
    @retval false success
*/
static mysql_service_status_t password_breach_check_init() {
  log_bi = mysql_service_log_builtins;
  log_bs = mysql_service_log_builtins_string;

  if (service_broadcast::init(service_name, component_name, true)) return true;

  Breach_checker::init_environment();
  if (Password_validation::register_functions()) {
    Breach_checker::deinit_environment();
    service_broadcast::deinit();
    return true;
  }
  return false;
}

/**
  De-initialization method for the component

  @return Status of deinitialization
    @retval true failure
    @retval false success
*/
static mysql_service_status_t password_breach_check_deinit() {
  if (service_broadcast::deinit()) return true;
  Breach_checker::deinit_environment();
  if (Password_validation::unregister_functions()) return true;
  return false;
}

}  // namespace password_breach_check

/****************************************************************************/

/* Component provides: validate_password component service implementation */
BEGIN_SERVICE_IMPLEMENTATION(password_breach_check, validate_password)
password_breach_check::Password_validation::validate,
    password_breach_check::Password_validation::get_strength
    END_SERVICE_IMPLEMENTATION();

ADD_BROADCAST_SERVICE_IMPLEMENTATION(password_breach_check)

/* component provides: the password_breach_check service */
BEGIN_COMPONENT_PROVIDES(password_breach_check)
PROVIDES_SERVICE(password_breach_check, validate_password),
    ADD_BROADCAST_SERVICE_PROVIDES(password_breach_check)
        END_COMPONENT_PROVIDES();

/* Dependencies */
BEGIN_COMPONENT_REQUIRES(password_breach_check)
REQUIRES_SERVICE(log_builtins), REQUIRES_SERVICE(log_builtins_string),
    REQUIRES_SERVICE(mysql_string_converter),
    REQUIRES_SERVICE(udf_registration),
    REQUIRES_SERVICE(mysql_current_thread_reader),
    REQUIRES_SERVICE(mysql_thd_security_context),
    REQUIRES_SERVICE(mysql_security_context_options),
    ADD_BROADCAST_SERVICE_DEPENDENCIES END_COMPONENT_REQUIRES();

/* component description */
BEGIN_COMPONENT_METADATA(password_breach_check)
METADATA("mysql.author", "Harin Vadodaria"),
    METADATA("mysql.license", "All Rights Reserved"),
    METADATA("password_breach_check", "1"), END_COMPONENT_METADATA();

/* component declaration */
DECLARE_COMPONENT(password_breach_check, "password_breach_check")
password_breach_check::password_breach_check_init,
    password_breach_check::password_breach_check_deinit END_DECLARE_COMPONENT();

/* components contained in this library */
DECLARE_LIBRARY_COMPONENTS &COMPONENT_REF(password_breach_check)
    END_DECLARE_LIBRARY_COMPONENTS
