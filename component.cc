/* Copyright (c) 2022, All Rights Reserved

The software is provided "AS IS", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability,
fitness for a particular purpose and noninfringement. In no event shall the
authors or copyright holders be liable for any claim, damages or other
liability, whether in an action of contract, tort or otherwise, arising from,
out of or in connection with the software or the use or other dealings in
the software. */

#include "password_breach_check.h"

/* Service placeholders */
REQUIRES_SERVICE_PLACEHOLDER(log_builtins);
REQUIRES_SERVICE_PLACEHOLDER(log_builtins_string);
REQUIRES_SERVICE_PLACEHOLDER(mysql_string_converter);
REQUIRES_SERVICE_PLACEHOLDER(udf_registration);

SERVICE_TYPE(log_builtins) * log_bi;
SERVICE_TYPE(log_builtins_string) * log_bs;

namespace password_breach_check {
/**
  Initialization entry method for the component

  @return Status of initialization
    @retval true  failure
    @retval false success
*/
static mysql_service_status_t password_breach_check_init() {
  log_bi = mysql_service_log_builtins;
  log_bs = mysql_service_log_builtins_string;

  if (Password_validation::register_functions()) return true;
  Breach_checker::init_environment();
  return false;
}

/**
  De-initialization method for the component

  @return Status of deinitialization
    @retval true failure
    @retval false success
*/
static mysql_service_status_t password_breach_check_deinit() {
  if (Password_validation::unregister_functions()) return true;
  Breach_checker::deinit_environment();
  return false;
}

}  // namespace password_breach_check

/****************************************************************************/

/* Component provides: validate_password component service implementation */
BEGIN_SERVICE_IMPLEMENTATION(password_breach_check, validate_password)
password_breach_check::Password_validation::validate,
    password_breach_check::Password_validation::get_strength
    END_SERVICE_IMPLEMENTATION();

/* component provides: the password_breach_check service */
BEGIN_COMPONENT_PROVIDES(password_breach_check)
PROVIDES_SERVICE(password_breach_check, validate_password),
    END_COMPONENT_PROVIDES();

/* Dependencies */
BEGIN_COMPONENT_REQUIRES(password_breach_check)
REQUIRES_SERVICE(registry), REQUIRES_SERVICE(log_builtins),
    REQUIRES_SERVICE(log_builtins_string),
    REQUIRES_SERVICE(mysql_string_converter),
    REQUIRES_SERVICE(udf_registration), END_COMPONENT_REQUIRES();

/* component description */
BEGIN_COMPONENT_METADATA(password_breach_check)
METADATA("mysql.author", "Harin Vadodaria"),
    METADATA("mysql.license", "All Rights Reserved"),
    METADATA("password_breach_check_service", "1"), END_COMPONENT_METADATA();

/* component declaration */
DECLARE_COMPONENT(password_breach_check, "mysql:password_breach_check")
password_breach_check::password_breach_check_init,
    password_breach_check::password_breach_check_deinit END_DECLARE_COMPONENT();

/* components contained in this library */
DECLARE_LIBRARY_COMPONENTS &COMPONENT_REF(password_breach_check)
    END_DECLARE_LIBRARY_COMPONENTS
