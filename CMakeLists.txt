# Copyright (c) 2022, All Rights Reserved
#
# The software is provided "AS IS", without warranty of any kind, express or
# implied, including but not limited to the warranties of merchantability,
# fitness for a particular purpose and noninfringement. In no event shall the
# authors or copyright holders be liable for any claim, damages or other
# liability, whether in an action of contract, tort or otherwise, arising from,
# out of or in connection with the software or the use or other dealings in
# the software.

DISABLE_MISSING_PROFILE_WARNING()

IF (WITH_CURL STREQUAL "none")
    MESSAGE(FATAL_ERROR "This component needs curl.")
ENDIF()

MY_INCLUDE_SYSTEM_DIRECTORIES(CURL)
INCLUDE_DIRECTORIES(
  ${CMAKE_CURRENT_SOURCE_DIR}
  )

SET(PASSWORD_BREACH_CHECK_LIBRARIES
  ${CURL_LIBRARY} ${SSL_LIBRARIES}
)

MYSQL_ADD_COMPONENT(password_breach_check
    password_breach_check.cc
    password_validation_impl.cc
    component.cc
    MODULE_ONLY
    TEST_ONLY
    LINK_LIBRARIES ${PASSWORD_BREACH_CHECK_LIBRARIES}
    )
