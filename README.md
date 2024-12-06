# password_breach_check
A MySQL component that checks if a given password has appeared in data breaches using https://haveibeenpwned.com/

ATTENTION: THIS COMPONENT IS CREATED FOR DEMONSTRATION. IT IS NOT PRODUCTION READY CODE. USE AT YOUR OWN RISK.

How does it work:
Component uses https://api.pwnedpasswords.com/range/ to look up partial SHA1
hash(first 5 characters) of a password. This would return list of SHA1 suffixes
and corresponding number indicating their presence in data breaches. It then
compares the result with SHA1 suffix hash to check whether given password ever
appeared in any of the password breach.

See https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange
to undestand why such a lookup protects searched password.

The component implements
a> password validation service
    Once installed, setting a compromised password through
    CREATE|ALTER USER ... IDENTIFIED ... BY ... or through  SET PASSWORD will
    result into failure.
    password_strength_check() function will return either 0 or 100.
    0: The given password appeared in one or more times in data breaches.
    100: The given password did not appear in any data breach.

b> password_breach_check function
    It accepts a password as argument and returns an integer value
    representing the number of times given password appeared in
    data breaches.

How to compile:
1. Obtain MySQL 9.x source code:
   git clone https://github.com/mysql/mysql-server mysql-server
2. Obtain libservicebroadcast - https://github.com/harinvadodaria/libservicebroadcast
3. Create directory <src>/components/password_breach_check and put source code
   for this component in the directory.
4. Compile the server code.

How to install:
1. Once binaries are compiled, create data directory and start server and
   point --plugin-dir to the directory that contains component shared library.
2. Make sure that MySQL server can reach to
   https://api.pwnedpasswords.com/range/
3. Execute INSTALL COMPONENT "file://component_password_breach_check";

How to use:
1. Create a user, change password of a user or call VALIDATE_PASSWORD_STRENGTH()
   function.
2. Call password_breach_check() function.
