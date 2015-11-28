# zf2-multi-factor-authentication
This is a sample implementation of Google multi-factor authentication (MFA) for Zend Framework 2.

Implementation by Team CODIFIC • We code terrific.

MIT License http://opensource.org/licenses/MIT.

# Specification
This plugin implements the Google multi-factor authentication using a one-time token that is valid for maximum 8 minutes (configurable). Even if a username/password combination is leaked, brute forced or dictionary attacked the MFA will make sure the attacker will still not be able to login as Google MGA 

# Installation
Add the plugin to your composer.json by using the following line:
```json
"codific/zf2-multi-factor-authentication": "dev-master"
```
and run 
```bash
php composer.phar update
```

# Usage
TODO