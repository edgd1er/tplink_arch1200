# tplink_arch1200

Update duckdns records using ip given in admin interface of the tplink archer C1200.

tool to update duckdns.org dns record get information from tplink's router-modem

Two classes are implemented:
- duckdns: to interact with [duckdns API](https://www.duckdns.org/spec.jsp)
- archer1200: to get information from tplink archer 1200

/!\ password encryption is not implemented. archer2000 initialisation need it.

### Get encrypted password
* open router's login url: http://tplinkwifi.net/webpages/login.html
  
Login using the local admin password:

* open developper console (F12 for Firefox and chrome), execute here under commands. 

 cut and paste in the console:
```
$('form#cloud-form-login').hide()
$('form#form-login').show()
$('form#form-login').find('input[type="password"].text-text.password-text.password-hidden').val('your_password').focusout()
$("input#login-password").password("doEncrypt");
$('input#login-password').val()
```
Login using the cloud login password
```
$('input#cloud-login-username').val('yourUser')
$('form#cloud-form-login').find('input[type="password"].text-text.password-text.password-hidden.l').val('your_password')
$('form#cloud-form-login').find('input[type="password"].text-text.password-text.password-hidden.l').focusout()
$('input#cloud-first-login-password').removeClass("hidden")
$('input#login-password').val()
$('form#cloud-form-login').submit()
```

### virtual environment
suggested for devs:
* Install virtual environment: `python3 -m venv env-name`
* Running virtual environment: `source env-name/bin/activate`
* Deactivate the virtual environment: `deactivate`
* Install packages: `pip install -r requirements.txt`

### Run tests
* update updateDuckDns.ini with modem's credentials
* run tests: 
  * fonctionnal tests:
    * ./archer1200_test.py -f
    * ./updateDuckDns_test.py
  * unittests: 
    * ./archer1200_test.py -u

* coverage
  * pré-requis: pip3 install coverage
  * run: `coverage run archer1200_test.py -u`
  * report html: `coverage html`
  * report json: `coverage json`

### Modem login status

using url with form=check_factory_default
if is_default is 
* true => first login form ( form to set a password, not handled by this module )
* false 
  * cloud_ever_login == true => cloud login form (email + pwd)
  * cloud_ever_login == false => login form ( password only)