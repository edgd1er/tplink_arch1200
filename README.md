# tplink_arch1200

Update duckdns records using ip given in admin interface of the tplink archer C1200.

tool to update duckdns.org dns record get information from tplink's router-modem

Two classes are implemented:
- duckdns: to interact with [duckdns API](https://www.duckdns.org/spec.jsp)
- archer1200: to get information from tplink archer 1200

/!\ password encryption is not implemented. archer2000 initialisation need it.

###Get encrypted password
* open router's login url: http://tplinkwifi.net/webpages/login.html
  
Login using the local admin password:

* open developper console (F12 for Firefox and chrome), execute here under commands. 

 cut and paste in de console:
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