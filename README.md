# tplink_arch1200

Update duckdns records using ip given in admin interface of the tplink archer C1200.

tool to update duckdns.org dns record get information from tplink's router-modem

Two classes are implemented:
- duckdns: to interact with [duckdns API](https://www.duckdns.org/spec.jsp)
- archer1200: to get information from tplink archer 1200

/!\ password encryption is not implemented. archer2000 initialisation need it.

###Get encrypted password
* open router' login url: http://tplinkwifi.net/webpages/login.html
* open developper console (F12 for Firefox and chrome), execute here under commands. 

  hide cloud login: `$('#cloud-form-login').hide()`
  
  show local login: `$('#form-login').show()`
  
  set password: `$('form#form-login').find('input[type="password"].text-text.password-text.password-hidden').val('__your_password__')`
  
  show 'real' input tag: `$('input#login-password').removeClass("hidden")`

  values update: `$('form#form-login').find('.password-container').focusout()`
  
  password encryption: `$("input#login-password").password("doEncrypt")`

  reveal encrypted value: `$("input#login-password").attr('type','text')`

  copy

cut and paste in de console:
```
$('#cloud-form-login').hide()
$('#form-login').show()
$('form#form-login').find('input[type="password"].text-text.password-text.password-hidden').val('__your_password__')
$('input#login-password').removeClass("hidden")
$('form#form-login').find('.password-container').focusout()
$("input#login-password").password("doEncrypt");
$("input#login-password").attr('type','text')
```