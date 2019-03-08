# ShibbolethGuardBundle

## Introduction
Shibboleth is a Single-Sign-On system made for webservices. This bundle provide
a Guard authenticator to use this authentication method in Symfony 3.4.
- Symfony Version 2.8 you should see
https://github.com/roenschg/ShibbolethGuardBundle.
- Symfony previous Version 2.8 you should see
https://github.com/roenschg/ShibbolethBundle.


## Installation
This library can be install using composer.

```
composer config repositories.shibboleth vcs https://github.com/Kury25/ShibbolethGuardBundle
composer require gauss-allianz/shibboleth-guard-bundle:dev-symfony34
```


## How to test locally
Setup a local IdP/SP infrastructure is a very time consuming job. I will describe
an easy way to test your functionality on your local system without an software
required. But you may consider using the following library:
https://packagist.org/packages/mrclay/shibalike

First of all you need to know which information are sent in which way by the
Apache2 webserver to the PHP. This might differ by several configurations.
You can test which information you get by just putting a script to your webserver
like this. (The script must be shibobleth secured area!)

```
<?php
    print_r(\$\_SERVER);
```

You can call the script and might need to configure the attribute naming. (see
section "configuration"). If the variables use the prefix "HTTP_" then skip the
prefix in the configuration and use the option "use_header".

Afterwards you can simulate the enviroment by copy the output from the php
script above and putting it into the app/app_dev.php like in the following
example.

```
    $_SERVER['HTTP_mail'] = "name@domain.tld";
    $_SERVER['HTTP_Shib-Application-Id'] = 'TEST';
    $_SERVER['HTTP_sn'] = "Lastname";
    $_SERVER['HTTP_givenName'] = "Firstname";
```

## Configuration
In your config.yml you have to set at least the following parameters:

```
shibboleth_guard:
    handler_path: /Shibboleth.sso
    session_initiator_path: /Login
    username_attribute: %shibboleth_username_attribute%
    use_headers: true
    logout_target: /
    attribute_definitions:
        mail: { header: mail, server: mail }
        persistent_id: { header: persistent_id, server: persistent_id }
```

The `handler_path` is the relative path to the Shibboleth handler url
The `session_initator_path` is used to set the login location
The `username_attribute` Defines the meta attribute that will be used to
identify the user (for the user provider)
The `use_headers` optiones specifies in which type the shibboleth daemon
set the attributes for the php script
The `logout_target` location for logout
With the `attribute_definitions` you can overwrite several options if they
are attribute names are different in your shibboleth configuration than default.
