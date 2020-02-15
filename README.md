# SSL Check PHP


This lib aims to obtain information on the validity of the SSL certificate of WebSites.
--------------------------------------------------------------


#### Example: verify https certification is valid

``` php
<?php

use JrBarros\CheckSSL;

require 'vendor/autoload.php';

$checkSLL = new CheckSSL();

$symfony = 'https://symfony.com';
$laravel = 'https://laravel.com';

$laminas = 'https://getlaminas.org';
$zend    = 'https://www.zend.com/';

$array = [$laminas, $zend];

$example0 = $checkSLL->add($symfony)->check();

$example1 = $checkSLL->add($symfony, $laravel)->check();

$example2 = $checkSLL->add($array)->check();

$example3 = $checkSLL->add($symfony, $laravel, $array)->check();

print_r($example0);
print_r($example1);
print_r($example2);
print_r($example3);
```
##### output $example0:

```php
[
    "is_valid"    => true,
    "created_at" => "2019-04-04T00:00:00Z",
    "valid_until" => "2020-04-04T12:00:00Z"
];
```
##### output $example1:
```php
[
    "symfony.com" => [
               "is_valid"    => true,
               "created_at" => "2019-04-04T00:00:00Z",
               "valid_until" => "2020-04-04T12:00:00Z"
           ],
  
    "laravel.com" => [
               "is_valid"    => true,
               "created_at" => "2019-11-19T00:00:00Z",
               "valid_until" => "2020-10-09T12:00:00Z"
           ]
];
```
##### output $example2:
```php
[
     "symfony.com" => [
             "is_valid"    => true,
             "created_at" => "2019-04-04T00:00:00Z",
             "valid_until" => "2020-04-04T12:00:00Z"
         ],

     "laravel.com" => [
             "is_valid"    => true,
             "created_at" => "2019-11-19T00:00:00Z",
             "valid_until" => "2020-10-09T12:00:00Z"
         ],
 
     "getlaminas.org" => [
             "is_valid"    => true,
             "created_at" => "2019-08-14T00:00:00Z",
             "valid_until" => "2020-08-13T12:00:00Z"
         ],
 
     "www.zend.com" => [
             "is_valid"    => true,
             "created_at" => "2019-06-12T00:00:00Z",
             "valid_until" => "2020-06-16T12:00:00Z"
         ]
];
```
##### output $example3:
```php
[
    "symfony.com" => [
             "is_valid"    => true,
             "created_at" => "2019-04-04T00:00:00Z",
             "valid_until" => "2020-04-04T12:00:00Z"
           ],
   
    "laravel.com" => [
            "is_valid"    => true,
            "created_at" => "2019-11-19T00:00:00Z",
            "valid_until" => "2020-10-09T12:00:00Z"
       ],
   
    "getlaminas.org" => [
           "is_valid"    => true,
           "created_at" => "2019-08-14T00:00:00Z",
           "valid_until" => "2020-08-13T12:00:00Z"
       ],
    
    "www.zend.com" => [
           "is_valid"    => true,
           "created_at" => "2019-06-12T00:00:00Z",
           "valid_until" => "2020-06-16T12:00:00Z"
       ]
];
```


#### Custom output format

``` php
<?php

use JrBarros\CheckSSL;

require 'vendor/autoload.php';

$data = [ 'https://symfony.com', 'https://getlaminas.org'];

$dateFormat = 'U';
$formatString = 'd-m-Y H:i:s';
$timeZone = 'America/Sao_Paulo';

$checkSLL = new CheckSSL($data, $dateFormat, $formatString, $timeZone);

print_r($checkSLL->check());
```

##### output custom format:
```php
[
    "symfony.com" => [
            "is_valid"    => true,
            "created_at" => "04-04-2019 00:00:00",
            "valid_until" => "04-04-2020 12:00:00"
        ],

    "getlaminas.org" => [
            "is_valid"    => true,
            "created_at" => "14-08-2019 00:00:00",
            "valid_until" => "13-08-2020 12:00:00"
        ]
];
```