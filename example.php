<?php
include_once 'crypt.php';
$password  = 'the password';                   # can be genegated by crypt::rand()
$salt      = 'the password salt';              # same
$key       = crypt::pbkdf2($password, $salt);  # secret key
$message   = 'secret message for humanity';    # message to hide
$encrypted = crypt::encrypt($message, $key);   # encrypt message, raw binary ciphertext returned
$decrypted = crypt::decrypt($encrypted, $key); # decrypt the ciphertext, original variable returned
echo $decrypted;                               # 'secret message for humanity'