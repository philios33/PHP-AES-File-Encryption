PHP-AES-Crypt
=============

PHP implementation of the open source aes crypt file format

File specification is described here
https://www.aescrypt.com/aes_file_format.html

Finally, a FREE easy to use PHP library which implements the open source AES encrypted file format.  There are many pitfalls to implementing file encryption solutions based on existing libraries such as mcrypt.  Many people incorrectly think you can just encrypt data and shove it in a file.  Alas, it is not that simple.

The open source file format handles many issues such as null bytes trimming, file integrity and fast password checking.  It even comes with file extension identifiers which allows arbitrary data to be tagged within the AES file (unencrypted).

This library makes it easier for users who are only interested in encrypting and decrypting .aes files with passwords.  Other technicalities such as file structure, versions & encryption keys are transparent to the user.

##Requirements
1. PHP 5
2. PHP Mcrypt extension 
I do not plan to port rijndael-128 to native php in the future.  Feel free if you're up to the challenge!

##Usage
1. Include the AESCryptLib.php class
2. Call the exposed public static functions

##Compatibility
This library writes version 2 of the aes file structure standard, and is also backwards compatible so it can read the older two versions.

##Download
Obviously I haven't written it yet
