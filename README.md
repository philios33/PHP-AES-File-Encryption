PHP-AES-Crypt
=============

PHP implementation of the open source aes crypt file format

File specification is described here
https://www.aescrypt.com/aes_file_format.html

Finally, a FREE easy to use PHP library which implements the open source AES encrypted file format.  There are many pitfalls to implementing file encryption solutions based on existing libraries, and many people think you can just encrypt data and shove it in a file.  WRONG.

The open source file format handles many issues such as null data trimming, file integrity and fast password checking.  It even comes with file extension identifiers which allows arbitrary data to be tagged within the AES file (unencrypted).

This library should hopefully make it easier for users to encrypt and decrypt files using AES.

##Requirements
1. PHP 5 (duh)
2. PHP Mcrypt extension (I do not plan to implement rijndael-128 from scratch in the future.  Feel free if you're up to the challenge!)

##Usage
1. Include the aes_file_encryption.php class
2. Construct a singleton
3. Call the exposed public methods

##Download
Obviously I haven't written it yet
