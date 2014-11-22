PHP AES File Encryption
=============

PHP implementation of the open source aes crypt file format

File specification is described here
https://www.aescrypt.com/aes_file_format.html

##Introduction
There are many PHP AES implementations available online which offer AES encryption for data streams.  It is possible to utilise these low level libraries to encrypt files, but unless you do everything correctly you can end up with an insecure (or broken) library.  This library works at a higher level, depending on a low level AES encryption engine (which you can configure), and implementing the open source aes crypt file format.

##Problems
There are many problems to solve when implementing file encryption using a lower level library (such as mycrpy).  Many people incorrectly think you can just encrypt data and shove it in a file.  Alas, it is not that simple.

The open source file format handles many issues such as null bytes trimming, file integrity and fast password checking.  It even comes with file extension identifiers which allows arbitrary data to be tagged within the AES file (unencrypted).

This library makes it easier for users who are only interested in encrypting and decrypting .aes files with passwords.  Other technicalities such as file structure, versions & encryption keys are transparent to the user.

##Requirements
1. PHP 5
2. An AES Encryption Implementation (such as mcrypt or some other native php library)
If you don't have mcrypt available, you can easily implement the AESEncrpyion interface using whatever library you want.

##Usage
1. Include the AESCryptLib.php class
2. Call the exposed public static functions

##Compatibility
This library writes version 2 of the aes file structure standard, and is also backwards compatible so it can read the older two versions.

##Download
Obviously I haven't written it yet.  Maybe it'll be ready after Christmas.
