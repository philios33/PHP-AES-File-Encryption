<?php
/**
 * Please see https://www.aescrypt.com/aes_file_format.html
 * for the file format used.  It should theoretically make .aes files which are
 * compatible with any AESCrypt software.
 * 
 * Sample Usage:
 * To come later on
 * 
 */
class AESCryptFile
{
	const ENCRYPTED_FILE_EXTENSION = "aes";
	
	//http://www.leaseweblabs.com/2014/02/aes-php-mcrypt-key-padding/
	//Only "Rijndael-128" in "Cipher-block chaining" (CBC) mode is defined as the Advanced Encryption Standard (AES).
	private $aes_impl;
	
	private $use_dynamic_filenaming;
	
	public function __construct(AESImplementation $aes_impl, $use_dynamic_filenaming = true) {
		$this->aes_impl = $aes_impl;
		$this->use_dynamic_filenaming = $use_dynamic_filenaming;
	}
	
	public function encryptFile($source_file, $passphrase, $dest_file = NULL, $ext_data = NULL)
	{
		//Check we can read the source file
		$this->checkSourceExistsAndReadable($source_file);
		
		//Open destination file for writing
		$dest_fh = $this->openDestinationFile($source_file, $dest_file, true);
		
		//Check any ext_data is formatted correctly
		$this->checkExtensionData($ext_data);
		
		//Check that the password is a string (it cannot be NULL)
		$this->checkPassphraseIsValid($passphrase);
		
		//Actually do the encryption here
		$this->doEncryptFile($source_file, $passphrase, $dest_fh, $ext_data);
		
		//Return encrypted file location
		$meta_data = stream_get_meta_data($dest_fh);
		fclose($dest_fh);
		$filename = realpath($meta_data["uri"]);
		return $filename;
	}
	
	public function readExtensionBlocks($source_file)
	{
		//Check we can read the source file
		$this->checkSourceExistsAndReadable($source_file);
		
		//Attempt to parse and return the extension blocks only
		//TODO
	}
	
	public function decryptFile($source_file, $passphrase, $dest_file = NULL)
	{
		//Check we can read the source file
		$this->checkSourceExistsAndReadable($source_file);
		
		//Open destination file for writing
		$dest_fh = $this->openDestinationFile($source_file, $dest_file, false);
		
		//Check whether the passphrase is correct before decrypting the keys and validating with HMAC1
		//If it is, attempt to decrypt the file using these keys and write to destination file
		$this->doDecryptFile($source_file, $passphrase, $dest_fh);
		
		//Return encrypted file location
		$meta_data = stream_get_meta_data($dest_fh);
		fclose($dest_fh);
		$filename = realpath($meta_data["uri"]);
		return $filename;
	}
	
	private function checkSourceExistsAndReadable($source_file)
	{
		//Source file must exist
		if (!file_exists($source_file)) {
			throw new AESCryptFileMissingException($source_file);
		}
		
		//Source file must be readable
		if (!is_readable($source_file)) {
			throw new AESCryptFileAccessException("Cannot read: " . $source_file);
		}
	}
	
	private function openDestinationFile($source_file, $dest_file, $encrypting = true) {
		
		//Please use checkSourceExistsAndReadable on the source before running this function as we assume it exists here
		$source_info = pathinfo($source_file);
		
		if (is_null($dest_file)) {
			if (!$encrypting) {
				//We are decrypting without a known destination file
				//We should check for a double extension in the file name e.g. (filename.docx.aes)
				//Actually, we just check it ends with .aes and strip off the rest
				if (preg_match("/^(.+)\." . AESCryptFile::ENCRYPTED_FILE_EXTENSION . "$/i", $source_info['basename'], $matches)) {
					//Yes, source is an .aes file
					//We remove the .aes part and use a destination file in the same source directory
					$dest_file = $source_info['dirname'] . DIRECTORY_SEPARATOR . $matches[1];
				} else {
					throw new AESCryptCannotInferDestinationException($source_file);
				}
				
			} else {
				//We are encrypting, use .aes as destination file extension
				$dest_file = $source_info['dirname'] . DIRECTORY_SEPARATOR . $source_info['filename'] .  "." . AESCryptFile::ENCRYPTED_FILE_EXTENSION;
			}
		}
		
		if ($this->use_dynamic_filenaming) {
			//Try others until it doesnt exist
			$dest_info = pathinfo($dest_file);
			
			$duplicate_id = 1;
			while (file_exists($dest_file))	{
				//Check the destination file doesn't exist (We never overwrite)
				$dest_file = $dest_info['dirname'] . DIRECTORY_SEPARATOR . $dest_info['filename'] . "({$duplicate_id})." . $dest_info['extension'];
				$duplicate_id++;
			}
		} else {
			if (file_exists($dest_file)) {
				throw new AESCryptFileExistsException($dest_file);
			}
		}
		
		//Now that we found a non existing file, attempt to open it for writing
		$dest_fh = fopen($dest_file, "x");
		if ($dest_fh === false) {
			throw new AESCryptFileAccessException("Cannot create for writing:" . $dest_file);
		}
				
		return $dest_fh;
	}
	
	private function checkExtensionData($ext_data)
	{
		if (is_null($ext_data)) {
			return;
		}
		if (!is_array($ext_data)) {
			throw new AESCryptInvalidExtensionException("Must be NULL or an array (containing 'extension block' arrays)");
		}
		
		//Ignore associative arrays
		$ext_data = array_values($ext_data);
		
		foreach ($ext_data as $index => $eb) {
			//Each block must contain the array keys 'identifier' and 'contents'
			if (!array_key_exists("identifier", $eb)) {
				throw new AESCryptInvalidExtensionException("Extension block at index {$index} must contain the key 'identifier'");
			}
			if (!array_key_exists("contents", $eb)) {
				throw new AESCryptInvalidExtensionException("Extension block at index {$index} must contain the key 'contents'");
			}
		}
	}
	
	private function checkPassphraseIsValid($passphrase)
	{
		if (is_null($passphrase)) {
			throw new AESCryptInvalidPassphraseException("NULL passphrase not allowed");
		}
	}
	
	private function doEncryptFile($source_file, $passphrase, $dest_fh, $ext_data)
	{
		//Create a random IV using the aes implementation
		//IV is based on the block size which is 128 bits (16 bytes) for AES
		$iv_1 = $this->aes_impl->create_iv();
		if (strlen($iv_1) != 16) {
			throw new AESCryptImplementationException("Returned an IV which is not 16 bytes long: " . bin2hex($iv_1));
		}
		//Use this IV and password to generate the first encryption key
		//We dont need to use AES for this as its just lots of sha hashing
		$enc_key_1 = $this->createKeyUsingIVAndPassphrase($iv_1, $passphrase);
		if (strlen($enc_key_1) != 32) {
			throw new Exception("Returned a passphrase which is not 32 bytes long: " . bin2hex($enc_key_1));
		}

		//Create another set of keys to do the actual file encryption
		$iv_2 = $this->aes_impl->create_iv();
		if (strlen($iv_2) != 16) {
			throw new AESCryptImplementationException("Returned an IV which is not 16 bytes long: " . bin2hex($iv_2));
		}
		//The file format uses AES 256 (which is the key length)
		$enc_key_2 = $this->aes_impl->createRandomKey();
		if (strlen($enc_key_2) != 32) {
			throw new AESCryptImplementationException("Returned a random key which is not 32 bytes long: " . bin2hex($enc_key_2));
		}
		
		//Encrypt the second set of keys using the first keys
		$file_encryption_keys = $iv_2 . $enc_key_2;
		$encrypted_keys = $this->aes_impl->encryptData($file_encryption_keys, $iv_1, $enc_key_1);
		$this->assertLength($encrypted_keys, 48);
		
		//Calculate HMAC1 using the first enc key
		$hmac_1 = hash_hmac("sha256", $file_encryption_keys, $enc_key_1, true);
		$this->assertLength($hmac_1, 32);
		
		//Now do file encryption
		$source_contents = file_get_contents($source_file);
		$encrypted_file_data = $this->aes_impl->encryptData($source_contents, $iv_2, $enc_key_2);
		
		$file_size_modulo = str_len($source_contents)%16;
		
		//HMAC the encrypted data too
		$hmac_2 = hash_hmac("sha256", $encrypted_file_data, $enc_key_2, true);
		
		//TODO actaully write it to the dest fh
	}
	
	//This is sha256 by standard and should always returns 256bits (32 bytes) of hash data
	//Looking at the java implementation, it seems we should iterate the hasing 8192 times
	private function createKeyUsingIVAndPassphrase($iv, $passphrase) 
	{
		$aes_key = $iv;
		$iterations = 8192;
		for($i=0; $i<$iterations; $i++)
		{
			$aes_key = hash("sha256", $aes_key . $passphrase, true);
		}
		return $aes_key;
	}
	
	
}

class AESCryptMissingDependencyException extends Exception {} //E.g. missing mcrypt
class AESCryptAuthenticationException extends Exception {} //E.g. when password is wrong
class AESCryptCorruptedFileException extends Exception {} //E.g. when file looks corrupted or wont parse
class AESCryptFileMissingException extends Exception {} //E.g. cant read file to encrypt
class AESCryptFileAccessException extends Exception {} //E.g. read/write error on files
class AESCryptFileExistsException extends Exception {} //E.g. when a destination file exists (we never overwrite)
class AESCryptInvalidExtensionException extends Exception {} //E.g. when an extension array is invalid
class AESCryptInvalidPassphraseException extends Exception {} //E.g. when an extension array is invalid
class AESCryptCannotInferDestinationException extends Exception {} //E.g. when we try to decrypt a 3rd party written file which doesnt have the standard file name convention
class AESCryptImplementationException extends Exception {} //For generic exceptions by the aes implementation used
