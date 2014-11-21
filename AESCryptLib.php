<?php

/**
 * Please see https://www.aescrypt.com/aes_file_format.html
 * for the file format used.  It should theoretically make .aes files which are
 * compatible with any AESCrypt software.
 * 
 * Sample Usage:
 * 1. Encrypt a file
 * $file_name = AESCryptLib::encryptFile('my_secret_document.docx', 'password123', 'my_encrypted_document.aes', array(
 *	array(
 *		'ident':'CREATED-BY',
 *		'data':'Philip Nicholls'
 *	)
 * ));
 * 
 * 2. Read extension blocks (AKA meta data) from a file
 * $extension_blocks = AESCryptLib::readExtensionBlocks('my_encrypted_document.aes');
 * foreach($extension_blocks as $ext_block) {
 *	$ext_ident = $ext_block['ident'];
 *	$ext_data = $ext_block['data'];
 *  print $ext_ident . "=" . $ext_data;
 * }
 * 
 * 3. Decrypt a file
 * $file_name = AESCryptLib::decryptFile('my_encrypted_document.aes', 'password123');
 */
class AESCryptLib
{
	public static function encryptFile($source_file, $passphrase, $dest_file = NULL, $use_dynamic_filenaming = true, $ext_data = NULL)
	{
		//Check we can read the source file
		self::checkSourceExistsAndReadable($source_file);
		
		//Open destination file for writing
		$dest_fh = self::openDestinationFile($source_file, $dest_file, $use_dynamic_filenaming, true);
		
		//Check any ext_data is formatted correctly
		self::checkExtensionData($ext_data);
		
		//Check that the password is a string (it cannot be NULL)
		self::checkPassphraseIsValid($passphrase);
		
		//Actually do the encryption here
		self::doEncryptFile($source_file, $passphrase, $dest_fh, $ext_data);
		
		//Return encrypted file location
		$meta_data = stream_get_meta_data($dest_fh);
		fclose($dest_fh);
		$filename = realpath($meta_data["uri"]);
		return $filename;
	}
	
	public static function readExtensionBlocks($source_file)
	{
		//Check we can read the source file
		self::checkSourceExistsAndReadable($source_file);
		
		//Attempt to parse and return the extension blocks only
	}
	
	public static function decryptFile($source_file, $passphrase, $dest_file = NULL, $use_dynamic_filenaming = true)
	{
		//Check we can read the source file
		self::checkSourceExistsAndReadable($source_file);
		
		//Open destination file for writing
		$dest_fh = self::openDestinationFile($source_file, $dest_file, $use_dynamic_filenaming, false);
		
		//Check whether the passphrase is correct before decrypting the keys and validating with HMAC1
		//If it is, attempt to decrypt the file using these keys and write to destination file
		self::doDecryptFile($source_file, $passphrase, $dest_fh);
		
		//Return encrypted file location
		$meta_data = stream_get_meta_data($dest_fh);
		fclose($dest_fh);
		$filename = realpath($meta_data["uri"]);
		return $filename;
	}
	
	private static function checkSourceExistsAndReadable($source_file)
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
	
	private static function openDestinationFile($source_file, $dest_file, $use_dynamic_filenaming, $encrypting = true) {
		
		//Please use checkSourceExistsAndReadable on the source before running this function as we assume it exists here
		$source_info = pathinfo($source_file);
		
		if (is_null($dest_file)) {
			if (!$encrypting) {
				//We are decrypting, attempt to lookup original file name from encrypted source file
				$orig_file_name = self::lookupOriginalFileNameFromSourceMetaData($source_file);
				if (!is_null($orig_file_name)) {
					//This will only be the filename and extension, not the path
					$dest_file = $source_info['dirname'] . DIRECTORY_SEPARATOR . $orig_file_name;
				} else {
					//Not found, we cannot continue because we have no idea what the file extension should be
					//User should specify dest file path explicitly
					throw new AESCryptUnknownOriginalFileExtensionException($source_file);
				}
			} else {
				//We are encrypting, use .aes as destination file extension
				$dest_file = $source_info['dirname'] . DIRECTORY_SEPARATOR . $source_info['filename'] . ".aes";
			}
		}
		
		if ($use_dynamic_filenaming) {
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
		$dest_fh = fopen($dest_file, "w");
				
		return $dest_fh;
	}
	
	private static function checkExtensionData($ext_data)
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
	
	private static function checkPassphraseIsValid($passphrase)
	{
		if (is_null($passphrase)) {
			throw new AESCryptInvalidPassphraseException("NULL passphrase not allowed");
		}
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
class AESCryptUnknownOriginalFileExtensionException extends Exception {} //E.g. when we try to decrypt a 3rd party written file which doesnt contain the meta data extension which tells us the ORIGINAL-FILE-NAME
