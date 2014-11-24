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
class AESCryptFileLib
{
	const ENCRYPTED_FILE_EXTENSION = "aes";
	
	//http://www.leaseweblabs.com/2014/02/aes-php-mcrypt-key-padding/
	//Only "Rijndael-128" in "Cipher-block chaining" (CBC) mode is defined as the Advanced Encryption Standard (AES).
	//The file format specifies IV length of 128 bits (the block length) and key length of 256 bits
	//These are assumed to be implemented properly in all AES256 interfaces
	private $aes_impl;
	
	private $use_dynamic_filenaming;
	
	private $debugging = false;
	
	public function __construct(AES256Implementation $aes_impl, $use_dynamic_filenaming = true) {
		$this->aes_impl = $aes_impl;
		$this->use_dynamic_filenaming = $use_dynamic_filenaming;
		
		try {
			$this->aes_impl->checkDependencies();
		} catch (Exception $e) {
			throw new AESCryptMissingDependencyException($e->getMessage());
		}
	}
	
	public function enableDebugging()
	{
		$this->debugging = true;
	}
	
	public function encryptFile($source_file, $passphrase, $dest_file = NULL, $ext_data = NULL)
	{
		//Check we can read the source file
		$this->checkSourceExistsAndReadable($source_file);
		
		//Check any ext_data is formatted correctly
		$this->checkExtensionData($ext_data);
		
		//Check that the password is a string (it cannot be NULL)
		$this->checkPassphraseIsValid($passphrase);
		
		//Actually do the encryption here
		$dest_fh = $this->doEncryptFile($source_file, $passphrase, $dest_file, $ext_data);
		
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
		//Open the file
		$source_fh = fopen($source_file, "rb");
		if ($source_fh === false) {
			throw new AESCryptFileAccessException("Cannot open file for reading: " . $source_file);
		}
		
		$this->readChunk($source_fh, 3, "file header", NULL, "AES");
		$version_chunk = $this->readChunk($source_fh, 1, "version byte", "C");
		$extension_blocks = array();
		if (bin2hex($version_chunk) === 0) {
			//This file uses version 0 of the standard
			//Extension blocks dont exist in this versions spec
		} else if (bin2hex($version_chunk) === 1) {
			//This file uses version 1 of the standard
			//Extension blocks dont exist in this versions spec
		} else if (bin2hex($version_chunk) === 2) {
			//This file uses version 2 of the standard (The latest standard at the time of writing)
			$this->readChunk($source_fh, 1, "reserved byte", "C", 0);
			$eb_index = 0;
			while (true) {
				//Read ext length
				$ext_length = $this->readChunk($source_fh, 2, "extension length", "n");
				if ($ext_length == 0) {
					break;
				} else {
					$ext_content = $this->readChunk($source_fh, $ext_length, "extension content");
					//Find the first NULL splitter character
					$null_index = strpos($ext_content, "\x00");
					if ($null_index === false) {
						throw new AESCryptCorruptedFileException("Extension block data at index {$eb_index} has no null splitter byte: " . $source_file);
					}
					$extension_blocks[$eb_index] = array(
						"identifier" => substr($ext_content, 0, $null_index-1),
						"contents" => substr($ext_content, $null_index)
					);
					$eb_index++;
				}
			}
		}
		return $extension_blocks;
	}
	
	public function decryptFile($source_file, $passphrase, $dest_file = NULL)
	{
		//Check we can read the source file
		$this->checkSourceExistsAndReadable($source_file);
		
		//Check whether the passphrase is correct before decrypting the keys and validating with HMAC1
		//If it is, attempt to decrypt the file using these keys and write to destination file
		$dest_fh = $this->doDecryptFile($source_file, $passphrase, $dest_file);
		
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
		
		if ($dest_file === NULL) {
			if (!$encrypting) {
				//We are decrypting without a known destination file
				//We should check for a double extension in the file name e.g. (filename.docx.aes)
				//Actually, we just check it ends with .aes and strip off the rest
				if (preg_match("/^(.+)\." . self::ENCRYPTED_FILE_EXTENSION . "$/i", $source_info['basename'], $matches)) {
					//Yes, source is an .aes file
					//We remove the .aes part and use a destination file in the same source directory
					$dest_file = $source_info['dirname'] . DIRECTORY_SEPARATOR . $matches[1];
				} else {
					throw new AESCryptCannotInferDestinationException($source_file);
				}
				
			} else {
				//We are encrypting, use .aes as destination file extension
				$dest_file = $source_file . "." . self::ENCRYPTED_FILE_EXTENSION;
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
		$dest_fh = fopen($dest_file, "xb");
		if ($dest_fh === false) {
			throw new AESCryptFileAccessException("Cannot create for writing:" . $dest_file);
		}
				
		return $dest_fh;
	}
	
	private function readChunk($source_fh, $num_bytes, $chunk_name, $unpack_format = NULL, $expected_value = NULL)
	{
		$read_data = fread($source_fh, $num_bytes);
		if ($read_data === false) {
			throw new AESCryptFileAccessException("Could not read chunk " . $chunk_name . " of " . $num_bytes . " bytes");
		}
		
		if (strlen($read_data) != $num_bytes) {
			throw new AESCryptCorruptedFileException("Could not read chunk " . $chunk_name . " of " . $num_bytes . " bytes, only found " . strlen($read_data) . " bytes");
		}
		
		if ($unpack_format !== NULL) {
			$read_data = unpack($unpack_format, $read_data);
			if (is_array($read_data)) {
				$read_data = $read_data[1];
			}
		}
		
		
		if ($expected_value !== NULL) {
			if ($read_data !== $expected_value) {
				throw new AESCryptCorruptedFileException("The chunk " . $chunk_name . " was expected to be " . bin2hex($expected_value) . " but found " . bin2hex($read_data));
			}
		}
		return $read_data;
	}
	
	private function checkExtensionData($ext_data)
	{
		if ($ext_data === NULL) {
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
		if ($passphrase === NULL) {
			throw new AESCryptInvalidPassphraseException("NULL passphrase not allowed");
		}
	}
	
	private function doEncryptFile($source_file, $passphrase, $dest_file, $ext_data)
	{
		$this->debug("ENCRYPTION", "Started");
		
		$header = "AES";
		$header .= pack("H*", "02"); //Version
		$header .= pack("H*", "00"); //Reserved
		
		//Generate the extension data
		$extdat_binary = $this->getBinaryExtensionData($ext_data);
		
		//Create a random IV using the aes implementation
		//IV is based on the block size which is 128 bits (16 bytes) for AES
		$iv_1 = $this->aes_impl->createIV();
		if (strlen($iv_1) != 16) {
			throw new AESCryptImplementationException("Returned an IV which is not 16 bytes long: " . bin2hex($iv_1));
		}
		$this->debug("IV1", bin2hex($iv_1));
		
		//Use this IV and password to generate the first encryption key
		//We dont need to use AES for this as its just lots of sha hashing
		$passphrase = iconv(mb_internal_encoding(), 'UTF-16LE', $passphrase);
		$this->debug("PASSPHRASE", $passphrase);
		$enc_key_1 = $this->createKeyUsingIVAndPassphrase($iv_1, $passphrase);
		if (strlen($enc_key_1) != 32) {
			throw new Exception("Returned a passphrase which is not 32 bytes long: " . bin2hex($enc_key_1));
		}
		$this->debug("KEY1", bin2hex($enc_key_1));
		
		//Create another set of keys to do the actual file encryption
		$iv_2 = $this->aes_impl->createIV();
		if (strlen($iv_2) != 16) {
			throw new AESCryptImplementationException("Returned an IV which is not 16 bytes long: " . bin2hex($iv_2));
		}
		$this->debug("IV2", bin2hex($iv_2));
		
		//The file format uses AES 256 (which is the key length)
		$enc_key_2 = $this->aes_impl->createRandomKey();
		if (strlen($enc_key_2) != 32) {
			throw new AESCryptImplementationException("Returned a random key which is not 32 bytes long: " . bin2hex($enc_key_2));
		}
		$this->debug("KEY2", bin2hex($enc_key_2));
		
		//Encrypt the second set of keys using the first keys
		$file_encryption_keys = $iv_2 . $enc_key_2;
		
		$encrypted_keys = $this->aes_impl->encryptData($file_encryption_keys, $iv_1, $enc_key_1);
		if (strlen($encrypted_keys) != 48) {
			throw new Exception("Assertion 1 failed");
		}
		$this->debug("ENCRYPTED KEYS", bin2hex($encrypted_keys));
		//$this->assertLength($encrypted_keys, 48);
		
		//Calculate HMAC1 using the first enc key
		$hmac_1 = hash_hmac("sha256", $encrypted_keys, $enc_key_1, true);
		if (strlen($hmac_1) != 32) {
			throw new Exception("Assertion 2 failed");
		}
		$this->debug("HMAC 1", bin2hex($hmac_1));
		//$this->assertLength($hmac_1, 32);
		
		//Now do file encryption
		$source_contents = file_get_contents($source_file);
		$encrypted_file_data = $this->aes_impl->encryptData($source_contents, $iv_2, $enc_key_2);
		
		$file_size_modulo = pack("C", strlen($source_contents)%16);
		
		$this->debug("FS MODULO", bin2hex($file_size_modulo));
		
		//HMAC the encrypted data too
		$this->debug("MD5 of ENC DATA", md5($encrypted_file_data));
		$hmac_2 = hash_hmac("sha256", $encrypted_file_data, $enc_key_2, true);
		
		$this->debug("HMAC2", bin2hex($hmac_2));
		
		//Actaully write it to the dest fh
		$enc_data = $header . $extdat_binary . $iv_1 . $encrypted_keys . $hmac_1 . $encrypted_file_data . $file_size_modulo . $hmac_2;
		
		//Open destination file for writing
		$dest_fh = $this->openDestinationFile($source_file, $dest_file, true);
		$written = fwrite($dest_fh, $enc_data);
		if ($written === false) {
			throw new AESCryptFileAccessException("Could not write encrypted data to file.  Tried to write " . strlen($enc_data) . " bytes");
		}
		$this->debug("ENCRYPTION", "Complete");
		
		return $dest_fh;
	}
	
	private function doDecryptFile($source_file, $passphrase, $dest_file)
	{
		$this->debug("DECRYPTION", "Started");
		
		//Check we can read the source file
		$this->checkSourceExistsAndReadable($source_file);
		
		//Attempt to parse and return the extension blocks only
		//Open the file
		$source_fh = fopen($source_file, "rb");
		if ($source_fh === false) {
			throw new AESCryptFileAccessException("Cannot open file for reading: " . $source_file);
		}
		
		$this->readChunk($source_fh, 3, "file header", NULL, "AES");
		$version_chunk = $this->readChunk($source_fh, 1, "version byte", "C");
		$extension_blocks = array();
		if ($version_chunk === 0) {
			//This file uses version 0 of the standard
			
		} else if ($version_chunk === 1) {
			//This file uses version 1 of the standard
			
		} else if ($version_chunk === 2) {
			//This file uses version 2 of the standard (The latest standard at the time of writing)
			$this->readChunk($source_fh, 1, "reserved byte", "C", 0);
			while (true) {
				//Read ext length
				$ext_length = $this->readChunk($source_fh, 2, "extension length", "n");
				if ($ext_length == 0) {
					break;
				} else {
					$this->readChunk($source_fh, $ext_length, "extension content");
				}
			}
			
			$iv_1 = $this->readChunk($source_fh, 16, "IV 1");
			$this->debug("IV1", bin2hex($iv_1));
			$enc_keys = $this->readChunk($source_fh, 48, "Encrypted Keys");
			$this->debug("ENCRYPTED KEYS", bin2hex($enc_keys));
			$hmac_1 = $this->readChunk($source_fh, 32, "HMAC 1");
			$this->debug("HMAC1", bin2hex($hmac_1));
			
			//Convert the passphrase to UTF-16LE
			$passphrase = iconv(mb_internal_encoding(), 'UTF-16LE', $passphrase);
			$this->debug("PASSPHRASE", bin2hex($passphrase));
			$enc_key_1 = $this->createKeyUsingIVAndPassphrase($iv_1, $passphrase);
			$this->debug("ENCKEY1FROMPASSWORD", bin2hex($enc_key_1));
			
			$this->validateHMAC($enc_key_1, $enc_keys, $hmac_1, "HMAC 1");
			
			
			$rest_of_data = "";
			while (!feof($source_fh)) {
				$rest_of_data .= fread($source_fh, 8192); //Read in 8K chunks
			}
			$encrypted_data = substr($rest_of_data, 0, -33);
			$file_size_modulos = unpack("C", substr($rest_of_data, -33, 1));
			$file_size_modulos = $file_size_modulos[1];
			if ($file_size_modulos === false) {
				throw new Exception("Could not decode file size modulos");
			}
			if ($file_size_modulos < 0 || $file_size_modulos >= 16) {
				throw new Exception("Invalid file size modulos: " . $file_size_modulos);
			}
			
			$hmac_2 = substr($rest_of_data, -32);
			$this->debug("HMAC2", bin2hex($hmac_2));
			
			$decrypted_keys = $this->aes_impl->decryptData($enc_keys, $iv_1, $enc_key_1);
			$this->debug("DECRYPTED_KEYS", bin2hex($decrypted_keys));
			
			$iv_2 = substr($decrypted_keys, 0, 16);
			$enc_key_2 = substr($decrypted_keys, 16);
			
			$this->debug("MD5 of ENC DATA", md5($encrypted_data));
			
			$this->validateHMAC($enc_key_2, $encrypted_data, $hmac_2, "HMAC 2");
			//All keys were correct, we can be sure that the decrypted data will be correct
			$decrypted_data = $this->aes_impl->decryptData($encrypted_data, $iv_2, $enc_key_2);
			//Modulos tells us how many bytes to trim from the end
			if ($file_size_modulos > 0) {
				$decrypted_data = substr($decrypted_data, 0, ((16 - $file_size_modulos) * -1));
			}
			
			//Open destination file for writing
			$dest_fh = $this->openDestinationFile($source_file, $dest_file, false);
			
			$result = fwrite($dest_fh, $decrypted_data);
			if ($result === false) {
				throw new Exception("Could not write back file");
			}
			if ($result != strlen($decrypted_data)) {
				throw new Exception("Could not write back file");
			}
			$this->debug("DECRYPTION", "Completed");
			return $dest_fh;
		} else {
			throw new Exception("Invalid version chunk: " . $version_chunk);
		}
		throw new Exception("Not implemented");
	}
	
	//Converts the given extension data in to binary data
	private function getBinaryExtensionData($ext_data)
	{
		$this->checkExtensionData($ext_data);
		
		if ($ext_data === NULL) {
			$ext_data = array();
		}
		
		$output = "";
		foreach ($ext_data as $ext) {
			$ident = $ext['identifier'];
			$contents = $ext['contents'];
			$data = $ident . pack("C", 0) . $contents;
			$output .= pack("n", strlen($data));
			$output .= $data;
		}
		$output .= pack("C", 0);
		$output .= pack("C", 0);
		return $output;
	}
	
	//This is sha256 by standard and should always returns 256bits (32 bytes) of hash data
	//Looking at the java implementation, it seems we should iterate the hasing 8192 times
	private function createKeyUsingIVAndPassphrase($iv, $passphrase) 
	{
		$aes_key = $iv . hex2bin("00000000000000000000000000000000");
		$iterations = 8192;
		for($i=0; $i<$iterations; $i++)
		{
			$hash = hash_init("sha256");
			hash_update($hash, $aes_key);
			hash_update($hash, $passphrase);
			$aes_key = hash_final($hash, true);
		}
		return $aes_key;
	}
	
	private function validateHMAC($key, $data, $hash, $name)
	{
		$calculated = hash_hmac("sha256", $data, $key, true);
		$actual = $hash;
		if ($calculated != $actual) {
			$this->debug("CALCULATED", bin2hex($calculated));
			$this->debug("ACTUAL", bin2hex($actual));
			throw new AESCryptInvalidPassphraseException("{$name} failed to validate.  Incorrect password or file corrupted");
		}
	}
	
	private function debug($name, $msg) {
		if ($this->debugging) {
			echo "<br/>";
			echo $name . " - " . $msg;
			echo "<br/>";
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
class AESCryptInvalidPassphraseException extends Exception {} //E.g. when the password is wrong
class AESCryptCannotInferDestinationException extends Exception {} //E.g. when we try to decrypt a 3rd party written file which doesnt have the standard file name convention
class AESCryptImplementationException extends Exception {} //For generic exceptions by the aes implementation used
