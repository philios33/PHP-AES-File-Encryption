<?php

require_once '../AESCryptFileLib.php';
require_once '../aes256/MCryptAES256Implementation.php';

abstract class CorruptionTest extends UnitTestCase {
	
	private $passphrase = "phil123456";
	private $badpassphrase = "notcorrect";
	
	function __construct($file_to_decode) {
		$this->file_enc = $file_to_decode;
		$this->file_dec = $file_to_decode . ".dec";
	}
	
	function setUp() {
		@unlink($this->file_dec);
	}
	
	function tearDown() {
		@unlink($this->file_dec);
	}
	
	function testVariables() {
		$this->assertNotEqual($this->passphrase, $this->badpassphrase);
		$this->assertTrue(file_exists($this->file_enc));
		$this->assertTrue(filesize($this->file_enc) > 0);
		$this->assertFalse(file_exists($this->file_dec));
	}
	
	function testCorrectPassword() {
		//Attempt to decrypt corrupted file with good passphrase
		$decrypted_file = NULL;
		try {
			$mcrypt = new MCryptAES256Implementation();
			$lib = new AESCryptFileLib($mcrypt);
			$decrypted_file = $lib->decryptFile($this->file_enc, $this->passphrase, $this->file_dec);
		} catch (AESCryptCorruptedFileException $e) {
			//OK
			$this->pass("Yes, file correctly detected as corrupted");
		} catch (Exception $e) {
			$this->fail("Not an AESCryptCorruptedFileException: " . get_class($e));
		}
		$this->assertNull($decrypted_file);	
    }
}

class DenchCorruptedTest extends CorruptionTest {
	public function __construct() {
		parent::__construct("files/altered.jpg.aes");
	}
}