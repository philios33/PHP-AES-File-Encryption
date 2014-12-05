<?php


require_once '../AESCryptFileLib.php';
require_once '../aes256/MCryptAES256Implementation.php';

abstract class AESCryptFileLibTest extends UnitTestCase {
	
	private $passphrase = "phil123456";
	private $badpassphrase = "notcorrect";
	
	function __construct($file_to_test) {
		$this->file_orig = $file_to_test;
		$this->file_enc = $file_to_test . ".aes";
		$this->file_dec = $file_to_test . ".dec";
	}
	
	function setUp() {
		@unlink($this->file_enc);
		@unlink($this->file_dec);
	}
	
	function tearDown() {
		@unlink($this->file_enc);
		@unlink($this->file_dec);
	}
	
	function testVariables() {
		$this->assertNotEqual($this->passphrase, $this->badpassphrase);
		$this->assertTrue(file_exists($this->file_orig));
		$this->assertTrue(filesize($this->file_orig) > 0);
		$this->assertFalse(file_exists($this->file_enc));
		$this->assertFalse(file_exists($this->file_dec));
	}
	
	function encryptFileAndReturnLib() {
		$mcrypt = new MCryptAES256Implementation();
		$lib = new AESCryptFileLib($mcrypt);
		
		//Encrypt file
		$encrypted_file = $lib->encryptFile($this->file_orig, $this->passphrase, $this->file_enc);
		$this->assertTrue(file_exists($encrypted_file));
		$this->assertTrue(filesize($encrypted_file) > 0);
		
		return $lib;
	}
	
	function testCorrectPassword() {
		$lib = $this->encryptFileAndReturnLib();
		
		//Attempt to decrypt with good passphrase
		$decrypted_file = $lib->decryptFile($this->file_enc, $this->passphrase, $this->file_dec);
		$this->assertTrue(file_exists($decrypted_file));
        $this->assertEqual(hash_file("sha256", $this->file_orig), hash_file("sha256", $decrypted_file));
    }
	
	function testBadPassword() {
		$lib = $this->encryptFileAndReturnLib();
		
		//Attempt decryption with bad passphrase
		$decrypted_file = NULL;
		try {
			$decrypted_file = $lib->decryptFile($this->file_enc, $this->badpassphrase, $this->file_dec);
		} catch (AESCryptInvalidPassphraseException $e) {
			//OK
			$this->pass("Yes, incorrect password");
		} catch (Exception $e) {
			$this->fail("Not an AESCryptInvalidPassphraseException: " . get_class($e));
		}
		$this->assertNull($decrypted_file);	
	}
}

class DenchTest extends AESCryptFileLibTest {
	public function __construct() {
		parent::__construct("files/dench.jpg");
	}
}

class NullEndingFileTest extends AESCryptFileLibTest {
	public function __construct() {
		parent::__construct("files/file_with_null_ending.bin");
	}
}

class SampleTextFileTest extends AESCryptFileLibTest {
	public function __construct() {
		parent::__construct("files/sample_text.txt");
	}
}