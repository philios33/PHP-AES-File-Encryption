<?php

require_once 'simpletest/autorun.php';
require_once '../AESCryptFileLib.php';
require_once '../AES256Implementation.php';
require_once '../aes256/AESMCryptImplementation.php';

class AESCryptFileLibTest extends UnitTestCase {
	function testBasicEncryptAndDecryptDenchUsingMcrypt() {
        @unlink('files/dench.jpg.aes');
		@unlink('files/dench_dec.jpg');
		
		$mcrypt = new AESMCryptImplementation();
		$lib = new AESCryptFileLib($mcrypt);
		
		$encrypted_file = $lib->encryptFile("files/dench.jpg", "philISgr347", "files/dench.jpg.aes");
		$this->assertTrue(file_exists($encrypted_file));
		$this->assertTrue(filesize($encrypted_file) > 0);
		
		$decrypted_file = $lib->decryptFile("files/dench.jpg.aes", "philISgr347", "files/dench_dec.jpg");
		$this->assertTrue(file_exists($decrypted_file));
        $this->assertTrue(hash_file("sha256", "files/dench.jpg") == hash_file("sha256", $decrypted_file));
        
    }
}
