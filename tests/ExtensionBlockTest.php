<?php

require_once '../AESCryptFileLib.php';
require_once '../aes256/MCryptAES256Implementation.php';

abstract class ExtensionBlockTest extends UnitTestCase {
	
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
	
	function assertBadExtensionBlock($lib, $ext_data)
	{
		$success = NULL;
		try {
			$success = $lib->encryptFile($this->file_orig, '1234', $this->file_enc, $ext_data);
		} catch (AESCryptInvalidExtensionException $aiee) {
			$this->pass("Bad extension block correctly identified");
		} catch (Exception $e) {
			$this->fail("Not an AESCryptInvalidExtensionException: " . get_class($e));
		}
		$this->assertNull($success);
	}
	
	function testInvalidExtensionBlocks() {
		$mcrypt = new MCryptAES256Implementation();
		$lib = new AESCryptFileLib($mcrypt);
		
		$this->assertBadExtensionBlock($lib, "Just a string");
		$this->assertBadExtensionBlock($lib, array("Array of single string"));
		$this->assertBadExtensionBlock($lib, array("Array of lots", "of strings"));
		$this->assertBadExtensionBlock($lib, array(array('bad' => 'xxx', 'keys' => 'xxx')));
		$this->assertBadExtensionBlock($lib, array(array('identifie' => 'misspelling', 'contents' => 'good')));
		$this->assertBadExtensionBlock($lib, array(array('identifier' => 'good', 'content' => 'misspelling')));
		$this->assertBadExtensionBlock($lib, array(array('identifier' => 'good', 'contents' => 'good'), 'bad item'));
		$this->assertBadExtensionBlock($lib, array(array('identifier' => 'good', 'contents' => 'good'), array('identifie' => 'misspelling', 'contents' => 'good')));
		$this->assertBadExtensionBlock($lib, array(array('identifier' => 'good', 'contents' => 'good'), NULL, NULL));
		$this->assertBadExtensionBlock($lib, array(array('identifier' => 'repeated', 'contents' => 'good'), array('identifier' => 'repeated', 'contents' => 'something else')));
	}
	
	function assertGoodExtensionBlock($lib, $ext_data)
	{
		//First encrypt the file
		$lib->encryptFile($this->file_orig, '1234', $this->file_enc, $ext_data);

		//Then read the blocks back out
		$read_blocks = $lib->readExtensionBlocks($this->file_enc);

		//These should match
		$this->assertIdentical($read_blocks, $ext_data);
	}
	
	function testValidExtensionBlocks() {
		$mcrypt = new MCryptAES256Implementation();
		$lib = new AESCryptFileLib($mcrypt);
		
		$this->assertGoodExtensionBlock($lib, array(array('identifier' => 'first', 'contents' => 'one'), array('identifier' => 'second', 'contents' => 'two'), array('identifier' => 'third', 'contents' => 'three')));
	}
	
}

class DenchExtensionBlockTest extends ExtensionBlockTest {
	public function __construct() {
		parent::__construct("files/dench.jpg");
	}
}