<?php
require_once('simpletest/autorun.php');

echo "Running all tests...";

class AllFileTests extends TestSuite {
    function __construct() {
        parent::__construct();
        $this->collect(dirname(__FILE__) . '/', new SimplePatternCollector('/Test.php/'));
    }
}