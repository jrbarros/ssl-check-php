<?php

use JrBarros\CheckSSL;
use PHPUnit\Framework\TestCase;

/**
 * Class CheckSSLTest
 */
final class CheckSSLTest extends TestCase
{

    public function testInvalidUrl() {
        $this->expectException(Exception::class);

        $invalidUrl = 'example.com.br';
        (new CheckSSL())->add($invalidUrl)->check();
    }

    public function testInvalidArray() {
        $this->expectException(Exception::class);

        $invalidUrlArray = ['example.com.br'];
        (new CheckSSL())->add($invalidUrlArray)->check();
    }

    public function testValidUrl() {

        $validUrl = 'https://www.google.com';
        $this->assertTrue((new CheckSSL())->add($validUrl)->check()['is_valid']);
    }

    public function testValidUrlArray() {

        $validUrlArray = ['https://www.google.com','https://www.microsoft.com'];
        $result = (new CheckSSL())->add($validUrlArray)->check();

        foreach ($result as $key => $item) {
            $this->assertTrue($item['is_valid']);
        }
    }

    public function testTypeResult() {
        $validUrl = 'https://www.google.com';
        $this->assertTrue(is_iterable((new CheckSSL())->add($validUrl)->check()));
    }

    public function testCustomDate() {

        $validUrl = ['https://www.google.com'];
        $format = 'U';
        $dateFormat = 'd-m-Y';

        $checkSLL = new CheckSSL($validUrl, $format, $dateFormat);

        $this->assertEquals(1,
            preg_match("/^(0[1-9]|[1-2][0-9]|3[0-1])-(0[1-9]|1[0-2])-[0-9]{4}$/",
                $checkSLL->check()['valid_until'])
        );
    }

    public function testCustomTimeout() {

        $checkSLL = new CheckSSL([], '', '', '', 60.0);

        $this->assertEquals(60.0, $checkSLL->getTimeout());
    }

    public function test() {

        $this->expectException(TypeError::class);

        $validUrl = [];
        $format = null;
        $dateFormat = 1254;

        (new CheckSSL($validUrl, null, $dateFormat));
    }
}