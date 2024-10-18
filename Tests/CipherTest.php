<?php

use Tanbolt\Cipher\Cipher;
use PHPUnit\Framework\TestCase;

class CipherTest extends TestCase
{
    public function testSetKey()
    {
        $key = Cipher::getKey();
        static::assertTrue(is_string($key));
        static::assertEquals($key, Cipher::setKey('aaa'));
        static::assertEquals('aaa', Cipher::getKey());
    }

    public function testRandom()
    {
        $count = 0;
        while (true) {
            $length = rand(2, 30);
            $bytes = Cipher::randomBytes($length);
            $str = Cipher::random($length);
            static::assertEquals($length, strlen($bytes));
            static::assertEquals($length, strlen($str));
            $count++;
            if ($count > 100) {
                break;
            }
        }
    }

    public function testZeroWidth()
    {
        $count = 10;
        while ($count) {
            $random1 = Cipher::randomBytes(rand(2, 20));
            $encode1 = Cipher::zwEncode($random1);
            static::assertEquals($random1, Cipher::zwDecode($encode1, true));

            $random2 = Cipher::random(rand(2, 20));
            $encode2 = 'foo'.$encode1.'bar'.Cipher::zwEncode($random2).'biz';
            static::assertEquals([$random1, $random2], Cipher::zwDecode($encode2));
            $count--;
        }
    }

    public function testBase64()
    {
        $count = 0;
        $checked = false;
        while (true) {
            $random = Cipher::randomBytes(rand(2, 20));
            $base64 = base64_encode($random);
            $encode = Cipher::b64Encode($random);
            static::assertEquals($random, Cipher::b64Decode($encode));
            if (!$checked && strpos($base64, '+') || strpos($base64, '/')) {
                $checked = true;
            }
            $count++;
            if ($count > 50 && $checked) {
                break;
            }
        }
    }

    /**
     * @dataProvider digestMethod
     * @param $algo
     */
    public function testDigest($algo)
    {
        $length = rand(2, 30);
        $digest = Cipher::digest(Cipher::randomBytes($length), $algo);
        if (is_string($digest)) {
            static::assertNotEmpty($digest);
        } else {
            static::assertFalse($digest);
            print 'digest with ['.$algo.'] return false';
        }
    }

    public function digestMethod()
    {
        $methods = array_keys(Cipher::digestMethod());
        $lowers = array_map(function ($method) {
            return [strtolower($method)];
        }, $methods);
        $uppers = array_map(function ($method) {
            return [strtoupper($method)];
        }, $methods);
        return $lowers + $uppers;
    }

    /**
     * @dataProvider cryptMethod
     * @param $algo
     */
    public function testCrypt($algo)
    {
        $length = rand(2, 30);
        $str = Cipher::randomBytes($length);
        $encode = Cipher::encrypt($str, $algo);
        if (is_string($encode)) {
            static::assertEquals($str, Cipher::decrypt($encode, $algo), $algo);
        } else {
            static::assertFalse($encode);
            print 'encrypt string with ['.$algo.'] return false';
        }
    }

    public function cryptMethod()
    {
        $methods = array_keys(Cipher::cryptMethod());
        $lowers = array_map(function ($method) {
            return [strtolower($method)];
        }, $methods);
        $uppers = array_map(function ($method) {
            return [strtoupper($method)];
        }, $methods);
        return $lowers + $uppers;
    }
}
