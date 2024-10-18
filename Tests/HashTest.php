<?php

use Tanbolt\Cipher\Cipher;
use Tanbolt\Cipher\Hash;
use PHPUnit\Framework\TestCase;

class HashTest extends TestCase
{
    protected static $md5 = [
        'foo' => 'ac5c5b64e2a9b262a5e7eed47ee6dd94',
        'foobar' => '3a9fddfe445305331f26dc00e77bd804'
    ];

    public function testAlgo()
    {
        $allAlgo = Hash::allAlgo();
        static::assertTrue(is_array($allAlgo));
        foreach ($allAlgo as $algo) {
            static::assertTrue(Hash::supportAlgo($algo));
        }
        static::assertFalse(Hash::supportAlgo('none'));
    }

    public function testCreate()
    {
        static::assertInstanceOf(Hash::class, Hash::create());
    }

    public function testUpdate()
    {
        $oldKey = Cipher::setKey('test');

        static::assertEquals('acbd18db4cc2f85cedef654fccc4a4d8', Hash::create('md5', false)->update('foo')->hex());
        static::assertEquals('31b6db9e5eb4addb42f1a6ca07367adc', Hash::create('md5', true, 'bar')->update('foo')->hex());

        static::assertEquals(static::$md5['foo'], Hash::create('md5')->update('foo')->hex());
        static::assertEquals(
            bin2hex(Hash::create('md5')->update('foo')->raw()),
            Hash::create('md5')->update('foo')->hex()
        );
        static::assertEquals(
            bin2hex(Hash::create('md5', false)->update('foo')->raw()),
            Hash::create('md5', false)->update('foo')->hex()
        );

        static::assertEquals(static::$md5['foobar'], Hash::create('md5')->update('foo', 'bar')->hex());
        static::assertEquals(static::$md5['foobar'], Hash::create('md5')->update('foo')->update('bar')->hex());

        Cipher::setKey($oldKey);
    }

    public function testUpdateFile()
    {
        $oldKey = Cipher::setKey('test');
        $existed = in_array("phpunit", stream_get_wrappers());
        if ($existed) {
            stream_wrapper_unregister("phpunit");
        }
        stream_wrapper_register("phpunit", "PHPUNITStream");

        $file = __DIR__.'/_';
        file_put_contents($file, 'foo');
        static::assertEquals(static::$md5['foo'], Hash::create('md5')->updateFile($file)->hex());
        @unlink($file);

        $context = stream_context_create(['phpunit' => ['salt' => 'bar']]);
        static::assertEquals(static::$md5['foobar'], Hash::create('md5')->updateFile('phpunit://foo', $context)->hex());
        static::assertEquals(static::$md5['foo'], Hash::create('md5')->updateFile('phpunit://foo')->hex());

        if ($existed) {
            stream_wrapper_restore("phpunit");
        }
        Cipher::setKey($oldKey);
    }

    public function testUpdateStream()
    {
        $oldKey = Cipher::setKey('test');

        $file = __DIR__.'/_';
        file_put_contents($file, 'foobar');

        $fp = fopen($file, 'rb');
        static::assertEquals(static::$md5['foobar'], Hash::create('md5')->updateStream($fp)->hex());
        fclose($fp);

        $fp = fopen($file, 'rb');
        static::assertEquals(static::$md5['foo'], Hash::create('md5')->updateStream($fp, 3)->hex());
        fclose($fp);

        @unlink($file);
        Cipher::setKey($oldKey);
    }

    public function testCopy()
    {
        $oldKey = Cipher::setKey('test');

        $hash = Hash::create('md5')->update('foo');
        $copyHash = $hash->copy();
        $cloneHash = clone $hash;

        static::assertInstanceOf(Hash::class, $copyHash);
        static::assertNotSame($hash, $copyHash);

        static::assertInstanceOf(Hash::class, $cloneHash);
        static::assertNotSame($hash, $cloneHash);

        static::assertEquals(static::$md5['foo'], $hash->hex());
        static::assertEquals(static::$md5['foo'], $copyHash->hex());
        static::assertEquals(static::$md5['foobar'], $cloneHash->update('bar')->hex());

        Cipher::setKey($oldKey);
    }

    public function testConsumed()
    {
        $hash = Hash::create('md5')->update('foo');
        static::assertFalse($hash->consumed());
        $hash->hex();
        static::assertTrue($hash->consumed());

        try {
            $hash->update('a');
            static::fail('It should throw exception if hash was consumed');
        } catch (Throwable $e) {
            static::assertTrue(true);
        }

        try {
            $hash->copy();
            static::fail('It should throw exception if hash was consumed');
        } catch (Throwable $e) {
            static::assertTrue(true);
        }

        try {
            $hash->hex();
            static::fail('It should throw exception if hash was consumed');
        } catch (Throwable $e) {
            static::assertTrue(true);
        }

        try {
            $hash->raw();
            static::fail('It should throw exception if hash was consumed');
        } catch (Throwable $e) {
            static::assertTrue(true);
        }
    }

    public function testEqual()
    {
        $oldKey = Cipher::setKey('test');

        static::assertTrue(Hash::create('md5')->update('foo')->equal(static::$md5['foo']));
        static::assertTrue(Hash::create('md5')->update('foo')->equal(hex2bin(static::$md5['foo'])));
        static::assertFalse(Hash::create('md5')->update('foo')->equal('any'));

        Cipher::setKey($oldKey);
    }
}

class PHPUNITStream {
    public $context;
    private $path;

    public function stream_open($path)
    {
        $context = stream_context_get_options($this->context);
        $context = $context['phpunit'] ?? [];
        $salt = $context['salt'] ?? '';
        $this->path = explode('//', $path)[1].$salt;
        return true;
    }

    public function stream_read() {
        if (!$this->path) {
            return '';
        }
        $path = $this->path;
        $this->path = null;
        return $path;
    }

    public function stream_eof() {
        return true;
    }

    public function stream_close() {
        return true;
    }
}
