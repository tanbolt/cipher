<?php
namespace Tanbolt\Cipher;

use Tanbolt\Config\Config;

/**
 * Class Cipher: 常用字符加密解密函数
 * @package Tanbolt\Cipher
 */
class Cipher
{
    /**
     * @var string
     */
    private static $key;

    /**
     * 支持的 随机 函数类型
     * @var int
     */
    private static $randType;

    /**
     * 支持的 digest 算法缓存
     * @var null
     */
    private static $digestMethods;

    /**
     * 支持的 crypt 算法缓存
     * @var null
     */
    private static $cryptMethods;

    /**
     * 缓存 crypt method iv 长度缓存
     * @var array
     */
    private static $cryptIvLen = [];

    /**
     * 零宽字符加解密
     * @var int
     */
    private static $spaceLow = "\u{200b}";
    private static $spaceHig = "\u{200c}";
    private static $spaceWrd = "\u{200d}";
    private static $spaceSpt = "\u{200e}";

    /**
     * 设置密钥 key，设置成功，返回旧 key； 失败返回 false
     * @param string $key
     * @return string|false
     */
    public static function setKey(string $key)
    {
        if (empty($key)) {
            return false;
        }
        $current = static::getKey();
        static::$key = $key;
        return $current;
    }

    /**
     * 获取密匙 key
     * @return string
     */
    public static function getKey()
    {
        if (null === static::$key) {
            $default = '11df611b174f40070084228b1683fc44';
            if (class_exists(Config::class)) {
                $default = Config::get('cipher_key', $default);
            }
            static::$key = $default;
        }
        return static::$key;
    }

    /**
     * 生成指定长度的随机字符串
     * @param int $length 字符串长度
     * @return string
     */
    public static function random(int $length = 16)
    {
        if ($length < 1) {
            return '';
        }
        $string = '';
        while (($len = mb_strlen($string)) < $length) {
            $size = $length - $len;
            $bytes = static::randomBytes($size);
            $string .= mb_substr(str_replace(['/', '+', '='], '', base64_encode($bytes)), 0, $size, 'UTF-8');
        }
        return $string;
    }

    /**
     * 生成指定长度的二进制随机数据
     * @param int $bytes 字节数
     * @return string
     * @throws
     */
    public static function randomBytes(int $bytes = 16)
    {
        if ($bytes < 1) {
            return '';
        }
        if (null === static::$randType) {
            static::$randType = function_exists('random_bytes') ? 0
                : (
                    function_exists('openssl_random_pseudo_bytes') ? 1 : (
                        function_exists('mcrypt_create_iv') ? 2 : false
                    )
                );
        }
        switch (static::$randType) {
            case 0:
                return random_bytes($bytes);
            case 1:
                $buf = openssl_random_pseudo_bytes($bytes, $strong);
                if (false === $buf || false === $strong || mb_strlen($buf) !== $bytes) {
                    throw new CipherException('Unable to generate random string.');
                }
                return $buf;
            case 2:
                /** @noinspection PhpElementIsNotAvailableInCurrentPhpVersionInspection */
                $buf = @mcrypt_create_iv($bytes);
                if (false === $buf || mb_strlen($buf) !== $bytes) {
                    throw new CipherException('Unable to generate random string.');
                }
                return $buf;
        }
        throw new CipherException('OpenSSL extension or Mcrypt extension is required for PHP 5 users.');
    }

    /**
     * 加密为零宽字符，加密后大小会膨胀很多倍，不建议加密较长字符
     * @param string $data
     * @return string
     */
    public static function zwEncode(string $data)
    {
        return self::$spaceSpt.join(self::$spaceWrd, array_map(function ($char) {
            return str_replace(['0', '1'], [self::$spaceLow, self::$spaceHig], decbin(ord($char)));
        }, str_split($data))).self::$spaceSpt;
    }

    /**
     * 加密零宽字符
     * - $data 中可包含多段加密零宽字符, 解密后返回数组，未找到返回空数组；
     * - 若确定只包含一段加密的零宽字符，可设置 $first=true，找到并解密后会返回字符串，未成功解密返回 null
     * @param string $data 包含零宽字符的数据
     * @param bool $first 是否仅获取一个解密的零宽字符
     * @return array|string|null
     */
    public static function zwDecode(string $data, bool $first = false)
    {
        $decode = [];
        $start = null;
        $lastPos = 0;
        $needLen = strlen(self::$spaceSpt);
        while (false !== $lastPos = strpos($data, self::$spaceSpt, $lastPos)) {
            if (null === $start) {
                $start = $lastPos += $needLen;
            } else {
                $char = null;
                $encode = substr($data, $start, $lastPos - $start);
                $encode = str_replace([self::$spaceLow, self::$spaceHig, self::$spaceWrd], ['0', '1', '_'], $encode);
                if (preg_match('/^[01_]+$/', $encode)) {
                    $char = join('', array_map(function ($bin) {
                        return chr(bindec($bin));
                    }, explode('_', $encode)));
                }
                // 解密成功, 直接返回或暂时缓存
                if ($char) {
                    if ($first) {
                        return $char;
                    }
                    $decode[] = $char;
                }
                $start = null;
                $lastPos += $needLen;
            }
        }
        return $first ? null : $decode;
    }

    /**
     * 获取可安全用于 url 的 base64 encode
     * @param string $data
     * @return string
     */
    public static function b64Encode(string $data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * 解码 Cipher::base64_encode 过的数据
     * @param string $data
     * @return string
     */
    public static function b64Decode(string $data)
    {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '='));
    }

    /**
     * 获取散列算法
     * - $algo=null: 获取所有可用的 digest 算法(包括别名)。
     * - $algo=string: 判断是否支持 digest 算法(支持别名)，不存在返回 false；存在返回正确的算法名。
     * @param ?string $algo
     * @return array|string|false
     * @see https://www.php.net/manual/zh/function.openssl-get-md-methods.php
     */
    public static function digestMethod(string $algo = null)
    {
        if (!static::$digestMethods) {
            static::$digestMethods = static::formatMethods(openssl_get_md_methods(true));
        }
        return static::getMethod((array)static::$digestMethods, $algo);
    }

    /**
     * 生成指定字符串的摘要信息，算法名称大小写不敏感
     * @param string $data 字符串
     * @param string $algo 算法
     * @param bool $raw 算法返回原始二进制数据
     * @return string
     * @see https://www.php.net/manual/zh/function.openssl-digest.php
     */
    public static function digest(string $data , string $algo = 'sha256', bool $raw = false)
    {
        if (empty($data)) {
            return '';
        }
        $method = static::digestMethod($algo);
        if (!$method) {
            throw new CipherException('Unknown openssl digest method: '.$algo);
        }
        return openssl_digest($data, $method, $raw);
    }

    /**
     * 获取加密算法
     * - $algo=null: 获取所有可用的 crypt 算法(包括别名)。
     * - $algo=string: 判断是否支持 crypt 算法(支持别名)，不存在返回 false； 存在返回正确的算法名
     * @param ?string $algo
     * @return array|string|false
     * @see http://php.net/manual/zh/function.openssl-get-cipher-methods.php
     */
    public static function cryptMethod(string $algo = null)
    {
        if (!static::$cryptMethods) {
            static::$cryptMethods = static::formatMethods(openssl_get_cipher_methods(true));
        }
        return static::getMethod((array)static::$cryptMethods, $algo);
    }

    /**
     * 加密数据，算法名称大小写不敏感
     * @param mixed $code 待加密数据
     * @param string $algo 算法
     * @return string|false
     * @see https://www.php.net/manual/zh/function.openssl-encrypt.php
     */
    public static function encrypt($code, string $algo = 'aes-128-cbc')
    {
        if (empty($code)) {
            return '';
        }
        $method = static::cryptMethod($algo);
        if (!$method) {
            throw new CipherException('Unknown openssl encrypt method: '.$algo);
        }
        $code = serialize($code);
        $ivLen = static::$cryptIvLen[$method] ?? (static::$cryptIvLen[$method] = openssl_cipher_iv_length($method));
        $iv = $ivLen ? static::randomBytes($ivLen) : '';
        $tag = null;
        $end = strtolower(substr($method, -4));
        if ('-gcm' === $end || '-ccm' === $end) {
            // AEAD 密码模式 需要 tag 参数
            $encode = openssl_encrypt($code, $method, static::$key, OPENSSL_RAW_DATA, $iv, $tag, '', 8);
        } else {
            $encode = openssl_encrypt($code, $method, static::$key, OPENSSL_RAW_DATA, $iv);
        }
        // 虽然支持 cryptMethod, 但可能 openssl 组件存在问题, 仍有可能加密失败
        if (false === $encode) {
            return false;
        }
        $encode = [
            'i' => $iv,
            'v' => $encode
        ];
        if (null !== $tag) {
            $encode['g'] = $tag;
        }
        return static::b64Encode(serialize($encode));
    }

    /**
     * 解密数据，算法名称大小写不敏感
     * @param string $encode 待解密数据
     * @param string $algo 算法
     * @return mixed|null
     * @see https://www.php.net/manual/zh/function.openssl-decrypt.php
     */
    public static function decrypt(string $encode, string $algo = 'aes-128-cbc')
    {
        if (empty($encode)) {
            return null;
        }
        $method = static::cryptMethod($algo);
        if (!$method) {
            throw new CipherException('Unknown openssl encrypt method: '.$algo);
        }
        set_error_handler(function(){});
        $encode = ($encode = static::b64Decode($encode)) ? unserialize($encode) : null;
        if (is_array($encode) && isset($encode['i']) && isset($encode['v'])) {
            if (isset($encode['g'])) {
                $encode = openssl_decrypt($encode['v'], $method, static::$key, OPENSSL_RAW_DATA, $encode['i'], $encode['g']);
            } else {
                $encode = openssl_decrypt($encode['v'], $method, static::$key, OPENSSL_RAW_DATA, $encode['i']);
            }
            if ($encode && ($encode = unserialize($encode))) {
                return $encode;
            }
        }
        restore_error_handler();
        return null;
    }

    /**
     * 提取 全小写 算法
     * @param array $methods
     * @return array
     */
    private static function formatMethods(array $methods)
    {
        $algo = [];
        foreach ($methods as $method) {
            $lower = strtolower($method);
            if ($lower === $method) {
                // 算法名称为 全小写
                $algo[$lower] = true;
            } elseif (!in_array($lower, $methods)) {
                // 算法名称不是全小写 且 不存在对应的全小写算法
                $algo[$lower] = $method;
            }
        }
        return $algo;
    }

    /**
     * 获取实际 算法名称
     * @param array $methods
     * @param ?string $algo
     * @return array|string|false
     */
    private static function getMethod(array $methods, string $algo = null)
    {
        if (!$algo) {
            return $methods;
        }
        $algo = $methods[$lower = strtolower($algo)] ?? null;
        return null === $algo ? false : (true === $algo ? $lower : $algo);
    }
}
