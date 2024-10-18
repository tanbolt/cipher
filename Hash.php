<?php
namespace Tanbolt\Cipher;

use HashContext;

/**
 * Class Hash: 哈希值 （消息摘要）生成
 * @package Tanbolt\Cipher
 */
class Hash
{
    /**
     * 算法上下文
     * @var HashContext|resource
     */
    private $context;

    /**
     * 是否已消费
     * @var bool
     */
    private $consumed = false;

    /**
     * 所有可用算法
     * @var array
     */
    private static $algorithms;

    /**
     * 获取所有可用算法
     * @return array
     */
    public static function allAlgo()
    {
        if (!static::$algorithms) {
            static::$algorithms = hash_algos();
        }
        return static::$algorithms;
    }

    /**
     * 判断是否支持 $algo 算法
     * @param string $algo
     * @return bool
     */
    public static function supportAlgo(string $algo)
    {
        return in_array($algo, static::allAlgo());
    }

    /**
     * 创建一个 Hash 对象
     * @param string $algo
     * @param bool $useKey
     * @param string|null $key
     * @return static
     */
    public static function create(string $algo = 'sha256', bool $useKey = true, string $key = null)
    {
        return new static($algo, $useKey, $key);
    }

    /**
     * Hash constructor.
     * @param string $algo
     * @param bool $useKey
     * @param string|null $key
     */
    public function __construct(string $algo = 'sha256', bool $useKey = true, string $key = null)
    {
        $this->context = $useKey ? hash_init($algo, HASH_HMAC, empty($key) ? Cipher::getKey() : $key) : hash_init($algo);
    }

    /**
     * 执行操作前，确认当前 Hash 对象未消费
     */
    private function check()
    {
        if ($this->consumed) {
            throw new CipherException('Hash already consumed');
        }
    }

    /**
     * 使用普通字符串填充数据
     * @param string|array $data
     * @return $this
     */
    public function update(...$data)
    {
        $this->check();
        foreach (static::flatten($data) as $item) {
            if (!hash_update($this->context, $item)) {
                throw new CipherException('hash update failed');
            }
        }
        return $this;
    }

    /**
     * 使用 [文件路径] 或 [封装协议] 填充数据
     * @see https://www.php.net/manual/zh/wrappers.php
     * @param string $filepath [文件路径] 或 [封装协议]
     * @param resource|null $streamContext 若 $filepath 为 [封装协议]，可为协议路径设置上下文
     * @return $this
     */
    public function updateFile(string $filepath, $streamContext = null)
    {
        $this->check();
        if (!($streamContext
            ? hash_update_file($this->context, $filepath, $streamContext)
            : hash_update_file($this->context, $filepath)
        )) {
            throw new CipherException('hash update file failed');
        }
        return $this;
    }

    /**
     * 使用数据流填充数据
     * @param resource $stream 流资源句柄
     * @param int $length 最大字符数
     * @return $this
     */
    public function updateStream($stream, int $length = -1)
    {
        $this->check();
        if (!hash_update_stream($this->context, $stream, $length)) {
            throw new CipherException('hash update stream failed');
        }
        return $this;
    }

    /**
     * 复制一个新的 Hash 对象，该对象包含当前的填充数据，但复制之后二者互相独立
     * @return Hash
     */
    public function copy()
    {
        return clone $this;
    }

    /**
     * 判断当前 Hash 对象是否已使用过，一旦使用过，已设置数据会被清空
     * @return bool
     */
    public function consumed()
    {
        return $this->consumed;
    }

    /**
     * 生成十六进制字符串格式摘要
     * @param bool $upper 是否返回大写格式，默认为小写
     * @return string
     */
    public function hex(bool $upper = false)
    {
        $this->check();
        $this->consumed = true;
        $hex = hash_final($this->context);
        return $upper ? strtoupper($hex) : $hex;
    }

    /**
     * 生成原始的二进制摘要
     * @return string
     */
    public function raw()
    {
        $this->check();
        $this->consumed = true;
        return hash_final($this->context, true);
    }

    /**
     * Hash 结果验证，支持二进制、十六进制
     * @param string $hash
     * @return bool
     */
    public function equal(string $hash)
    {
        $hex = $this->hex();
        return hash_equals($hex, strtolower($hash)) || hash_equals(hex2bin($hex), $hash);
    }

    /**
     * 克隆对象，创建新的上下文
     */
    public function __clone()
    {
        $this->check();
        $this->context = hash_copy($this->context);
    }

    /**
     * flatten array
     * @param array $array
     * @return array
     */
    private static function flatten(array $array)
    {
        $flatten = [];
        array_walk_recursive($array, function($a) use (&$flatten) {
            $flatten[] = $a;
        });
        return $flatten;
    }
}
