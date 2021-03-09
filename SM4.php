<?php

/**
 * @desc: 国密算法SM4
 * SM4加密方式类似于AES加密，为对称加密，可以通过相应的秘钥进行加密和解密
 * 加密前需要客户端先自己生成一个长度为32位的子串作为key，其中子串不能包含中文。并且SM4加密方式有CBC和ECB两种，需要客户端选择应用的加密方式
 * +----------------------------------------------------------
 * @author Tinywan(ShaoBo Wan)
 * +----------------------------------------------------------
 */

class SM4
{
    const SM4_CK = [
        0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
        0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
        0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
        0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
        0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
        0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
        0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
        0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
    ];

    const SM4_Sbox = [
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
        0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
        0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
        0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
        0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
        0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
        0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
        0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
        0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
        0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
        0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
        0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
        0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
        0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
        0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
    ];

    /**
     * 系统参数
     */
    const SM4_FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC];

    private $key = []; //16个 HEXHEX格式的数组 16字节 128bits  为了操作方便,直接存成十进制

    private $skey = []; //记录每轮加密的秘钥 记录成十进制

    private $block_size = 32;

    /**
     * SM4 constructor.
     * @param $key 32个十六进制的字符
     * @throws Exception
     */
    public function __construct($key)
    {
        $this->key = $this->preProcess($key);
        $this->setSkey();
    }

    /**
     * 计算每轮加密需要的秘钥
     */
    private function setSkey()
    {
        $skey = [];
        for ($i = 0; $i < 4; $i++) {
            $skey[] = self::SM4_FK[$i] ^ ($this->key[4 * $i] << 24 | $this->key[4 * $i + 1] << 16 | $this->key[4 * $i + 2] << 8 | $this->key[4 * $i + 3]);
        }
        for ($k = 0; $k < 32; $k++) {
            $tmp = $skey[$k + 1] ^ $skey[$k + 2] ^ $skey[$k + 3] ^ self::SM4_CK[$k];

            //非线性化操作
            $buf = (self::SM4_Sbox[($tmp >> 24) & 0xff]) << 24 |
                (self::SM4_Sbox[($tmp >> 16) & 0xff]) << 16 |
                (self::SM4_Sbox[($tmp >> 8) & 0xff]) << 8 |
                (self::SM4_Sbox[$tmp & 0xff]);
            //线性化操作
            $skey[] = $skey[$k] ^ ($buf ^ $this->sm4Rotl32($buf, 13) ^ $this->sm4Rotl32($buf, 23));
            $this->skey[] = $skey[$k + 4];
        }
    }


    /**
     * 32比特的buffer中循环左移n位
     * @param $buf int 可以传递进10进制 也可以是0b开头的二进制
     * @param $n int 向左偏移n位
     *
     * @return int
     * reference http://blog.csdn.net/w845695652/article/details/6522285
     */
    private function sm4Rotl32($buf, $n)
    {
        return (($buf << $n) & 0xffffffff) | ($buf >> (32 - $n));
    }

    /**
     * 对字符串加密
     * @param $plainText
     *
     * @return string
     * @throws Exception
     */
    public function encrypt($plainText)
    {
        $bytes = bin2hex($plainText);
        $need_pad_length = $this->block_size - strlen($bytes) % $this->block_size;
        $pad_bytes = str_pad(
            $bytes,
            strlen($bytes) + $need_pad_length,
            sprintf("%02x", $need_pad_length / 2),
            STR_PAD_RIGHT
        );
        $chunks = str_split($pad_bytes, $this->block_size);

        return strtolower(implode('', array_map(function ($chunk) {
            return $this->encryptBinary($chunk);
        }, $chunks)));
    }


    /**
     * SM4加密单个片段(128bit)
     * @param $text string 32个十六进制字符串
     *
     * @return string
     * @throws Exception
     */
    private function encryptBinary($text)
    {
        $x = $re = [];
        $t = $this->preProcess($text);
        for ($i = 0; $i < 4; $i++) {
            $x[] = $t[$i * 4] << 24 |
                $t[$i * 4 + 1] << 16 |
                $t[$i * 4 + 2] << 8 |
                $t[$i * 4 + 3];
        }

        for ($k = 0; $k < 32; $k++) {
            $tmp = $x[$k + 1] ^ $x[$k + 2] ^ $x[$k + 3] ^ $this->skey[$k];

            $buf = self::SM4_Sbox[($tmp >> 24) & 0xff] << 24 |
                self::SM4_Sbox[($tmp >> 16) & 0xff] << 16 |
                self::SM4_Sbox[($tmp >> 8) & 0xff] << 8 |
                self::SM4_Sbox[$tmp & 0xff];

            $x[$k + 4] = $x[$k] ^ $buf
                ^ $this->sm4Rotl32($buf, 2)
                ^ $this->sm4Rotl32($buf, 10)
                ^ $this->sm4Rotl32($buf, 18)
                ^ $this->sm4Rotl32($buf, 24);
        }
        for ($i = 0; $i < 4; $i++) {
            $re[] = ($x[35 - $i] >> 24) & 0xff;
            $re[] = ($x[35 - $i] >> 16) & 0xff;
            $re[] = ($x[35 - $i] >> 8) & 0xff;
            $re[] = $x[35 - $i] & 0xff;
        }
        return $this->wrapResult($re);
    }


    /**
     * 预处理16字节长度的16进制字符串 返回10进制的数组 数组大小为16
     * @param $text
     *
     * @return array
     * @throws Exception
     */
    private function preProcess($text)
    {
        preg_match('/[0-9a-f]{32}/', strtolower($text), $re);
        if (empty($re)) {
            throw new Exception('error input format!');
        }
        $key = $re[0];
        for ($i = 0; $i < 16; $i++) {
            $result[] = hexdec($key[2 * $i] . $key[2 * $i + 1]);
        }

        return $result;
    }

    /**
     * 将十进制结果包装成16进制字符串输出
     * @param $result
     *
     * @return string
     */
    private function wrapResult($result)
    {
        $hex_str = '';
        foreach ($result as $v) {
            $tmp = dechex($v);
            $len = strlen($tmp);
            if ($len == 1) //不足两位十六进制的数 在前面补一个0,保证输出也是32个16进制字符
            {
                $hex_str .= '0';
            }
            $hex_str .= $tmp;
        }
        return strtoupper($hex_str);
    }


    /**
     * SM4解密单个片段(128bits)
     * @param $text string 32个16进制字符串
     * @return string
     * @throws Exception
     */
    private function decrypt_decrypt($text)
    {
        $x = $re = [];
        $t = $this->preProcess($text);
        for ($i = 0; $i < 4; $i++) {
            $x[] = $t[4 * $i] << 24 |
                $t[4 * $i + 1] << 16 |
                $t[4 * $i + 2] << 8 |
                $t[4 * $i + 3];
        }
        for ($k = 0; $k < 32; $k++) {
            $tmp = $x[$k + 1] ^ $x[$k + 2] ^ $x[$k + 3] ^ $this->skey[31 - $k];
            $buf = (self::SM4_Sbox[($tmp >> 24) & 0xff]) << 24 |
                (self::SM4_Sbox[($tmp >> 16) & 0xff]) << 16 |
                (self::SM4_Sbox[($tmp >> 8) & 0xff]) << 8 |
                (self::SM4_Sbox[$tmp & 0xff]);
            $x[$k + 4] = $x[$k] ^ $buf
                ^ $this->sm4Rotl32($buf, 2)
                ^ $this->sm4Rotl32($buf, 10)
                ^ $this->sm4Rotl32($buf, 18)
                ^ $this->sm4Rotl32($buf, 24);
        }

        for ($i = 0; $i < 4; $i++) {
            $re[] = ($x[35 - $i] >> 24) & 0xff;
            $re[] = ($x[35 - $i] >> 16) & 0xff;
            $re[] = ($x[35 - $i] >> 8) & 0xff;
            $re[] = $x[35 - $i] & 0xff;
        }
        return $this->wrapResult($re);
    }

    /**
     * @desc: 方法描述
     * @param $cipherText
     * @return string
     */
    public function decrypt($cipherText)
    {
        $chunks = str_split($cipherText, $this->block_size);
        $decrypt_text_data = implode('', array_map(function ($chunk) {
            return $this->decrypt_decrypt($chunk);
        }, $chunks));

        $pad_length = hexdec(substr($decrypt_text_data, -2));

        return hex2bin(preg_replace(
            sprintf("/%s$/", str_repeat(sprintf("%02x", $pad_length), $pad_length)),
            '',
            $decrypt_text_data
        ));
    }
}
