## 概述

2012年3月，国家密码管理局正式公布了包含SM4分组密码算法在内的《祖冲之序列密码算法》等6项密码行业标准。与DES和AES算法类似，SM4算法是一种分组密码算法。其分组长度为128bit，密钥长度也为128bit。加密算法与密钥扩展算法均采用32轮非线性迭代结构，以字（32位）为单位进行加密运算，每一次迭代运算均为一轮变换函数F。SM4算法加/解密算法的结构相同，只是使用轮密钥相反，其中解密轮密钥是加密轮密钥的逆序。

## 说明

加密前需要客户端先自己生成一个长度为32位的子串作为key（Java生成的 32为 hash值），其中子串不能包含中文。以下SM4加密方式为ECB模式，需要客户端选择应用的加密方式。

## 目录结构

```php
.
|-- LICENSE
|-- README.md
|-- SM4.php
|-- SM4Example.java
`-- test.php 
```

## 参考案例

### 加密

```php
$key = '35d251411ea04318565f0dbda6ffb6a8';

// 加密内容
$content = [
    'name' => 'Tinywan',
    'School' => 'ZheJiang University',
    'age' => 24,
    'github' => [
        'url' => 'https://github.com/Tinywan',
        'start' => 2000,
    ],
];

// 必须转换为字符串
$content = json_encode($content, JSON_UNESCAPED_UNICODE);
$sm4 = new SM4($key);
$encryptContent = $sm4->encrypt($content);
var_dump($encryptContent);
// 加密内容： b4358f5860343dbf2089ba75ee55deca8d922a069413f39cb3f8b64c01048c780ba5f03290642505d65d79c59684d76cf42443047f547c9f29dc2a49f872a2719ce00539058ab1fb5830e8e0c10144b574a87118390baa765b3429ba7afe5d28
```

### 解密

```php
$key = '35d251411ea04318565f0dbda6ffb6a8';

// 加密内容
$encryptContent = 'b4358f5860343dbf2089ba75ee55deca8d922a069413f39cb3f8b64c01048c780ba5f03290642505d65d79c59684d76cf42443047f547c9f29dc2a49f872a2719ce00539058ab1fb5830e8e0c10144b574a87118390baa765b3429ba7afe5d28';

$sm4 = new SM4($key);
$decryptedJsonContent = $sm4->decrypt($encryptContent);
print_r($decryptedJsonContent);
```

解密结果
```json
{
    "name": "Tinywan",
    "School": "ZheJiang University",
    "age": 24,
    "github": {
        "url": "https://github.com/Tinywan",
        "start": 2021
    }
}
```
> 可以通过 json_decode($content, true) ，转换为数组使用

## 引用文献

1. [《PHP实现国密算法SM4》](https://blog.csdn.net/liangxun0712/article/details/78611082)

2. [《关于PKCS5Padding与PKCS7Padding的区别》](https://blog.csdn.net/zsy19881226/article/details/46928177?utm_source=blogxgwz0)
