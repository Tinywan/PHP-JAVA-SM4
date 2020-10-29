# 国密算法SM4

SM4加密方式类似于AES加密，为对称加密，可以通过相应的秘钥进行加密和解密

加密前需要客户端先自己生成一个长度为32位的子串作为key，其中子串不能包含中文。并且SM4加密方式有CBC和ECB两种，需要客户端选择应用的加密方式


## 使用

#### 加密

```php
$key = '35d251411ea04318565f0dbda6ffb6a8'

// 加密内容
$content = [
    'name' => 'Tinywan',
    'age' => 24,
    'github' => [
        'url' => 'https://github.com/Tinywan',
        'start' => 2000,
    ],
];

// 必须转换为字符串
$content = json_encode($content, JSON_UNESCAPED_UNICODE);
$sm4 = new \SM4Util();
$encryptContent = $sm4->setKey($key)->encrypt($content);
var_dump($encryptContent);
// 加密内容： b4358f5860343dbf2089ba75ee55deca8d922a069413f39cb3f8b64c01048c780ba5f03290642505d65d79c59684d76cf42443047f547c9f29dc2a49f872a2719ce00539058ab1fb5830e8e0c10144b574a87118390baa765b3429ba7afe5d28
```

#### 解密

```php
$key = '35d251411ea04318565f0dbda6ffb6a8'

// 加密内容
$content = 'b4358f5860343dbf2089ba75ee55deca8d922a069413f39cb3f8b64c01048c780ba5f03290642505d65d79c59684d76cf42443047f547c9f29dc2a49f872a2719ce00539058ab1fb5830e8e0c10144b574a87118390baa765b3429ba7afe5d28';

$sm4 = new \SM4Util();
$decryptedContent = $sm4->setKey($key)->decrypt($content);
var_dump($decryptedContent);
```

解密结果
```json
{
    "name": "tinywan",
    "age": 24,
    "github": {
        "url": "https://github.com/tinywan",
        "start": 2000
    }
}
```

## 引用文献

1. [《PHP实现国密算法SM4》](https://blog.csdn.net/liangxun0712/article/details/78611082)

2. [《关于PKCS5Padding与PKCS7Padding的区别》](https://blog.csdn.net/zsy19881226/article/details/46928177?utm_source=blogxgwz0)