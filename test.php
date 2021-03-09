<?php
require_once 'SM4.php';
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
$content = json_encode($content,JSON_HEX_QUOT);
$sm4 = new SM4($key);
$encryptContent = $sm4->encrypt($content);
var_dump($encryptContent);

// 开始解密
$decryptedJsonContent = $sm4->decrypt($encryptContent);
var_dump($decryptedJsonContent);
$decryptedArrContent = json_decode($decryptedJsonContent,true);
print_r($decryptedArrContent);
