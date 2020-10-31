import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

/**
 * @description:SM4Example
 */
public class SM4Example {
    private static final String ENCODING = "UTF-8";
    /* 初始 */
    private static final String KEY = "35d251411ea04318565f0dbda6ffb6a8";
    public static final String ALGORIGTHM_NAME = "SM4";
    public static final String ALGORITHM_NAME_ECB_PADDING = "SM4/ECB/PKCS7Padding";
    public static final int DEFAULT_KEY_SIZE = 128;

    public SM4Example() {
    }

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * @Description:生成ecb暗号
     */
    private static Cipher generateEcbCipher(String algorithmName, int mode, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithmName, BouncyCastleProvider.PROVIDER_NAME);
        Key sm4Key = new SecretKeySpec(key, ALGORIGTHM_NAME);
        cipher.init(mode, sm4Key);
        return cipher;
    }

    /**
     * @Description:自动生成密钥
     */
    public static byte[] generateKey() throws Exception {
        return generateKey(DEFAULT_KEY_SIZE);
    }

    public static byte[] generateKey(int keySize) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance(ALGORIGTHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        kg.init(keySize, new SecureRandom());
        return kg.generateKey().getEncoded();
    }

    /**
     * @Description:加密
     */
    public static String encryptEcb(String paramStr) throws Exception {
        return encryptEcb(paramStr, null);
    }

    /**
     * @Description:加密
     */
    public static String encryptEcb(String paramStr, String key) throws Exception {
        String cipherText = "";
        if (null != paramStr && !"".equals(paramStr)) {
            byte[] keyData = ByteUtils.fromHexString(key == null ? KEY : key);
            byte[] srcData = paramStr.getBytes(ENCODING);
            byte[] cipherArray = encrypt_Ecb_Padding(keyData, srcData);
            cipherText = ByteUtils.toHexString(cipherArray);
        }
        return cipherText;
    }

    /**
     * @Description:加密模式之ecb
     */
    public static byte[] encrypt_Ecb_Padding(byte[] key, byte[] data) throws Exception {
        Cipher cipher = generateEcbCipher(ALGORITHM_NAME_ECB_PADDING, Cipher.ENCRYPT_MODE, key);
        byte[] bs = cipher.doFinal(data);
        return bs;
    }

    /**
     * @Description:sm4解密
     */
    public static String decryptEcb(String cipherText) throws Exception {
        return decryptEcb(cipherText, null);
    }

    /**
     * @Description:sm4解密
     */
    public static String decryptEcb(String cipherText, String key) throws Exception {
        String decryptStr = "";
        byte[] keyData = ByteUtils.fromHexString(key == null ? KEY : key);
        byte[] cipherData = ByteUtils.fromHexString(cipherText);
        byte[] srcData = decrypt_Ecb_Padding(keyData, cipherData);
        decryptStr = new String(srcData, ENCODING);
        return decryptStr;
    }

    /**
     * @Description:解密
     */
    public static byte[] decrypt_Ecb_Padding(byte[] key, byte[] cipherText) throws Exception {
        Cipher cipher = generateEcbCipher(ALGORITHM_NAME_ECB_PADDING, Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(cipherText);
    }

    /**
     * @Description:密码校验
     */
    public static boolean verifyEcb(String cipherText, String paramStr) throws Exception {
        boolean flag = false;
        byte[] keyData = ByteUtils.fromHexString(KEY);
        byte[] cipherData = ByteUtils.fromHexString(cipherText);
        byte[] decryptData = decrypt_Ecb_Padding(keyData, cipherData);
        byte[] srcData = paramStr.getBytes(ENCODING);
        flag = Arrays.equals(decryptData, srcData);
        return flag;
    }

    /**
     * @Description:测试类
     */
    public static void main(String[] args) {
        try {
            String str = "Hi Java Tinywan";
            String key = "35d251411ea04318565f0dbda6ffb6a8";
            String cipher1 = SM4Example.encryptEcb(str, key);
            System.out.println("key：" + key);
            System.out.println("明文：" + str);
            System.out.println("密文：" + cipher1);
            System.out.println("解密：" + SM4Example.decryptEcb(cipher1, key));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
