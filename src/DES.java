import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.security.SecureRandom;

public class DES {
    public static void main(String[] args) {
        String message = "Hello World!";
        String key = "12345678";
        System.out.println("明文：" + message);
        String ciphertext = encrypt(message, key);
        System.out.println("密文：" + ciphertext);
        System.out.println("明文：" + decrypt(ciphertext, key));

    }

    /**
     * 基本数据加密
     *
     * @param message 明文
     * @param key     秘钥
     * @return 加密后的结果
     */
    public static String encrypt(String message, String key) {
        if (message.isEmpty() || key.isEmpty()) {
            return null;
        }
        try {
            byte[] byteMessage = encrypt(message.getBytes(), key.getBytes());
            return new BASE64Encoder().encode(byteMessage);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 基于字节加密
     *
     * @param message 明文
     * @param key     秘钥
     * @return 加密后的结果
     */
    public static byte[] encrypt(byte[] message, byte[] key) throws Exception {
        // 产生可信任的随机数源
        SecureRandom secureRandom = new SecureRandom();
        // 基于密钥数据创建DESKeySpec对象
        DESKeySpec desKeySpec = new DESKeySpec(key);
        // 创建密钥工厂，将DESKeySpec转换成SecretKey对象来保存对称密钥
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = secretKeyFactory.generateSecret(desKeySpec);
        // Cipher实际完成加密操作，指定其加密算法
        Cipher cipher = Cipher.getInstance("DES");
        // 初始化Cipher对象，ENCRYPT_MODE表示加密
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, secureRandom);
        // 加密
        return cipher.doFinal(message);
    }

    /**
     * 基本数据解密
     *
     * @param ciphertext 密文
     * @param key        秘钥
     * @return 解密后的结果
     */
    public static String decrypt(String ciphertext, String key) {
        if (ciphertext.isEmpty() || key.isEmpty()) {
            return null;
        }
        try {
            BASE64Decoder base64Decoder = new BASE64Decoder();
            byte[] bufCiphertext = base64Decoder.decodeBuffer(ciphertext);
            byte[] message = decrypt(bufCiphertext, key.getBytes());
            return new String(message);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    /**
     * 基于字节解密
     *
     * @param ciphertext 密文
     * @param key        秘钥
     * @return 加密后的结果
     * @throws Exception 各种异常
     */
    public static byte[] decrypt(byte[] ciphertext, byte[] key) throws Exception {
        // 产生可信任的随机数源
        SecureRandom secureRandom = new SecureRandom();
        // 基于密钥数据创建DESKeySpec对象
        DESKeySpec desKeySpec = new DESKeySpec(key);
        // 创建密钥工厂，将DESKeySpec转换成SecretKey对象来保存对称密钥
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = secretKeyFactory.generateSecret(desKeySpec);
        // Cipher实际完成加密操作，指定其解密算法
        Cipher cipher = Cipher.getInstance("DES");
        // 初始化Cipher对象，DECRYPT_MODE表示解密
        cipher.init(Cipher.DECRYPT_MODE, secretKey, secureRandom);
        // 解密
        return cipher.doFinal(ciphertext);
    }
}
