import com.sun.org.apache.xml.internal.security.utils.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;


public class DES {
    public static void main(String[] args) {
        // 明文
        String message = "Hello World!";
        // 秘钥，使用DES加密时，必须为8位
        String key = "12345678";
        String encryptText = encrypt(message, key);
        System.out.println("密文：" + encryptText);
        String decryptText = decrypt(encryptText, key);
        System.out.println("明文：" + decryptText);
    }

    /**
     * 加密
     *
     * @param message 明文
     * @param key     秘钥
     * @return 密文
     */
    public static String encrypt(String message, String key) {
        try {
            // 创建加密对象
            Cipher cipher = Cipher.getInstance("DES");
            // 创建加密规则，第一个参数表示key的字节码，第二个参数表示加密类型
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "DES");
            // 进行加密初始化，第一个参数表示加密模式，第二个参数表示加密规则
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            // 调用加密方法，参数表示明文的字节码
            byte[] cipherBytes = cipher.doFinal(message.getBytes());
            // 创建Base64对象，注意导入Apache的包
            return Base64.encode(cipherBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    /**
     * 解密
     *
     * @param encryptText 密文
     * @param key         秘钥
     * @return 明文
     */
    public static String decrypt(String encryptText, String key) {
        try {
            // 创建解密对象
            Cipher cipher = Cipher.getInstance("DES");
            // 创建解密规则，第一个参数表示秘钥的字节码，第二个参数表示解密类型
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "DES");
            // 进行解密初始化，第一个参数表示解密模式，第二个参数表示解密规则
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            // 调用解密方法，参数表示密文的字节码
            byte[] decryptBytes = cipher.doFinal(Base64.decode(encryptText));
            return new String(decryptBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
