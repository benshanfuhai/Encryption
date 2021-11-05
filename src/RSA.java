import com.sun.org.apache.xml.internal.security.utils.Base64;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class RSA {
    /**
     * 秘钥长度
     */
    private final static int KEY_SIZE = 512;

    /**
     * 封装随机产生的公钥与私钥
     */
    private final static Map<String, String> keyMap = new HashMap<>();

    /**
     * 随机生成密钥对
     */
    public static void genKeyPair() {
        try {
            // KeyPairGenerator用于生成公私钥对，基于RSA算法生成对象
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            // 初始化密钥对生成器
            keyPairGenerator.initialize(KEY_SIZE, new SecureRandom());
            // 生成一个秘钥对，保存在keyPair中
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            // 获取公钥
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            String publicKeyString = Base64.encode(publicKey.getEncoded());
            // 获取私钥
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            String privateKeyString = Base64.encode(privateKey.getEncoded());
            // 保存到keyMap中
            keyMap.put("publicKey", publicKeyString);
            keyMap.put("privateKey", privateKeyString);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    /**
     * 公钥加密
     *
     * @param message   明文
     * @param publicKey 公钥
     * @return 公钥加密密文
     */
    public static String encryptByPublicKey(String message, String publicKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            byte[] publicKeyBytes = Base64.decode(publicKey.getBytes());
            RSAPublicKey rsaPublicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
            cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
            byte[] encryptBytes = cipher.doFinal(message.getBytes());
            return Base64.encode(encryptBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 私钥签名
     *
     * @param message    明文
     * @param privateKey 私钥
     * @return 私钥签名密文
     */
    public static String encryptByPrivateKey(String message, String privateKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            byte[] privateKeyBytes = Base64.decode(privateKey.getBytes());
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
            cipher.init(Cipher.ENCRYPT_MODE, rsaPrivateKey);
            byte[] encryptBytes = cipher.doFinal(message.getBytes());
            return Base64.encode(encryptBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 公钥验签
     *
     * @param encryptTextByPrivateKey 待验证的密文
     * @param publicKey               公钥
     * @return 公钥验签明文
     */
    public static String decryptByPublicKey(String encryptTextByPrivateKey, String publicKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            byte[] publicKeyBytes = Base64.decode(publicKey.getBytes());
            RSAPublicKey rsaPublicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
            cipher.init(Cipher.DECRYPT_MODE, rsaPublicKey);
            byte[] encryptBytesByPrivateKey = Base64.decode(encryptTextByPrivateKey.getBytes());
            byte[] decryptBytesByPublicKey = cipher.doFinal(encryptBytesByPrivateKey);
            return new String(decryptBytesByPublicKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 私钥解密
     *
     * @param encryptTextByPublicKey 公钥加密密文
     * @param privateKey             私钥
     * @return 私钥解密明文
     */
    public static String decryptByPrivateKey(String encryptTextByPublicKey, String privateKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            byte[] privateKeyBytes = Base64.decode(privateKey.getBytes());
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
            cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
            byte[] encryptBytesByPublicKey = Base64.decode(encryptTextByPublicKey.getBytes());
            byte[] decryptBytesByPrivateKey = cipher.doFinal(encryptBytesByPublicKey);
            return new String(decryptBytesByPrivateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        String message = "Hello World!";
        genKeyPair();
        String publicKey = keyMap.get("publicKey");
        String privateKey = keyMap.get("privateKey");
        String encryptTextByPublicKey = encryptByPublicKey(message, publicKey);
        System.out.println("公钥加密密文：" + encryptTextByPublicKey);
        String decryptTextByPrivateKey = decryptByPrivateKey(encryptTextByPublicKey, privateKey);
        System.out.println("私钥解密明文：" + decryptTextByPrivateKey);
        System.out.println();
        String encryptTextByPrivateKey = encryptByPrivateKey(message, privateKey);
        System.out.println("私钥签名密文：" + encryptTextByPrivateKey);
        String decryptTextByPublicKey = decryptByPublicKey(encryptTextByPrivateKey, publicKey);
        System.out.println("公钥验签明文：" + decryptTextByPublicKey);
    }
}
