import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;

public class FileEncrypt {
    public static void main(String[] args) {
        // 秘钥
        String key = "12345678";
        // 加密图片
        // encryptFileByDES("src/sources/test.png", key);
        // decryptFileByDES("src/sources/encryptImg.png", key);
        // 加密文本
        encryptFileByDES("src/sources/test.txt", key);
        decryptFileByDES("src/sources/encryptTxt.txt", key);
    }

    /**
     * 通过字节读取文件
     *
     * @param filePath 文件路径
     * @return 比特数组
     */
    public static byte[] readFileByBytes(String filePath) {
        try {
            File file = new File(filePath);
            InputStream inputStream = new FileInputStream(file);
            byte[] bytes = new byte[(int) file.length()];
            // byte[] b = new byte[1024];
            inputStream.read(bytes);
            // int length = inputStream.read(b);
            inputStream.close();
            // System.out.println(new String(b, 0, length));
            return bytes;
            // System.out.println(new String(bytes));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 使用DES加密图片
     *
     * @param filePath 待加密图片路径
     * @param key      秘钥
     */
    public static void encryptFileByDES(String filePath, String key) {
        byte[] fileBytes = readFileByBytes(filePath);
        try {
            Cipher cipher = Cipher.getInstance("DES");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "DES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            byte[] encryptBytes = cipher.doFinal(fileBytes);
            File file = new File("src/sources/encryptTxt.txt");
            FileOutputStream fileOutputStream = new FileOutputStream(file);
            fileOutputStream.write(encryptBytes);
            fileOutputStream.flush();
            fileOutputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 使用DES解密图片
     *
     * @param filePath 待解密图片路径
     * @param key      秘钥
     */
    public static void decryptFileByDES(String filePath, String key) {
        byte[] fileBytes = readFileByBytes(filePath);
        try {
            Cipher cipher = Cipher.getInstance("DES");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "DES");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            byte[] decryptBytes = cipher.doFinal(fileBytes);
            File file = new File("src/sources/decryptTxt.txt");
            FileOutputStream fileOutputStream = new FileOutputStream(file);
            fileOutputStream.write(decryptBytes);
            fileOutputStream.flush();
            fileOutputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
