import java.security.MessageDigest;

public class SHA {
    public static void main(String[] args) {
        String message = "hello";
        System.out.println("SHA-256: " + getSHA256(message));
        System.out.println("SHA-512: " + getSHA512(message));
    }

    /**
     * 获取 SHA-256 摘要信息
     *
     * @param message 原文
     * @return 摘要信息
     */
    public static String getSHA256(String message) {
        return getSHA(message, "SHA-256");
    }

    /**
     * 获取 SHA-512 摘要信息
     *
     * @param message 原文
     * @return 摘要信息
     */
    public static String getSHA512(String message) {
        return getSHA(message, "SHA-512");
    }


    /**
     * 获取 SHA 摘要信息
     *
     * @param message 原文
     * @param type    SHA 摘要类型
     * @return 摘要信息
     */
    public static String getSHA(String message, String type) {
        String hashMessage = null;
        if (message != null && message.length() > 0) {
            try {
                // 创建哈希对象，并传入哈希类型
                MessageDigest messageDigest = MessageDigest.getInstance(type);
                // 传入字符串
                messageDigest.update(message.getBytes());
                // 得到 byte[] 类型结果
                byte[] digest = messageDigest.digest();
                // 將 byte[] 转化为 String
                StringBuilder hexString = new StringBuilder();
                for (byte b : digest) {
                    String hex = Integer.toHexString(0xff & b);
                    if (hex.length() == 1) {
                        hexString.append('0');
                    }
                    hexString.append(hex);
                }
                hashMessage = hexString.toString();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return hashMessage;
    }
}
