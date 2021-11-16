import java.security.MessageDigest;

public class MD5 {
    public static void main(String[] args) {
        String message = "hello";
        System.out.println("MD5: " + getMD5(message));
    }


    /**
     * 获取消息的 MD5 值
     *
     * @param message 消息
     * @return 消息的 MD5 值
     */
    public static String getMD5(String message) {
        String hashMessage = null;
        if (message != null && message.length() > 0) {
            try {
                MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                messageDigest.update(message.getBytes());
                byte[] digest = messageDigest.digest();
                StringBuilder stringBuilder = new StringBuilder();
                for (byte b : digest) {
                    String hexString = Integer.toHexString(0xff & b);
                    if (hexString.length() == 1) {
                        stringBuilder.append("0");
                    }
                    stringBuilder.append(hexString);
                }
                hashMessage = stringBuilder.toString();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return hashMessage;
    }
}
