package example;

import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class Main {

    val digestName = "md5";
    val digestPassword = "HG58YZ3CR9";

    @Throws(Exception::class)
    fun setupSecretKey(): SecretKey  {
        val md = MessageDigest.getInstance(digestName);
        val digestOfPassword = md.digest(digestPassword.toByteArray());
        val keyBytes = Arrays.copyOf(digestOfPassword, 24);
        for ( j in 0..7 ) {
            keyBytes[j+16] = keyBytes[j];
        }

        return SecretKeySpec(keyBytes, "DESede");
    }

    @Throws(Exception::class)
    fun setupCipher(optMode: Int): Cipher {
      val key = setupSecretKey();
      val iv = IvParameterSpec(ByteArray(8));
      val cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
      cipher.init(optMode, key, iv);
      return cipher;
    }

    @Throws(Exception::class)
    fun encrypt(message: String): ByteArray {
        val cipher = setupCipher(Cipher.ENCRYPT_MODE);

        val plainTextBytes = message.toByteArray()
        val cipherText = cipher.doFinal(plainTextBytes);

        return cipherText;
    }

    @Throws(Exception::class)
    fun decrypt(message: ByteArray): String {
        val decipher = setupCipher(Cipher.DECRYPT_MODE);

        val plainText = decipher.doFinal(message);

        return String(plainText);
    }
}

@Throws(Exception::class)
fun main(args: Array<String>) {

    val text = "password";
    val m = Main()
    val codedtext = m.encrypt(text);
    val decodedtext = m.decrypt(codedtext);

    println("Orignal: " + text);
    println("Encrypted: " + codedtext); // this is a byte array, you'll just see a reference to an array
    println("Decrypted: " + decodedtext); // This correctly shows "kyle boon"
}
