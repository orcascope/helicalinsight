package com.helicalinsight.auth.customAuth;

import java.io.IOException;
import org.apache.commons.codec.binary.Base64;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import java.io.InputStream;
import java.util.Properties;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

public class CipherUtils
{
    static Properties prop;
    static InputStream input;
    static String key;
    static String algorithm;
    static String mode;
    static String padding;
    private static final Logger logger;

    static {
        CipherUtils.prop = new Properties();
        CipherUtils.input = CipherUtils.class.getResourceAsStream("/customAuthentication.properties");
        CipherUtils.key = null;
        CipherUtils.algorithm = null;
        CipherUtils.mode = null;
        CipherUtils.padding = null;
        logger = LoggerFactory.getLogger((Class) CipherUtils.class);
    }

    public static String encrypt(final String strToEncrypt) throws IOException {
        try {
            CipherUtils.input = CipherUtils.class.getResourceAsStream("/customAuthentication.properties");
            CipherUtils.prop.load(CipherUtils.input);
            CipherUtils.key = CipherUtils.prop.getProperty("cipherKey");
            CipherUtils.algorithm = CipherUtils.prop.getProperty("cipherAlgorithm");
            CipherUtils.mode = CipherUtils.prop.getProperty("cipherMode");
            CipherUtils.padding = CipherUtils.prop.getProperty("cipherPadding");
            final Cipher cipher = Cipher.getInstance(String.valueOf(CipherUtils.algorithm) + "/" + CipherUtils.mode + "/" + CipherUtils.padding);
            final SecretKeySpec secretKey = new SecretKeySpec(CipherUtils.key.getBytes(), CipherUtils.algorithm);
            cipher.init(1, secretKey);
            final String encryptedString = Base64.encodeBase64URLSafeString(cipher.doFinal(strToEncrypt.getBytes()));
            return encryptedString;
        }
        catch (Exception e) {
            e.printStackTrace();
            CipherUtils.input.close();
            return null;
        }
    }

    public static String decrypt(final String strToDecrypt) {
        try {
            CipherUtils.input = CipherUtils.class.getResourceAsStream("/customAuthentication.properties");
            CipherUtils.prop.load(CipherUtils.input);
            CipherUtils.key = CipherUtils.prop.getProperty("cipherKey");
            CipherUtils.algorithm = CipherUtils.prop.getProperty("cipherAlgorithm");
            CipherUtils.mode = CipherUtils.prop.getProperty("cipherMode");
            CipherUtils.padding = CipherUtils.prop.getProperty("cipherPadding");
            CipherUtils.logger.debug("customAuthentication.properties " + CipherUtils.input  + "  strToDecrypt  "+ strToDecrypt) ;
            CipherUtils.logger.debug("cipher key " + CipherUtils.prop.getProperty("cipherKey"));
            final Cipher cipher = Cipher.getInstance(String.valueOf(CipherUtils.algorithm) + "/" + CipherUtils.mode + "/" + CipherUtils.padding);
            final SecretKeySpec secretKey = new SecretKeySpec(CipherUtils.key.getBytes(), CipherUtils.algorithm);
            cipher.init(2, secretKey);
            final String decryptedString = new String(cipher.doFinal(Base64.decodeBase64(strToDecrypt)));
            CipherUtils.logger.debug("decryptedString " + decryptedString );
            return decryptedString;
        }
        catch (Exception e) {
            CipherUtils.logger.error("Decrypt exception");
            e.printStackTrace();
            return null;
        }
    }
}
