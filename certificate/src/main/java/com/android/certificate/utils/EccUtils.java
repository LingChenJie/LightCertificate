package com.android.certificate.utils;

import com.android.architecture.utils.Base64Utils;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;

/**
 * File describe:
 * Author: SuQi
 * Create date: 2023/3/27
 * Modify date: 2023/3/27
 * Version: 1
 */
public class EccUtils {

    /**
     * @ org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi.ecParameters (line #173)
     * 192, 224, 239, 256, 384, 521
     */
    private final static int KEY_SIZE = 521;//bit
    private final static String SIGNATURE = "SHA256withECDSA";

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    //生成秘钥对
    public static KeyPair getKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");//BouncyCastle
        keyPairGenerator.initialize(KEY_SIZE, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    //获取公钥(Base64编码)
    public static String getPublicKey(KeyPair keyPair) {
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        byte[] bytes = publicKey.getEncoded();
        return Base64Utils.encode(bytes);
    }

    //获取私钥(Base64编码)
    public static String getPrivateKey(KeyPair keyPair) {
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        byte[] bytes = privateKey.getEncoded();
        return Base64Utils.encode(bytes);
    }

    //公钥加密
    public static byte[] encrypt(byte[] content, ECPublicKey pubKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        return cipher.doFinal(content);
    }

    //私钥解密
    public static byte[] decrypt(byte[] content, ECPrivateKey priKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, priKey);
        return cipher.doFinal(content);
    }

    //私钥签名
    public static byte[] sign(String content, ECPrivateKey priKey) throws Exception {
        //这里可以从证书中解析出签名算法名称
        //Signature signature = Signature.getInstance(getSigAlgName(pubCert));
        Signature signature = Signature.getInstance(SIGNATURE);//"SHA256withECDSA"
        signature.initSign(priKey);
        signature.update(content.getBytes());
        return signature.sign();
    }

    //公钥验签
    public static boolean verify(String content, byte[] sign, ECPublicKey pubKey) throws Exception {
        //这里可以从证书中解析出签名算法名称
        //Signature signature = Signature.getInstance(getSigAlgName(priCert));
        Signature signature = Signature.getInstance(SIGNATURE);//"SHA256withECDSA"
        signature.initVerify(pubKey);
        signature.update(content.getBytes());
        return signature.verify(sign);
    }

    /**
     * 解析证书的签名算法，单独一本公钥或者私钥是无法解析的，证书的内容远不止公钥或者私钥
     */
    private static String getSigAlgName(File certFile) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate x509Certificate = (X509Certificate) cf.generateCertificate(new FileInputStream(certFile));
        return x509Certificate.getSigAlgName();
    }


    public static void main(String[] args) {
//        printProvider();
        try {
            KeyPair keyPair = getKeyPair();
            ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
            ECPrivateKey priKey = (ECPrivateKey) keyPair.getPrivate();
            System.out.println("[pubKey]:\n" + getPublicKey(keyPair));
            System.out.println("[priKey]:\n" + getPrivateKey(keyPair));

            //测试文本
            String content = "abcdefg";

            //加密
            byte[] cipherTxt = encrypt(content.getBytes(), pubKey);
            //解密
            byte[] clearTxt = decrypt(cipherTxt, priKey);
            //打印
            System.out.println("content:" + content);
            System.out.println("cipherTxt[" + cipherTxt.length + "]:" + new String(cipherTxt));
            System.out.println("clearTxt:" + new String(clearTxt));

            //签名
            byte[] sign = sign(content, priKey);
            //验签
            boolean ret = verify(content, sign, pubKey);
            //打印
            System.out.println("content:" + content);
            System.out.println("sign[" + sign.length + "]:" + new String(sign));
            System.out.println("verify:" + ret);

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("[main]-Exception:" + e.toString());
        }

    }


    private static void printProvider() {
        Provider provider = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        for (Provider.Service service : provider.getServices()) {
            System.out.println(service.getType() + ": "
                    + service.getAlgorithm());
        }
    }

}