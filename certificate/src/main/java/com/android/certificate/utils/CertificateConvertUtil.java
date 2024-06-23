package com.android.certificate.utils;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Enumeration;

/**
 * File describe:
 * Author: SuQi
 * Create date: 2023/5/10
 * Modify date: 2023/5/10
 * Version: 1
 */
public class CertificateConvertUtil {

    public static final String PKCS12 = "PKCS12";
    public static final String JKS = "JKS";

    /**
     * pkcs12 转 jks
     *
     * @param input_keystore_file  pkcs12证书路径
     * @param keystore_password    pkcs12证书密钥库口令
     * @param output_keystore_file jks证书路径
     */
    public static void PKCS12ToJKS(String input_keystore_file,
                                   String keystore_password, String output_keystore_file) {
        try {
            KeyStore inputKeyStore = KeyStore.getInstance(PKCS12);
            FileInputStream fis = new FileInputStream(input_keystore_file);

            char[] nPassword = null;
            if (keystore_password != null && !keystore_password.trim().equals("")) {
                nPassword = keystore_password.toCharArray();
            }
            inputKeyStore.load(fis, nPassword);
            fis.close();

            System.out.println("keystore type=" + inputKeyStore.getType());

            KeyStore outputKeyStore = KeyStore.getInstance(JKS);
            outputKeyStore.load(null, nPassword);

            Enumeration<String> enums = inputKeyStore.aliases();
            while (enums.hasMoreElements()) {
                String keyAlias = enums.nextElement();
                System.out.println("alias=[" + keyAlias + "]");

                if (inputKeyStore.isKeyEntry(keyAlias)) {
                    Key key = inputKeyStore.getKey(keyAlias, nPassword);
                    Certificate[] certChain = inputKeyStore.getCertificateChain(keyAlias);
                    outputKeyStore.setKeyEntry(keyAlias, key, nPassword, certChain);
                }
                FileOutputStream out = new FileOutputStream(output_keystore_file);
                outputKeyStore.store(out, nPassword);
                out.close();
                outputKeyStore.deleteEntry(keyAlias);

                System.out.println("convert is finished!");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    /**
     * jks 转 pkcs12
     *
     * @param input_keystore_file  jks证书路径
     * @param keystore_password    jks证书密钥库口令
     * @param output_keystore_file pkcs12证书路径
     */
    public static void JKSToPKCS12(String input_keystore_file,
                                   String keystore_password, String output_keystore_file) {
        try {
            KeyStore inputKeyStore = KeyStore.getInstance(JKS);
            FileInputStream fis = new FileInputStream(input_keystore_file);

            char[] nPassword = null;
            if (keystore_password != null && !keystore_password.trim().equals("")) {
                nPassword = keystore_password.toCharArray();
            }

            inputKeyStore.load(fis, nPassword);
            fis.close();

            System.out.println("keystore type=" + inputKeyStore.getType());

            KeyStore outputKeyStore = KeyStore.getInstance(PKCS12);
            outputKeyStore.load(null, nPassword);

            Enumeration<String> enums = inputKeyStore.aliases();
            while (enums.hasMoreElements()) {

                String keyAlias = enums.nextElement();
                System.out.println("alias=[" + keyAlias + "]");

                if (inputKeyStore.isKeyEntry(keyAlias)) {
                    Key key = inputKeyStore.getKey(keyAlias, nPassword);
                    Certificate[] certChain = inputKeyStore.getCertificateChain(keyAlias);
                    outputKeyStore.setKeyEntry(keyAlias, key, nPassword, certChain);
                }
                FileOutputStream out = new FileOutputStream(output_keystore_file);
                outputKeyStore.store(out, nPassword);
                out.close();
                outputKeyStore.deleteEntry(keyAlias);
                System.out.println("convert is finished!");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        CertificateConvertUtil.JKSToPKCS12("/mine2.keystore",
                "123456", "/mine2.pfx");
    }

}
