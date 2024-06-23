package com.android.certificate;

import com.android.architecture.utils.AppUtils;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;

import javax.security.cert.X509Certificate;

/**
 * File describe:
 * Author: SuQi
 * Create date: 2023/5/9
 * Modify date: 2023/5/9
 * Version: 1
 */
public class CertificateHelper {

    public static X509Certificate getCAX509Certificate(String assetsPath, String alias, String password) {
        X509Certificate caX509Cert = null;
        try {
            Certificate cert = getCertsFromBKS(assetsPath, alias, password);
            if (cert != null) {
                caX509Cert = X509Certificate.getInstance(cert.getEncoded());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return caX509Cert;
    }

    public static Certificate getCertsFromBKS(String assetsPath, String alias, String password) {
        Certificate cert = null;
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            InputStream inputStream = AppUtils.getApp().getAssets().open(assetsPath);
            keyStore.load(inputStream, password.toCharArray());
            cert = keyStore.getCertificate(alias);
            System.out.println("Certificate: " + cert);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return cert;
    }

}
