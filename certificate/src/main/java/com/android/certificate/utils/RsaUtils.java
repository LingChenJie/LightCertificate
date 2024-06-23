package com.android.certificate.utils;

import com.android.architecture.utils.Base64Utils;
import com.android.architecture.utils.ByteUtil;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

/**
 * File describe:
 * Author: SuQi
 * Create date: 2022/12/7
 * Modify date: 2022/12/7
 * Version: 1
 */
public class RsaUtils {

    private static final String TAG = RsaUtils.class.getSimpleName();

    public static final String RSA = "RSA";
    public static final int DEFAULT_KEY_SIZE = 2048;
    public static final String ECB_NO_PADDING = "RSA/ECB/NoPadding";
    public static final String ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";
    public static final String ECB_PKCS5_PADDING = "RSA/ECB/PKCS5Padding";
    public static final String ECB_PKCS7_PADDING = "RSA/ECB/PKCS7Padding";
    public static final String NONE_OAEP_PADDING = "RSA/NONE/OAEPPadding";
    // 当前秘钥支持加密的最大字节数
    public static final int DEFAULT_BUFFER_SIZE = (DEFAULT_KEY_SIZE / 8) - 11;

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            System.out.println("security provider BC not found");
            Security.addProvider(new BouncyCastleProvider());
        }
    }


    /**
     * generateRSAKeyPair
     *
     * @param keyLength 1028/2048
     * @return
     */
    public static KeyPair generateRSAKeyPair(int keyLength) {
        try {
            KeyPairGenerator generator;
            generator = KeyPairGenerator.getInstance(RSA);
            generator.initialize(keyLength);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] getPublicKeyEncoded(KeyPair keyPair) {
        RSAPublicKey key = (RSAPublicKey) keyPair.getPublic();
        System.out.println("publicKey modules(N):" + key.getModulus().toString(16).toUpperCase());
        System.out.println("publicKey exponent(E):" + key.getPublicExponent().toString(16).toUpperCase());
        System.out.println("publicKey format:" + key.getFormat());
        return key.getEncoded();
    }

    public static byte[] getPrivateKeyEncoded(KeyPair keyPair) {
        RSAPrivateKey key = (RSAPrivateKey) keyPair.getPrivate();
        System.out.println("privateKey modules(N):" + key.getModulus().toString(16).toUpperCase());
        System.out.println("privateKey exponent(E):" + key.getPrivateExponent().toString(16).toUpperCase());
        System.out.println("privateKey format:" + key.getFormat());
        System.out.println("------------------");
        RSAPrivateCrtKey crtKey = (RSAPrivateCrtKey) key;
        System.out.println("privateKey P:" + crtKey.getPrimeP().toString(16).toUpperCase());
        System.out.println("privateKey Q:" + crtKey.getPrimeQ().toString(16).toUpperCase());
        System.out.println("privateKey D:" + crtKey.getPrivateExponent().toString(16).toUpperCase());
        System.out.println("privateKey DP:" + crtKey.getPrimeExponentP().toString(16).toUpperCase());
        System.out.println("privateKey DQ:" + crtKey.getPrimeExponentQ().toString(16).toUpperCase());
        System.out.println("privateKey QP:" + crtKey.getCrtCoefficient().toString(16).toUpperCase());
        System.out.println("------------------");
        return key.getEncoded();
    }

    /**
     * getPublicKey
     *
     * @param modulus        16进制
     * @param publicExponent 16进制
     * @return
     */
    public static byte[] getPublicKeyEncoded(String modulus, String publicExponent) {
        try {
            BigInteger bigIntModulus = new BigInteger(modulus, 16);
            BigInteger bigIntPublicExponent = new BigInteger(publicExponent, 16);
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(bigIntModulus, bigIntPublicExponent);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            PublicKey key = keyFactory.generatePublic(keySpec);
            return key.getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * getPrivateKey
     *
     * @param modulus         16进制
     * @param privateExponent 16进制
     * @return
     */
    public static byte[] getPrivateKeyEncoded(String modulus, String privateExponent) {
        try {
            BigInteger bigIntModulus = new BigInteger(modulus, 16);
            BigInteger bigIntPrivateExponent = new BigInteger(privateExponent, 16);
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(bigIntModulus, bigIntPrivateExponent);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            PrivateKey key = keyFactory.generatePrivate(keySpec);
            return key.getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * getPublicKey
     *
     * @param privateKeyEncoded 私钥
     * @return
     */
    public static byte[] getPublicKeyEncoded(byte[] privateKeyEncoded) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyEncoded);
            PrivateKey priKey = keyFactory.generatePrivate(keySpec);
            RSAPrivateKeySpec priv = keyFactory.getKeySpec(priKey, RSAPrivateKeySpec.class);
            RSAPublicKeySpec keySpec2 = new RSAPublicKeySpec(priv.getModulus(), BigInteger.valueOf(65537));
            PublicKey publicKey = keyFactory.generatePublic(keySpec2);
            return publicKey.getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * getPublicKey
     *
     * @param publicKeyEncoded 公钥编码
     * @return
     */
    public static RSAPublicKey getPublicKey(byte[] publicKeyEncoded) {
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyEncoded);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            PublicKey key = keyFactory.generatePublic(keySpec);
            return (RSAPublicKey) key;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * getPrivateKey
     *
     * @param privateKeyEncoded 私钥编码
     * @return
     */
    public static RSAPrivateKey getPrivateKey(byte[] privateKeyEncoded) {
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyEncoded);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            PrivateKey key = keyFactory.generatePrivate(keySpec);
            return (RSAPrivateKey) key;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 公钥加密
     *
     * @param publicKeyEncoded
     * @param data
     * @return
     */
    public static byte[] encryptByPublicKey(byte[] publicKeyEncoded, byte[] data) {
        try {
            RSAPublicKey key = getPublicKey(publicKeyEncoded);
            Cipher cipher = Cipher.getInstance(NONE_OAEP_PADDING);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] decryptByPrivateKey(byte[] privateKeyEncoded, byte[] data) {
        try {
            RSAPrivateKey key = getPrivateKey(privateKeyEncoded);
            Cipher cipher = Cipher.getInstance(NONE_OAEP_PADDING);
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
//        test();
//        test2();
//        test3();
        try {
            test4();
            test5();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void test() {
        KeyPair keyPair = generateRSAKeyPair(DEFAULT_KEY_SIZE);
        byte[] privateKey = getPrivateKeyEncoded(keyPair);
        byte[] publicKey = getPublicKeyEncoded(keyPair);
        System.out.println("------------------");
        System.out.println("------------------");
        System.out.println("privateKey(HEX):" + ByteUtil.bytes2HexStr(privateKey));
        System.out.println("publicKey(HEX):" + ByteUtil.bytes2HexStr(publicKey));

        byte[] data = ByteUtil.hexStr2Bytes("11223344556677881122334455667788");
        byte[] encryptResult = encryptByPublicKey(publicKey, data);
        System.out.println("------------------");
        System.out.println("encryptResult(HEX):" + ByteUtil.bytes2HexStr(encryptResult));

        byte[] decryptResult = decryptByPrivateKey(privateKey, encryptResult);
        System.out.println("------------------");
        System.out.println("decryptResult(HEX):" + ByteUtil.bytes2HexStr(decryptResult));
    }

    public static void test2() {
        String module = "c0301ed3994f78d29b5282230ca43b493d4a55f0daf5944369d4d5d2add167bc86b812b4c11a1b17a1ceaee39530ca05e67ef12bce88859d217311fff2db06684fe7aa400fbf4dfdb6ede6780ac277c01751a41d4c558ee9259236520e84d9a2f89530cd74c00f974c2ba3a1f85cb225e1792d81cee7af6f76d6b3edb5d9cc7fcc0d39000a7d997077b054ed1d6f753191804c3e8e0b26a64c7b9449f275e89248d917e788ee8f63bae94c235f85ac976c90e4a8894934bb721b04c2dff53dae9a2b42b642f9db2015ef2fc67412a7a48333c19d4f62ca6ed90de35db1249cac3a197d762c7ba4a0384a950e5f73ae472c7bd72ac4bf51276e4f5bef3b278b07";
        String exponent = "300f9895e7dff4e20e0f9b15b2c29b44dc7beb73f8fdb2df0ce739b59edc202a08329e12efbb5c8d135cc1658e588e1cdda05f254a57dfba04b4670aefab9035a3cdd64880e7a154525bb9e7c9210a9b51f98ba5fc01e5642e8e1ae1785a06a6f7ad2f7021c329e2f71c6ea6419ac4be2e5d8460d2e223802762d7ca1950e70f9acf9a9ae12206180553f8837e9cffa212bde1e209f49ed793cc2028bee76e5ce035f10dcf9f6ec3fea98fd2213883780a88847c7892a69b5382425bc1aef627c35b83d0a39902c9b89816b7c28cfbdf41625e57e74fbeb417425020d18eddca0ccb1f3740529e59adee1d38d3d93293665c9e7485f24c47bba7c2cd2ab52591";
        byte[] privateKey = getPrivateKeyEncoded(module, exponent);

        byte[] en = ByteUtil.hexStr2Bytes("124DCD2654F46B4296BE416D1B63568AF74A196DD2A2FB993AA6E3D024C6C95AD74F423FA9D48381C09A9807A285F4A37E8C9ABC3974FEF29294FD66563B3DAB8067FB20B3FA4326E806A009D879ED319AB63EDD0D2D8219AD17CF2BB8311A58EEDB29089352531AB93D85D1B7031352D2B5870C2179BE89A2412076E3C4B14492194DA0E838BC46FD4E8FB5139AD22FBB7B90C6C371B78B203448956D682AA8793D8C78FF61CCEB408DC1E516909D5C0F6AC5DD5CDC19687B58B7794003E1CE2118902633823C4EB320E8BA5AC2C48F0841FEB7FB171B59F73D7808E91E5FB59DD606CC215ECB269A91202A4401D91C256504BF260DDFF4C01524A43C1586C6");
        byte[] bytes = decryptByPrivateKey(privateKey, en);
        System.out.println("bytes:" + ByteUtil.bytes2HexStr(bytes));
    }

    public static void test3() {
        String publicKey = "30820122300D06092A864886F70D01010105000382010F003082010A0282010100F231050B587D6829370BC3A826E4B93A025BE7D068852CB8AE1E9BA828C69F8D082F6657F53DF393742576F71A2A4725275BCA6A010261484BB03057C09B1E8C30A3BD59A70717621AC9CE1E070737C6A0DE318961127D03EF076436EF4FB98E5C48BFAB12357BFE7340FAFCE4E80346E8CEEA616D36E51B31EDFFC95701A0DE833C615E55B38B7FAFA059AECBF4A74C1DC8337E4DA251EF1C14B0070D140E37778CCD5896BA4442FB2203650D638A5BD84E9181DC7E68F01D4A9C03BABC6682B123A54D9D6401A4DD37415E4EB3D3A163E085360C1F5F0225AB80DB62CC8E5EC0BA2FE400D393E1C722823C8553ABFAD0DEF72DED0A9CFFFF1CB21D498A45C50203010001";
        byte[] data = ByteUtil.hexStr2Bytes("11223344556677881122334455667799");
        byte[] encryptResult = encryptByPublicKey(ByteUtil.hexStr2Bytes(publicKey), data);
        System.out.println("encryptResult:" + ByteUtil.bytes2HexStr(encryptResult));
    }

    public static void test4() throws CertificateException {
        String certificateBase64Str = "MIIC0DCCAbigAwIBAgIIAJvBVAAAEpMwDQYJKoZIhvcNAQELBQAwLjELMAkGA1UE" +
                "BhMCUFQxHzAdBgNVBAMMFk1ORlN1YkNBIERldmljZSBTaWduZXIwHhcNMTgwNjE1" +
                "MDAwMDAwWhcNMTkwNjE1MDAwMDAwWjAiMQswCQYDVQQGEwJQVDETMBEGA1UEAwwK" +
                "RGV2S2V5UGFpcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL0mq7LY" +
                "Vj1cyKwKQlWUvIHcLg/i9mgn/V8CNcXfqoeRTlo4n2Rqwor1wDxPe2xDQauq8Y1z" +
                "HKGPXuECULlyokr8GA7BKGPru4bsX+WjI1kR1uiBIVbUGVEBTS/BL8k1MVRL6ON7" +
                "Vo/v9rixg8Rb0lOhZH9wr8Lr0kzBo7PcU1kR9hkuapL0oe6AVODGWnwEnBn7mDGC" +
                "17cgX3QinWnOUQNkrYaMtu4FcSL30omXZjO8wknfwiu6I40zsaSgJmpznf8jeI+4" +
                "cSg+loIyp+E4PYM57QvoJu9govIR9F4sVAblpsJdrB5X9v0TO+9SXS7bhG4BODMQ" +
                "ssCDwYbaGw4f4iECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAi4NjsZAEHXLK6mOh" +
                "GgkI7dFYKQN8l+N7IwwqAwaj0QumXd4e6V8OxAD5QbnIP+JNaVeinRCYfeEsg+bx" +
                "mRmKIOEjLzZwkZo6BoF7JiCfSKpoi0+1gWSr2E+zu4YMu3KzyhQGio/oZg9jDhTn" +
                "9uXShDtnQs3slqbsjqTSBoxpO1449IOnsXJPZbupCM3LUhtEUjNscO0nQlW2Z4nC" +
                "+rFzOssOJwfmsIl5TGtM1Fg8hla6/VBORvSi8eZMLeGfelOLaGAYAqDd4olXyBQP" +
                "cZw7+Beq0rWCxEQ0CVrujnKWPJu0OyMMhiQHtapDPi52s6tI4abSdqGHwuNJvRyy" +
                "NyWaWA==";
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = certificateFactory.generateCertificate(new ByteArrayInputStream(Base64Utils.decode(certificateBase64Str)));
        X509Certificate x509Certificate = (X509Certificate) certificate;
        System.out.println("x509Certificate : " + x509Certificate.toString());

        String publicKeyBase64Str = Base64Utils.encode(x509Certificate.getPublicKey().getEncoded());
        System.out.println("publicKeyBase64: " + publicKeyBase64Str);

        byte[] data = ByteUtil.hexStr2Bytes("A75AA4576271BEB57EC1B845FCCF1AC4");
        byte[] encryptResult = encryptByPublicKey(x509Certificate.getPublicKey().getEncoded(), data);
        System.out.println("encryptResult:" + ByteUtil.bytes2HexStr(encryptResult));
    }

    public static void test5() {
        String data = "BA64D05DB" +
                "BF2E1E5A8D98DF53B8DDDE28C630A59662DE05BD83F1EBB54744710E96F6B0AD9046D0CBA23086122" +
                "D05DFD4D46FCFE4D5C0A1D06214615920C1B3848D2F7B05E88F2FE7C00598445E1037D9F033497F7F" +
                "232316BFC783507D16A727FBF1BA75EA26D8306F8654A514B6319DABD1633FB4C50945C97323F30F7" +
                "9D7296864A5DD7FEEBA0BAAB3A609064162E656A3CFA126C6D397DC868E35553398CFE55E942F480E" +
                "8DBF93EC29C9F2CFC0CBA1CCC93C5CD714B614A2902BCAF5BDF8DDACC8482FCE236D4A89DE903BD21" +
                "700061A778CD802EA527F7DF0637AD5567FDF97D0B50B9DD2DE9695B81F22994A118B0B98877CDFF6" +
                "1C1C44257071B64D9";
        String privateKeyBase64Str = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC9Jquy2FY9XMis" +
                "CkJVlLyB3C4P4vZoJ/1fAjXF36qHkU5aOJ9kasKK9cA8T3tsQ0GrqvGNcxyhj17h" +
                "AlC5cqJK/BgOwShj67uG7F/loyNZEdbogSFW1BlRAU0vwS/JNTFUS+jje1aP7/a4" +
                "sYPEW9JToWR/cK/C69JMwaOz3FNZEfYZLmqS9KHugFTgxlp8BJwZ+5gxgte3IF90" +
                "Ip1pzlEDZK2GjLbuBXEi99KJl2YzvMJJ38IruiONM7GkoCZqc53/I3iPuHEoPpaC" +
                "MqfhOD2DOe0L6CbvYKLyEfReLFQG5abCXaweV/b9EzvvUl0u24RuATgzELLAg8GG" +
                "2hsOH+IhAgMBAAECggEBAJuBClF7R9Mkz5mYyZZANIXydS/8YKWaktQkJf8qdbEE" +
                "hczolinhF1VU2pj6ozaLSJcQb4vhoh00mEUWOTVtB/3rqP+gT0tuhvpSpDhPWYUl" +
                "hHAbkUQoFTQihMmI4ndhss9hpPI3+R9WoZiP4AtzjcPRgKTBCM6QP5F49NOuhBtJ" +
                "nIQTYYFYl2Cu2wt0bvprclbVQthCrkPnZywF5fOzk7wTiByhGeYA52ZMRO4WHg6r" +
                "XVBU/xb8VBZbTjhEzgIeGwMf1pixHf8UbuvsSbQ1V3b8t3CHt9xtbZUGTYt4LIoI" +
                "rcMHKg8e2YpO6qmu91YZp4qw2xxqfh0R0mFlaSgGV9ECgYEA8cHQWGUAQouhiQ28" +
                "5dACbOmA4BMq6ez5meJ02EgGbQFwTLIwafLa35GBP8TTGSpWf3XEQ86v2S3HX20o" +
                "M2ICBI9yVIyKTrpJv9P6N7UqaxSGJ3cMGooIrUiSFZ7BORFnkQ5b8ASlHF2WahJN" +
                "W30z1oPly6IBso5XAzKaOMbptqUCgYEAyEtzk+ml7uoxhh2DPcLFOaVWPo1DGd2R" +
                "M9UdadwVv+Ok7LWpK7/Z1MVYW7BYWUXF+RuCgG4tLMN7ERT5LlcVWvWO6bq5EQij" +
                "+YfAkmrwOidV5YiMR7/gCg/6W7D4guUCSJn1w/7vPHohR5mSFHicIWP7qrCSWbDB" +
                "vXabmiBUIM0CgYBnpWEuVHbtELH7cTFYEXrIuL8w0ebnDVrhV44in5Zpq2E68HYD" +
                "JkQh717LORYLxvP4h0PSkk0fvhmo1sKSbOVSkTFCAFLXd9Rgcn/m3DvIVq9BQi+l" +
                "PSKFMAS5UiuizMxrCw3tdABZjeILrbcOjznnMPsW92jk5VN2on4t81GFpQKBgCzn" +
                "pZjiyD3hKYs88KCXGyqKY+SQPRv+bcBmJjsGiaXEvsQHEk9pqsemGuIrjhMtrm3j" +
                "+gUbLmubw+qXfioigforlYfXQgiMnF6kTctFyGfxS7OzQmgPn4YCAQovifemqjVm" +
                "tw/jBvXTF8T6rCKEy9Q8mz6waY9MLpNwlQAgAVx9AoGAI47mJnDj0Doo59WXjIXT" +
                "eB2SE/0YoWZDvTvUxFQOm5n3Ed6mq9nVcl1RSH8bhkrZQRiFsrrLz6iJR4BmjRgw" +
                "67WlKYG8mX7HXvEjYf5yAsuxdh0N5xnYlyeXhSciyij6YE4caQoja+VRBgMPzlYv" +
                "IDkIK7tutsTEsyrc7SHy9j4=";

        byte[] dataBytes = ByteUtil.hexStr2Bytes(data);
        byte[] decryptResult = decryptByPrivateKey(Base64Utils.decode(privateKeyBase64Str), dataBytes);
        System.out.println("decryptResult:" + ByteUtil.bytes2HexStr(decryptResult));
    }


}
