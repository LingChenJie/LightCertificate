package com.android.certificate.utils;

import com.android.architecture.utils.ByteUtil;

import java.nio.charset.StandardCharsets;

/**
 * File describe:
 * Author: SuQi
 * Create date: 2023/5/9
 * Modify date: 2023/5/9
 * Version: 1
 */
public class Test {

    public static void main(String[] args) {
        byte[] psw = new byte[]{'1', '2', '3', '4', '5', '6'};
        String hexStr = ByteUtil.bytes2HexStr(psw);
        byte[] bytes = "123456".getBytes(StandardCharsets.UTF_8);
        String hexStr2 = ByteUtil.bytes2HexStr(bytes);
        System.out.println(hexStr);
        System.out.println(hexStr2);
    }
}
