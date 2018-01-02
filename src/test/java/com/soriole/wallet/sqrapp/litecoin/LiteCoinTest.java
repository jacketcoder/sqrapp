package com.soriole.wallet.sqrapp.litecoin;

import com.soriole.wallet.lib.ECKeyPair;
import com.soriole.wallet.lib.exceptions.ValidationException;
import jdk.nashorn.internal.runtime.Debug;
import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.assertEquals;

public class LiteCoinTest {
    private Litecoin instance;

    public LiteCoinTest() {
        instance = new Litecoin();
    }

    @Test
    public void testAddress() throws ValidationException {
        String address = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM";
        String privateKeyStr = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725";

        BigInteger privateKey = new BigInteger(privateKeyStr,16);
        ECKeyPair keyPair = ECKeyPair.create(privateKey);

        byte[] pubBytes = keyPair.getPublic();
        String computedAddress = instance.address(pubBytes);
        System.out.print(computedAddress);
        assertEquals(address, computedAddress);
    }
}
