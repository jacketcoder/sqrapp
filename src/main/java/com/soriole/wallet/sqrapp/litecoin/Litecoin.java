package com.soriole.wallet.sqrapp.litecoin;

import com.soriole.wallet.lib.ByteUtils;
import com.soriole.wallet.lib.ECKeyPair;
import com.soriole.wallet.lib.exceptions.ValidationException;
import com.soriole.wallet.sqrapp.CryptoCurrency;
import com.soriole.wallet.sqrapp.bitcoin.BitcoinExtendedKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;

public class Litecoin implements CryptoCurrency{
    //for logging
    private static final Logger mLog= LoggerFactory.getLogger(Litecoin.class);
    private SecureRandom mRandom = new SecureRandom();
    @Override
    public byte[] newSeed() {
        byte[] seed = new byte[32];
        mRandom.nextBytes(seed);
        return seed;
    }

    @Override
    public byte[] newPrivateKey() {
         BitcoinExtendedKey mLiteCoinKeyHelper= BitcoinExtendedKey.createNew();
         return mLiteCoinKeyHelper.getMaster().getPrivate();
    }

    @Override
    public byte[] newPrivateKey(byte[] seed) {
        try {
            BitcoinExtendedKey mLiteCoinKeyHelper= BitcoinExtendedKey.create(seed);
            return mLiteCoinKeyHelper.getMaster().getPrivate();
        } catch (ValidationException e) {
            mLog.error("private key creation became unsuccessful");
        }
        return null;
    }

    @Override
    public byte[] newPrivateKey(byte[] seed, int index) {
        try {
            BitcoinExtendedKey mLiteCoinKeyHelper = BitcoinExtendedKey.create(seed);
            return mLiteCoinKeyHelper.getChild(index).getMaster().getPrivate();
        } catch (ValidationException e) {
            mLog.error("Could not create bitcoin private key[{}]", index, e);
        }
        return null;
    }

    @Override
    public byte[] publicKey(byte[] privateKey) {
        try {
            ECKeyPair mKeyPair = new ECKeyPair(privateKey, true);
            return mKeyPair.getPublic();
        } catch (ValidationException e) {
            mLog.error("Public key from private key could not get created", e);
        }
        return null;
    }
    public String address(byte[] pubBytes){
        if(pubBytes.length == 64){
            byte[] encodedPubBytes = new byte[65];
            encodedPubBytes[0] = 0x04;
            System.arraycopy(pubBytes, 0, encodedPubBytes, 1, pubBytes.length);
            pubBytes = encodedPubBytes;
        }
        byte[] keyHash = ByteUtils.keyHash(pubBytes);
        byte[] keyHashWithVersion = new byte[keyHash.length + 1];
        keyHashWithVersion[0] = 0x30; // version byte
        System.arraycopy(keyHash, 0, keyHashWithVersion, 1, keyHash.length);
        return ByteUtils.toBase58WithChecksum(keyHashWithVersion);

    }

}

