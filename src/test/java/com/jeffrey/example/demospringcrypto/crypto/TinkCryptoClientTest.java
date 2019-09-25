package com.jeffrey.example.demospringcrypto.crypto;

import com.google.common.io.BaseEncoding;
import org.assertj.core.util.Strings;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class TinkCryptoClientTest {

    private CryptoClient cryptoClient;

    @Before
    public void init() throws Exception {
        this.cryptoClient = new TinkCryptoClient();
    }

    @Test
    public void generateNewAes256Key() throws RuntimeException {
        String aesKeyBase64 = this.cryptoClient.generateNewAesKey();
        Assert.assertFalse(Strings.isNullOrEmpty(aesKeyBase64));

        String aesKey = new String(BaseEncoding.base64().decode(aesKeyBase64));
        Assert.assertFalse(Strings.isNullOrEmpty(aesKey));
    }

    @Test
    public void encryptAndDecryptAes() throws RuntimeException {
        String aesKeyBase64 = this.cryptoClient.generateNewAesKey();
        String decipheredText = UUID.randomUUID().toString();

        String cipheredTextBase64 = this.cryptoClient.encryptWithAesKey(aesKeyBase64, decipheredText);
        Assert.assertFalse(Strings.isNullOrEmpty(cipheredTextBase64));

        Assert.assertEquals(decipheredText, this.cryptoClient.decryptWithAesKey(aesKeyBase64, cipheredTextBase64));
    }

    @Test
    public void concurrentEncryptDecryptAes() throws RuntimeException, InterruptedException {
        final int total = 500;
        Executor executor = Executors.newFixedThreadPool(5);
        CountDownLatch lock = new CountDownLatch(total);

        for (int i=0; i<total; i++) {
            executor.execute(() -> {
                String aesKeyBase64 = this.cryptoClient.generateNewAesKey();
                String decipheredText = UUID.randomUUID().toString();

                String cipheredTextBase64 = this.cryptoClient.encryptWithAesKey(aesKeyBase64, decipheredText);
                Assert.assertFalse(Strings.isNullOrEmpty(cipheredTextBase64));

                Assert.assertEquals(decipheredText, this.cryptoClient.decryptWithAesKey(aesKeyBase64, cipheredTextBase64));

                lock.countDown();

            });
        }

        /**
         * Assume each pair of encrypt/decrypt operation take 25ms,
         * with a thread pool of 5, approximately 500/5 * 25 = 2500ms
         * is required
         *
         * If each request comes in at a rate of less than 7ms, the
         * system buffer will be at risk as the next request cannot be
         * consumed until there are available worker thread, potentially
         * dropping new requests when the system buffer is saturated
         */
        lock.await(2500L, TimeUnit.MILLISECONDS);
        Assert.assertEquals(0, lock.getCount());
    }

    @Test
    public void generateNewHmacSha2Key() throws RuntimeException {
        String hmacBase64 = this.cryptoClient.generateNewHmacSha2Key();
        Assert.assertFalse(Strings.isNullOrEmpty(hmacBase64));

        String hmacKey = new String(BaseEncoding.base64().decode(hmacBase64));
        Assert.assertFalse(Strings.isNullOrEmpty(hmacKey));
    }

    @Test
    public void hashAndVerify() throws RuntimeException {
        String hmacBase64 = this.cryptoClient.generateNewHmacSha2Key();
        String message = UUID.randomUUID().toString();

        String authTagBase64 = this.cryptoClient.computeAuthTagWithHmacKey(hmacBase64, message);
        Assert.assertFalse(Strings.isNullOrEmpty(authTagBase64));

        this.cryptoClient.verifyAuthTagWithHmacKey(hmacBase64, message, authTagBase64);
    }

}
