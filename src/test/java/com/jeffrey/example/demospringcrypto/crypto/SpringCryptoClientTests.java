package com.jeffrey.example.demospringcrypto.crypto;

import com.google.common.base.Strings;
import com.google.common.io.BaseEncoding;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;

import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class SpringCryptoClientTests {

    private CryptoClient cryptoClient;

    @Before
    public void init() {
        this.cryptoClient = new SpringCryptoClient();
    }

    @Test
    public void generateNewAes256Key() throws RuntimeException {
        String aesKeyBase64 = this.cryptoClient.generateNewAesKey();
        Assert.assertFalse(Strings.isNullOrEmpty(aesKeyBase64));

        String aesKey = new String(BaseEncoding.base64().decode(aesKeyBase64));
        Assert.assertFalse(Strings.isNullOrEmpty(aesKey));
    }

    @Test
    public void encrypt() {
        String password = "admin";
        String keyName = "YODA-DEK";

        // --- debug only --- //
//        String _secret = "{bcrypt}$2a$10$QYnG/AXdg89lCEGBFyK9Rejb5Hmo6Fe8le7JpFoJ16/0LiKpbXMhmear9e+iZ2gmAdwGUpuN//18jk8KElczkeigOMM7quTmrHirjOXjeIg==            ";
//        String hashedPassword = _secret.substring(0, _secret.length()/2);

        PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        String hashedPassword = passwordEncoder.encode(password);
        boolean isMatched = passwordEncoder.matches(password, hashedPassword);

        BytesEncryptor encryptor = Encryptors.stronger(
                // convert to HEX before passing into encryptors
                BaseEncoding.base16().encode(password.getBytes()),
                BaseEncoding.base16().encode(hashedPassword.getBytes())
        );
        String cipheredKeyName = BaseEncoding.base64().encode(encryptor.encrypt(keyName.getBytes()));

        // determine if hashedPassword or cipheredKeyName is longer
        int hashedPasswordLength = hashedPassword.length();
        int cipheredKeyNameLength = cipheredKeyName.length();

        int size = Math.max(hashedPasswordLength, cipheredKeyNameLength);

        String secret = String.format("%-" + size + "s", hashedPassword) +
                        String.format("%-" + size + "s", cipheredKeyName);
        System.out.println("[" + secret + "]");

        // --- for debug only --- //
//        int secretLength = secret.length();
//        String decipheredText = String.format("%-" + hashedPassword.length() + "s", "TestDEK");
//        int length = decipheredText.length();

        System.out.println();
        Assert.assertEquals(keyName, decrypt(password, secret));
    }

    private String decrypt(String password, String secret) {
        String hashedPassword = StringUtils.trimTrailingWhitespace(secret.substring(0, secret.length()/2));
        String cipheredKeyName = StringUtils.trimTrailingWhitespace(secret.substring(secret.length()/2));

        // verify password
        PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        if (passwordEncoder.matches(password, hashedPassword)) {
            // if password is correct, use the password and hashed password to decrypt the key name
            BytesEncryptor encryptor = Encryptors.stronger(
                    // convert to HEX before passing into encryptors
                    BaseEncoding.base16().encode(password.getBytes()),
                    BaseEncoding.base16().encode(hashedPassword.getBytes())
            );
            byte[] decipheredKeyName = encryptor.decrypt(BaseEncoding.base64().decode(cipheredKeyName));
            return new String(decipheredKeyName);
        }
        return null;
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
}
