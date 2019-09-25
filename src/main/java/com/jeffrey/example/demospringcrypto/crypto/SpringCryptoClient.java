package com.jeffrey.example.demospringcrypto.crypto;

import com.google.common.io.BaseEncoding;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.security.crypto.encrypt.Encryptors;

import java.util.UUID;

public class SpringCryptoClient implements CryptoClient {
    private static final Logger LOGGER = LoggerFactory.getLogger(SpringCryptoClient.class);

    @Override
    public String generateNewAesKey() throws RuntimeException {
        String password = UUID.randomUUID().toString();
        String salt = UUID.randomUUID().toString();

        String secret = password.concat(salt);
        LOGGER.debug("secret: {}", secret);

        return BaseEncoding.base64().encode(secret.getBytes());
    }

    @Override
    public String encryptWithAesKey(String aesKeyBase64, String decipheredText) throws RuntimeException {
        String secret = new String(BaseEncoding.base64().decode(aesKeyBase64));
        String password = secret.substring(0,secret.length()/2-1);
        String salt = secret.substring(secret.length()/2, secret.length());

        BytesEncryptor encryptor = Encryptors.stronger(
                BaseEncoding.base16().encode(password.getBytes()),
                BaseEncoding.base16().encode(salt.getBytes()));

        String cipheredTextBase64String = BaseEncoding.base64().encode(encryptor.encrypt(decipheredText.getBytes()));
        LOGGER.debug("ciphered text base64: {}", cipheredTextBase64String);

        return cipheredTextBase64String;
    }

    @Override
    public String decryptWithAesKey(String aesKeyBase64, String cipheredTextBase64) throws RuntimeException {
        String secret = new String(BaseEncoding.base64().decode(aesKeyBase64));
        String password = secret.substring(0,secret.length()/2-1);
        String salt = secret.substring(secret.length()/2, secret.length());

        BytesEncryptor encryptor = Encryptors.stronger(
                BaseEncoding.base16().encode(password.getBytes()),
                BaseEncoding.base16().encode(salt.getBytes()));

        String decipheredText = new String(encryptor.decrypt(BaseEncoding.base64().decode(cipheredTextBase64)));
        LOGGER.debug("deciphered text: {}", decipheredText);

        return decipheredText;
    }

    @Override
    public String generateNewEcdsaKeyPair() throws RuntimeException {
        // TODO: to be implemented
        return null;
    }

    @Override
    public String signWithEcdsaPrivateKey(String ecdsaPrivateKeyBase64, String message) throws RuntimeException {
        // TODO: to be implemented
        return null;
    }

    @Override
    public void verifySignatureWithEcdsaPublicKey(String ecdsaPrivateKeyBase64, String message, String signatureBase64) {
        // TODO: to be implemented
        return;
    }

    @Override
    public String generateNewHmacSha2Key() {
        // TODO: to be implemented
        return null;
    }

    @Override
    public String computeAuthTagWithHmacKey(String hmacKeyBase64, String message) throws RuntimeException {
        // TODO: to be implemented
        return null;
    }

    @Override
    public void verifyAuthTagWithHmacKey(String hmacKeyBase64, String message, String authTagBase64) {
        // TODO: to be implemented
        return;
    }

}
