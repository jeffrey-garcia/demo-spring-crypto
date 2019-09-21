package com.jeffrey.example.demospringcrypto.crypto;

public interface CryptoClient {

    String generateNewAesKey() throws RuntimeException;

    String encryptWithAesKey(final String aesKeyJsonBase64String, final String decipheredText) throws RuntimeException;

    String decryptWithAesKey(final String aesKeyJsonBase64String, final String cipheredText) throws RuntimeException;

}
