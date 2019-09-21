package com.jeffrey.example.demospringcrypto.service;

import com.jeffrey.example.demospringcrypto.crypto.CryptoClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

@Service
public class CryptoService {
    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoService.class);

    @Autowired
    @Qualifier("cryptoClient")
    CryptoClient cryptoClient;

    public String generateAesKey() {
        return cryptoClient.generateNewAesKey();
    }

    public String encryptAes(String aesKeyJsonBase64String, String decipheredText) {
        return cryptoClient.encryptWithAesKey(aesKeyJsonBase64String, decipheredText);
    }

    public String decryptAes(String aesKeyJsonBase64String, String cipheredText) {
        return cryptoClient.decryptWithAesKey(aesKeyJsonBase64String, cipheredText);
    }

}
