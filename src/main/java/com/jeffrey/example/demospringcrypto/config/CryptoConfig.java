package com.jeffrey.example.demospringcrypto.config;

import com.jeffrey.example.demospringcrypto.crypto.CryptoClient;
import com.jeffrey.example.demospringcrypto.crypto.SpringCryptoClient;
import com.jeffrey.example.demospringcrypto.crypto.TinkCryptoClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CryptoConfig {
    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoConfig.class);

    @Bean
    @Qualifier("cryptoClient")
    CryptoClient buildCryptoClient() throws Exception {
        return new TinkCryptoClient();
//        return new SpringCryptoClient();
    }

}
