package com.jeffrey.example.demospringcrypto.controller;

import com.jeffrey.example.demospringcrypto.service.CryptoService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
public class MainController {

    private static final Logger LOGGER = LoggerFactory.getLogger(MainController.class);

    @Autowired
    private CryptoService cryptoService;

    /**
     * curl "http://localhost:8080/aesKey" -i -X GET
     */
    @GetMapping(path="/aesKey")
    public @ResponseBody String getAesKey() {
        LOGGER.debug("getAesKey");
        return cryptoService.generateAesKey();
    }

    /**
     * curl 'http://localhost:8080/aesEncrypt' -i -X POST -H "Content-Type: application/json" -d '{"aesKeyJsonBase64String":"{\"primaryKeyId\":1224333868,\"key\":[{\"keyData\":{\"typeUrl\":\"type.googleapis.com/google.crypto.tink.AesGcmKey\",\"keyMaterialType\":\"SYMMETRIC\",\"value\":\"GiDlGE9V4Oawy6zR4E2EAY5ircYkwEVP3u22r6xhu6UFVA==\"},\"outputPrefixType\":\"TINK\",\"keyId\":1224333868,\"status\":\"ENABLED\"}]}","decipheredText":"123"}'
     */
    @PostMapping(path="/aesEncrypt")
    public @ResponseBody String aesEncrypt(@RequestBody Map<String,String> requestBodyMap) {
        LOGGER.debug("aesEncrypt");

        String aesKeyJsonBase64String = requestBodyMap.get("aesKeyJsonBase64String");
        String decipheredText = requestBodyMap.get("decipheredText");

        return cryptoService.encryptAes(aesKeyJsonBase64String, decipheredText);
    }

    /**
     * curl 'http://localhost:8080/aesDecrypt' -i -X POST -H "Content-Type: application/json" -d '{"aesKeyJsonBase64String":"{\"primaryKeyId\":1224333868,\"key\":[{\"keyData\":{\"typeUrl\":\"type.googleapis.com/google.crypto.tink.AesGcmKey\",\"keyMaterialType\":\"SYMMETRIC\",\"value\":\"GiDlGE9V4Oawy6zR4E2EAY5ircYkwEVP3u22r6xhu6UFVA==\"},\"outputPrefixType\":\"TINK\",\"keyId\":1224333868,\"status\":\"ENABLED\"}]}","cipheredText":"AUj52iz0GDJ2sMA++aBKQnoax9YU7+wzj/x2TvWzv17dEBJX"}'
     */
    @PostMapping(path="/aesDecrypt")
    public @ResponseBody String aesDecrypt(@RequestBody Map<String,String> requestBodyMap) {
        LOGGER.debug("aesDecrypt");

        String aesKeyJsonBase64String = requestBodyMap.get("aesKeyJsonBase64String");
        String cipheredText = requestBodyMap.get("cipheredText");

        return cryptoService.decryptAes(aesKeyJsonBase64String, cipheredText);
    }

}
