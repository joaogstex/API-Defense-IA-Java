package com.javaloginauthentication;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.HttpEntity;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

class LoginExample {

    static final String AUTH_URL = "http://192.168.1.175:8000/brms/api/v1.0/accounts/authorize";
    static final String KEEP_ALIVE_URL = "http://192.168.1.175:8000/brms/api/v1.0/accounts/keepalive";
    static final String UPDATE_TOKEN_URL = "http://192.168.1.175:8000/brms/api/v1.0/accounts/updateToken";
    static final String USER2 = "Gustavo";
    static final String IP_ADDRESS = "192.168.1.175";
    static final String PASSWORD = "Meunomesilva1@";
    static final String TOKEN = "token";
    static final String POST = "post";
    static final String PUT = "put";

    static final String SUCCESS_CODE = "1000";

    static String SIGNATURE_MD5_TEMP4 = null;
    static String TOKEN_VALUE = null;

    static int HEART_COUNT = 0;

    public static void login() throws Exception {
        // Tentar logar pela primeira vez

        // Parâmetros do primeiro login
        Map<String, Object> firstLoginParams = new HashMap<>(3);
        firstLoginParams.put("userName", USER2);
        firstLoginParams.put("ipAddress", IP_ADDRESS);
        firstLoginParams.put("clientType", "WINPC_V2");

        String firstResponseString = sendPostOrPut(AUTH_URL, firstLoginParams, POST);
        JSONObject firstLoginResponse = JSONObject.parseObject(firstResponseString);
        System.out.println(firstLoginResponse);

        // Tentar login pela segunda vez
        String realm = firstLoginResponse.getString("realm");
        String randomKey = firstLoginResponse.getString("randomKey");
        String signature = generateSignature(USER2, PASSWORD, realm, randomKey);

        KeyPair keyPair = getRsaKeys();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        Map<String, Object> secondLoginParams = new HashMap<>(9);
        secondLoginParams.put("mac", "2C-F0-5D-4D-5E-DB");
        secondLoginParams.put("signature", signature);
        secondLoginParams.put("userName", USER2);
        secondLoginParams.put("randomKey", randomKey);

        // Codifica a chave pública para base64, para transferí-la por protocolo HTTP

        String publicKeyWithBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        String privateKeyWithBase64 = Base64.getEncoder().encodeToString(privateKey.getEncoded());

        secondLoginParams.put("publicKey", publicKeyWithBase64);
        secondLoginParams.put("encrytType", "MD5");
        secondLoginParams.put("ipAddress", IP_ADDRESS);
        secondLoginParams.put("clientType", "WINPC_V2");
        secondLoginParams.put("userType", "0");

        String secondResponseString = sendPostOrPut(AUTH_URL, secondLoginParams, POST);
        JSONObject secondResponse = JSONObject.parseObject(secondResponseString);

        System.out.println("Signature: " + signature);
        System.out.println("Second login payload: " + JSON.toJSONString(secondLoginParams));
        System.out.println("Second response: " + secondResponseString);
        
        TOKEN_VALUE = secondResponse.getString(TOKEN);

        //realizar a adição dos valores dinamicamente ao fazer login
        PersonAddExample.token = TOKEN_VALUE;
        PersonAddExample.privateKeyWithBase64 = privateKeyWithBase64;
        PersonAddExample.secretKeyWithRsa = secondResponse.getString("secretKey");
        PersonAddExample.secretVectorWithRsa = secondResponse.getString("secretVector");
        
        MqConnectionExample.token = TOKEN_VALUE;
        MqConnectionExample.privateKeyWithBase64 = privateKeyWithBase64;
        MqConnectionExample.secretKeyWithRsa = secondResponse.getString("secretKey");
        MqConnectionExample.secretVectorWithRsa = secondResponse.getString("secretVector");

        System.out.println(String.format("token is : %s", TOKEN_VALUE));
        System.out.println(String.format("duration is : %s", secondResponse.getString("duration")));
        System.out.println(String.format("secretKeyWithRsa is : %s", secondResponse.getString("secretKey")));
        System.out.println(String.format("secretVectorWithRsa is : %s", secondResponse.getString("secretVector")));

        System.out.println(String.format(
                "your privateKeyWithBase64, you can decrypt secretKeyWithRsa and secretVectorWithRsa with it: %s",
                privateKeyWithBase64));
        // Faz uma busca para saber se o valor do token é nulo ou está vazio
        if (TOKEN_VALUE == null || TOKEN_VALUE.isEmpty()) {
            System.err.println("Token inválido, login falhou. Tente novamente.");
            System.exit(1);
        }
        // Passo 3: Mantém vivo (keep-alive) e atualiza o token

        /* 
        while (true) {
            // Manda um heart (pulso) por 22 segundos
            Thread.sleep(22000);
            Map<String, Object> keepAliveParamMap = new HashMap<>(1);
            keepAliveParamMap.put("token", TOKEN_VALUE);
            JSONObject heartResponse = JSONObject.parseObject(sendPostOrPut(KEEP_ALIVE_URL, keepAliveParamMap, PUT));
            if (SUCCESS_CODE.equals(heartResponse.getString("code"))) {
                System.out.println("Heart success!");
            }
            HEART_COUNT++;
            // Atualiza o token por 22 minutos.
            if (HEART_COUNT % 60 == 0) {
                // Restaura a contagem heart para zero
                HEART_COUNT = 0;
                String signatureForUpdataToken = DigestUtils.md5Hex(SIGNATURE_MD5_TEMP4 + ":" + TOKEN_VALUE);
                Map<String, Object> updateTokenParamMap = new HashMap<>(2);
                updateTokenParamMap.put("token", TOKEN_VALUE);
                updateTokenParamMap.put("signature", signatureForUpdataToken);
                JSONObject udpateTokenResponse = JSONObject
                        .parseObject(sendPostOrPut(UPDATE_TOKEN_URL, updateTokenParamMap, POST));
                if (SUCCESS_CODE.equals(udpateTokenResponse.getString("code"))) {
                    String newTokenValue = udpateTokenResponse.getJSONObject("data").getString(TOKEN);
                    System.out.println(String.format("update token success! new token:%s", newTokenValue));
                    TOKEN_VALUE = newTokenValue;
                }
            }
        }
    */
    }

    static String sendPostOrPut(String url, Map<String, Object> params, String requestMode)
            throws ClientProtocolException, IOException {
        if (!requestMode.equals(POST) && !requestMode.equals(PUT)) {
            return null;
        }
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpEntityEnclosingRequestBase httpRequest = null;
        if (requestMode.equals(POST)) {
            httpRequest = new HttpPost(url);
        } else if (requestMode.equals(PUT)) {
            httpRequest = new HttpPut(url);
        }
        StringEntity entity = new StringEntity(JSON.toJSONString(params), "UTF-8");
        httpRequest.setEntity(entity);
        System.out.println("Chaves no params: " + params.keySet());
        httpRequest.setHeader("Content-Type", "application/json;charset=UTF-8");
        if (params.containsKey(TOKEN) && params.get(TOKEN) != null) {
            httpRequest.setHeader("X-Subject-Token", params.get(TOKEN).toString());
            System.out.println("Caiu no header"); // debug
        } else {
            System.out.println("TOKEN está ausente ou nulo no par");
        }
        CloseableHttpResponse response = httpClient.execute(httpRequest);
        HttpEntity responseEntity = response.getEntity();
        // Para evitar um código bagunçado, codifica os dados de resposta em UTF-8
        String reply = EntityUtils.toString(responseEntity, "UTF-8");
        // Finalmente disponibiliza recursos
        if (httpClient != null) {
            httpClient.close();
        }
        if (response != null) {
            response.close();
        }
        return reply;
    }

    static String generateSignature(String userName, String passWord, String realm, String randomKey) {
        String temp1 = DigestUtils.md5Hex(passWord);
        String temp2 = DigestUtils.md5Hex(userName + temp1);
        String temp3 = DigestUtils.md5Hex(temp2);
        String temp4 = DigestUtils.md5Hex(userName + ":" + realm + ":" + temp3);
        // Retém o temp4 para calcular a assinatura para atualizar o token depois
        SIGNATURE_MD5_TEMP4 = temp4;
        String signature = DigestUtils.md5Hex(temp4 + ":" + randomKey);
        return signature;
    }

    /**
     * Generate RSA public key and private key.
     * 
     * @return KeyPair
     * @throws Exception
     */
    static KeyPair getRsaKeys() throws Exception {
        Provider provider = Security.getProvider("SunRsaSign");
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", provider);
        keyPairGen.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyPairGen.generateKeyPair();
        return keyPair;
    }
}
