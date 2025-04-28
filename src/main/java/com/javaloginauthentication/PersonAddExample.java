package com.javaloginauthentication;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Esse é um exemplo de adição de pessoa
 */
class PersonAddExample {

    static final String POST = "post";
    static final String GET = "get";
    static final String TOKEN = "token";
    static final String RESULT = "results";
    static final String PAGE_DATA = "pageData";
    static final Integer SUCCESS_CODE = 1000;
    static final Integer RETURN_CODE_DATA_NOT_EXIST = 1007;
    //Quando há erro o código retornado é 7000
    static final String URL_PRFIX = "http://192.168.1.175:8000";
    static final String PERSON_ADD_URL = URL_PRFIX + "/obms/api/v1.1/acs/person";
    static final String PERSON_GROUP_TREE_URL = URL_PRFIX + "/obms/api/v1.1/acs/person-group/list";
    static final String ENTRANCE_GROUP_URL = URL_PRFIX + "/ipms/api/v1.1/entrance-group/page?page=1&pageSize=1&keyword=";
    static final String FACE_REPOSITORY_URL = URL_PRFIX + "/brms/api/v1.1/face/application/control/repository/page?orderType=0&orderDirection=0&keyword=&page=1&pageSize=1";
    static final String PASSAGE_RULE_URL = URL_PRFIX + "/obms/api/v1.1/acp/passage/rule/exclude/page?page=1&pageSize=20&keyword=&resourceType=4&resourceCode=";

    // Attention: Tokens are updated every 22 minutes,Please use the latest
    // token,otherwise,the interface will respond 7000.
    static String token;
    // This three params you can obtain from the LoginExample or your client.
    static String secretKeyWithRsa;
    static String secretVectorWithRsa;
    static String privateKeyWithBase64;

    public static void addPerson() throws Exception {
        // Before start,read relevant API first,and this example is long,be patient
        // pleas
        // Assign values to parameters.This step has 7 modules.
        // You can optionally assign values to your parameters, because some parameters
        // can be empty.
        Map<String, Object> param = new HashMap<>(8);
        /** Module 1: Basic Info */
        Map<String, Object> baseInfoParams = new HashMap<>(10);
        // Person source, 0 = People management list, 1 = Access control group, 2 = Face
        // comparison group, 3 = Entrance and exit vehicle group; 0 by default
        baseInfoParams.put("source", "0");
        // general 8 random number
        baseInfoParams.put("personId", randomNumber(8));
        baseInfoParams.put("firstName", "Steven");
        baseInfoParams.put("lastName", "Rogers");
        // Gender: 0 = Unknown, 1 = Male, 2 = Female; 0 by default.
        baseInfoParams.put("gender", "1");
        // Person Group : We got it through Get the List of Person Groups interface.
        List<TreeNode> treeNodeList = deserializeData(sendPostOrGet(PERSON_GROUP_TREE_URL, null, GET), TreeNode.class,
                RESULT,
                "Person Group");
        // Select your own personnel group node,we only use the first here.
        baseInfoParams.put("orgCode", treeNodeList.get(0).getOrgCode());
        baseInfoParams.put("email", "teste" + randomNumber(4) + "@email.com");
        baseInfoParams.put("tel", "13800001234");
        baseInfoParams.put("remark", "");
        // Attention:The picture information is encoded by Base64,some characters are
        // omitted here.

        // adiciona o método para codificar imagem para base 64
        String faceImageBase64 = encodeImageToBase64(
                "C:\\Users\\Ecoground Tecnologia\\Downloads\\JavaLoginAuth\\javaloginauthentication\\src\\main\\resources\\steve.jpg");
        baseInfoParams.put("facePictures", Arrays.asList(faceImageBase64));

        param.put("baseInfo", baseInfoParams);
        /** Module 2: Additional Info */
        Map<String, Object> extensionInfoParams = new HashMap<>(8);
        extensionInfoParams.put("nickName", "Steve");
        extensionInfoParams.put("address", "No.569, Leaman Place, Brooklyn Heights, New York, USA");
        extensionInfoParams.put("idType", "0");
        extensionInfoParams.put("idNo", "100101198012255310");
        extensionInfoParams.put("birthday", "1912-07-04");
        // Region: Reference the API.
        extensionInfoParams.put("nationalityId", "51");
        extensionInfoParams.put("companyName", "Avengers");
        extensionInfoParams.put("position", "Captain");
        extensionInfoParams.put("department", "Shield department");
        param.put("extensionInfo", extensionInfoParams);
        /** Module 3: Residence Info */
        Map<String, Object> residentInfoParams = new HashMap<>(2);
        residentInfoParams.put("sipId", "02#1#" + randomNumber(4));
        // Video intercom householder or not, 0 = No, 1 = Yes; 0 by default.
        residentInfoParams.put("houseHolder", "1");
        residentInfoParams.put("vdpUser", "0");
        param.put("residentInfo", residentInfoParams);
        /** Module 4: Authentication Info */
        Map<String, Object> authenticationInfoParams = new HashMap<>(8);
        // Combination unlocking password, AES encryption.
        authenticationInfoParams.put("combinationPassword", encryptPassWordWithAES("123456"));
        List<Map<String, Object>> cardList = new ArrayList<>(1);
        Map<String, Object> cardMap = new HashMap<>(3);
        cardMap.put("cardNo", generateRandomCardHex());
        // cardMap.put("mainFlag", "1");
        cardMap.put("duressFlag", "0");
        cardList.add(cardMap);
        authenticationInfoParams.put("cards", cardList);
        authenticationInfoParams.put("endTime", "1924963200");
        authenticationInfoParams.put("startTime", "1609430400");
        // Fingerprint list,limit three.
        List<Map<String, Object>> fingerPritList = new ArrayList<>(1);
        Map<String, Object> fingerprintMap = new HashMap<>(3);
        // Attention:The fingerprint information is encoded by Base64,some characters
        // are omitted here.
        fingerprintMap.put("fingerprint", "xR9pAOCGm+UQSbjE ..... AAdDR4QDxsAAOva");
        fingerprintMap.put("name", "fingerprint01");
        // Duress fingerprint or not, 0 = No, 1 = Yes
        fingerprintMap.put("duressFlag", "0");
        fingerPritList.add(fingerprintMap);
        authenticationInfoParams.put("fingerprints", fingerPritList);
        param.put("authenticationInfo", authenticationInfoParams);
        /** Module 5: Access Control Permissions */
        Map<String, Object> accessInfoParams = new HashMap<>(5);
        // get passageRuleIds
        System.out.println("🔎 Testando chamada para PASSAGE_RULE_URL");
        String passageRuleResponse = sendPostOrGet(PASSAGE_RULE_URL, null, GET);
        System.out.println("Resposta da API de regras de passagem: \n" + passageRuleResponse);
         
        List<ResourceExcludeRuleVo> passageRuleList = deserializeData(
                passageRuleResponse, ResourceExcludeRuleVo.class, PAGE_DATA, "passage rule info");
        if (null != passageRuleList && passageRuleList.size() > 0) {
            accessInfoParams.put("passageRuleIds",
                    passageRuleList.stream().map(ResourceExcludeRuleVo::getId).collect(Collectors.toList()));
        } else {
            accessInfoParams.put("passageRuleIds", null);
            System.err.println("⚠ Nenhuma regra de passagem encontrada.");
        }
        
        // deixa como null apenas para conseguir rodar sem erro de regra
        accessInfoParams.put("passageRuleIds", null);
        // Number of times visitors can unlock; 200 by default.
        accessInfoParams.put("guestUseTimes", "200");
        // Access control person type, 0 = Normal, 1 = Blocklist, 2 = Visitor, 3=
        // Patrol, 4 = VIP, 5 = Others; 0 by default.
        accessInfoParams.put("accessType", "2");
        param.put("accessInfo", accessInfoParams);
        /** Module 6: Face Comparison */
        Map<String, Object> faceComparisonInfoParams = new HashMap<>(2);
        // Enable face comparison group, 0 = No, 1 = Yes.
        faceComparisonInfoParams.put("enableFaceComparisonGroup", "1");
        // Face comparison group ID: We got it through [Get Face Watch List in pages]
        // interface.
        System.out.println("🔎 Testando chamada para FACE_REPOSITORY_URL");
        String faceRepoResponse = sendPostOrGet(FACE_REPOSITORY_URL, null, GET);
        System.out.println("Resposta da API de grupos faciais: \n" + faceRepoResponse);
        
        List<FaceRepositoryGroup> faceRepositoryGroupList = deserializeData(
                faceRepoResponse, FaceRepositoryGroup.class, PAGE_DATA, "Face Repository Group");
        // Select your own face repository group,we only use the first here.
        if (null != faceRepositoryGroupList && faceRepositoryGroupList.size() > 0) {
            faceComparisonInfoParams.put("faceComparisonGroupId", faceRepositoryGroupList.get(0).getRepositoryId());
        } else {
            faceComparisonInfoParams.put("faceComparisonGroupId", null);
            System.err.println("⚠ Nenhum grupo facial encontrado.");
        }
        
        // deixa como null apenas para conseguir rodar sem erro de regra
        faceComparisonInfoParams.put("faceComparisonGroupId", null);
        param.put("faceComparisonInfo", faceComparisonInfoParams);
        /** Module 7: Vehicle Info & Entrance and Exit Vehicle Group */
        Map<String, Object> entranceInfoParams = new HashMap<>(4);
        List<Map<String, Object>> vehicles = new ArrayList<>(1);
        Map<String, Object> vehicleMap = new HashMap<>(8);
        vehicleMap.put("entranceEndTime", "-1");
        vehicleMap.put("entranceStartTime", "-1");
        vehicleMap.put("plateNo", "ZHE" + randomNumber(4));
        // Vehicle color: Reference the API.
        vehicleMap.put("vehicleColor", "1");
        vehicleMap.put("entranceLongTerm", "1");
        // Vehicle entrance and exit group ID: We got it through [Get the List of
        // Entrance and Exit Groups of Vehicles in Pages] interface.
        System.out.println("🔎 Testando chamada para ENTRANCE_GROUP_URL");
        String entranceGroupResponse = sendPostOrGet(ENTRANCE_GROUP_URL, null, GET);
        System.out.println("Resposta da API de grupos de veículos: \n" + entranceGroupResponse);
        
        List<EntranceGroup> entranceGroupList = deserializeData(
                entranceGroupResponse, EntranceGroup.class, PAGE_DATA, "Entrance and Exit Group");
        // Select your own entrance group,we only use the first here.
        if (null != entranceGroupList && entranceGroupList.size() > 0) {
            vehicleMap.put("entranceGroupIds",
                    entranceGroupList.stream().map(e -> e.getGroupId()).collect(Collectors.toList()).subList(0, 1));
        } else {
            vehicleMap.put("entranceGroupIds", null);
        }
        
        // deixa como null apenas para conseguir rodar sem erro de regra
        vehicleMap.put("entranceGroupIds", null);
        vehicleMap.put("remark", "");
        // Vehicle brand: Reference the API.
        vehicleMap.put("vehicleBrand", "47");
        vehicles.add(vehicleMap);
        entranceInfoParams.put("vehicles", vehicles);
        // Enable vehicle entrance and exit group, 0 = No, 1 = Yes.
        entranceInfoParams.put("enableEntranceGroup", "1");
        entranceInfoParams.put("parkingSpaceNum", "0");
        // Enable parking space, 0 = No, 1 = Yes.
        entranceInfoParams.put("enableParkingSpace", "0");
        param.put("entranceInfo", entranceInfoParams);
        // Last: Send a POST request with the param.If you get the return code of 1000,
        // it means you succeed.
        String responseString = sendPostOrGet(PERSON_ADD_URL, param, POST);
        Integer responseCode = (Integer) JSONObject.parseObject(responseString).get("code");
        if (responseCode.compareTo(SUCCESS_CODE) == 0) {
            System.out.println(responseString);
        } else {
            throw new Exception(responseString);
        }
    }

    /**
     * Obtém 8 digitos randômicos
     * 
     * @param count
     * @return
     */
    public static String randomNumber(int count) {
        Random random = new Random();
        StringBuilder val = new StringBuilder();
        for (int i = 0; i < count; ++i) {
            val.append(random.nextInt(10));
        }
        return val.toString();
    }

    /**
     * Send post or get request method with HTTP.
     * 
     * @param url
     * @param params
     * @return reply
     */
    static String sendPostOrGet(String url, Map<String, Object> params, String requestMode) throws IOException {
        String cha = url.contains("?") ? "&" : "?";
        String realUrl = url + cha + "token=" + token;

        System.out.println("➡️ URL acessada: " + realUrl);
        if (!requestMode.equals(POST) && !requestMode.equals(GET)) {
            return null;
        }

        CloseableHttpClient httpClient = HttpClients.createDefault();
        CloseableHttpResponse httpResponse = null;

        if (requestMode.equals(POST)) {
            HttpEntityEnclosingRequestBase httpRequest = new HttpPost(realUrl);
            StringEntity entity = new StringEntity(JSON.toJSONString(params), "UTF-8");
            httpRequest.setEntity(entity);
            httpRequest.setHeader("Content-Type", "application/json;charset=UTF-8");
            httpRequest.setHeader("X-Subject-Token", token);
            if (params.containsKey(TOKEN)) {
                httpRequest.setHeader("X-Subject-Token", params.get(TOKEN).toString());
            }
            httpResponse = httpClient.execute(httpRequest);
        } else if (requestMode.equals(GET)) {
            HttpGet httpGet = new HttpGet(realUrl);
            httpGet.setHeader("X-Subject-Token", token);
            httpResponse = httpClient.execute(httpGet);
        }
        HttpEntity responseEntity = httpResponse.getEntity();
        // In order to avoid messy code,encode the response data in UTF-8.
        String reply = EntityUtils.toString(responseEntity, "UTF-8");
        // Release resources finally.
        if (httpClient != null) {
            httpClient.close();
        }
        if (httpResponse != null) {
            httpResponse.close();
        }
        return reply;
    }

    /**
     * AES encryption
     * 
     * @param password
     * @return
     */
    static String encryptPassWordWithAES(String password) {
        try {
            byte[] privateKey = Base64.getDecoder().decode(privateKeyWithBase64);
            String secretKey = decryptRSAByPrivateKey(secretKeyWithRsa, privateKey);
            String secretVector = decryptRSAByPrivateKey(secretVectorWithRsa, privateKey);
            return encryptWithAES7(password, secretKey, secretVector);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * AES encryption mode is CBC, and the filling mode is pkcs7padding
     * 
     * @param text
     * @param aesKey
     * @param aesVector
     * @return
     * @throws Exception
     */
    static String encryptWithAES7(String text, String aesKey, String aesVector) throws Exception {
        SecretKey keySpec = new SecretKeySpec(aesKey.getBytes("UTF-8"), "AES");
        // If your program run with an exception :"Cannot find any provider supporting
        // AES/CBC/PKCS7Padding",you can replace "PKCS7Padding" with "PKCS5Padding".
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec(aesVector.getBytes("UTF-8"));
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
        byte[] encrypted = cipher.doFinal(text.getBytes("UTF-8"));
        return parseByte2HexStr(encrypted);
    }

    /**
     * Byte array to 16 bit string
     * 
     * @param buf
     * @return
     */
    static String parseByte2HexStr(byte buf[]) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < buf.length; i++) {
            String hex = Integer.toHexString(buf[i] & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }
            sb.append(hex.toLowerCase());
        }
        return sb.toString();
    }

    /**
     * RSA private key is pkcs8 format
     * 
     * @param text
     * @param privateKeyEncoded : RSA privateKey
     * @return
     * @throws Exception
     */
    static String decryptRSAByPrivateKey(String text, byte[] privateKeyEncoded) throws Exception {
        byte[] data = Base64.getDecoder().decode(text);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKeyEncoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] result = null;
        for (int i = 0; i < data.length; i += 256) {
            int to = (i + 256) < data.length ? (i + 256) : data.length;
            byte[] temp = cipher.doFinal(Arrays.copyOfRange(data, i, to));
            result = sumBytes(result, temp);
        }
        return new String(result, "UTF-8");
    }

    static byte[] sumBytes(byte[] bytes1, byte[] bytes2) {
        byte[] result = null;
        int len1 = 0;
        int len2 = 0;
        if (null != bytes1) {
            len1 = bytes1.length;
        }
        if (null != bytes2) {
            len2 = bytes2.length;
        }
        if (len1 + len2 > 0) {
            result = new byte[len1 + len2];
        }
        if (len1 > 0) {
            System.arraycopy(bytes1, 0, result, 0, len1);
        }
        if (len2 > 0) {
            System.arraycopy(bytes2, 0, result, len1, len2);
        }
        return result;
    }

    /**
     * Deserialize data
     * 
     * @param responseString
     * @param clazz
     * @param fieldName
     * @param businessName
     * @param
     * @return
     * @throws Exception
     */
    static <T> List<T> deserializeData(String responseString, Class<T> clazz, String fieldName, String businessName)
            throws Exception {
        if (responseString == null || !responseString.trim().startsWith("{")) {
            throw new IOException("❌ A resposta da API não está em formato JSON:\n" + responseString);
        }
        JSONObject jsonObject = JSONObject.parseObject(responseString);
        Integer code = (Integer) jsonObject.get("code");
        if (code == null) {
            throw new IOException("❌ A resposta da API não contém o campo 'code'. Resposta completa:\n" + responseString);
        }
        if (code.compareTo(SUCCESS_CODE) == 0) {
            Object dataObject = jsonObject.getJSONObject("data").get(fieldName);
            if (dataObject != null) {
                List resultList = JSONObject.parseArray(dataObject.toString(), clazz);
                if (resultList == null || resultList.size() == 0) {
                    throw new Exception("If you want to add a " + businessName +
                            ", please add it in client first.");
                }
                return JSONObject.parseArray(dataObject.toString(), clazz);
            }
        } else if (code.compareTo(RETURN_CODE_DATA_NOT_EXIST) == 0) {
            throw new Exception("If you want to add   a " + businessName + ", please add it in client first.");
        } else {
            throw new Exception(responseString);
        }
        return null;
    }

    static class TreeNode {
        private String orgCode;
        private String parentOrgCode;
        private String orgName;
        private String remark;
        private List children;
        private String childNum;

        public String getOrgCode() {
            return orgCode;
        }

        public void setOrgCode(String orgCode) {
            this.orgCode = orgCode;
        }

        public String getParentOrgCode() {
            return parentOrgCode;
        }

        public void setParentOrgCode(String parentOrgCode) {
            this.parentOrgCode = parentOrgCode;
        }

        public String getOrgName() {
            return orgName;
        }

        public void setOrgName(String orgName) {
            this.orgName = orgName;
        }

        public String getRemark() {
            return remark;
        }

        public void setRemark(String remark) {
            this.remark = remark;
        }

        public List getChildren() {
            return children;
        }

        public void setChildren(List children) {
            this.children = children;
        }

        public String getChildNum() {
            return childNum;
        }

        public void setChildNum(String childNum) {
            this.childNum = childNum;
        }
    }

    static class ResourceExcludeRuleVo {
        private String id;
        private String ruleName;
        private String ruleType;
        private String pointType;
        private String timeTemplateId;
        private String timeTemplateName;
        private String holidayPlanId;
        private String holidayPlanName;
        private int personCount;
        private int pointCount;

        public String getRuleType() {
            return ruleType;
        }

        public void setRuleType(String ruleType) {
            this.ruleType = ruleType;
        }

        public int getPersonCount() {
            return personCount;
        }

        public void setPersonCount(int personCount) {
            this.personCount = personCount;
        }

        public int getPointCount() {
            return pointCount;
        }

        public void setPointCount(int pointCount) {
            this.pointCount = pointCount;
        }

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getRuleName() {
            return ruleName;
        }

        public void setRuleName(String ruleName) {
            this.ruleName = ruleName;
        }

        public String getPointType() {
            return pointType;
        }

        public void setPointType(String pointType) {
            this.pointType = pointType;
        }

        public String getTimeTemplateId() {
            return timeTemplateId;
        }

        public void setTimeTemplateId(String timeTemplateId) {
            this.timeTemplateId = timeTemplateId;
        }

        public String getTimeTemplateName() {
            return timeTemplateName;
        }

        public void setTimeTemplateName(String timeTemplateName) {
            this.timeTemplateName = timeTemplateName;
        }

        public String getHolidayPlanId() {
            return holidayPlanId;
        }

        public void setHolidayPlanId(String holidayPlanId) {
            this.holidayPlanId = holidayPlanId;
        }

        public String getHolidayPlanName() {
            return holidayPlanName;
        }

        public void setHolidayPlanName(String holidayPlanName) {
            this.holidayPlanName = holidayPlanName;
        }
    }

    static class AccessGroup {
        private String accessGroupId;
        private String accessGroupName;
        private String remark;
        private List<Map<String, Object>> doorGroups;
        private String personCount;

        public String getAccessGroupId() {
            return accessGroupId;
        }

        public void setAccessGroupId(String accessGroupId) {
            this.accessGroupId = accessGroupId;
        }

        public String getAccessGroupName() {
            return accessGroupName;
        }

        public void setAccessGroupName(String accessGroupName) {
            this.accessGroupName = accessGroupName;
        }

        public String getRemark() {
            return remark;
        }

        public void setRemark(String remark) {
            this.remark = remark;
        }

        public List<Map<String, Object>> getDoorGroups() {
            return doorGroups;
        }

        public void setDoorGroups(List<Map<String, Object>> doorGroups) {
            this.doorGroups = doorGroups;
        }

        public String getPersonCount() {
            return personCount;
        }

        public void setPersonCount(String personCount) {
            this.personCount = personCount;
        }
    }

    static class EntranceGroup {
        private String groupId;
        private String groupName;
        private String groupColor;
        private String remark;
        private String defaultGroup;
        private String vehicleCount;

        public String getGroupId() {
            return groupId;
        }

        public void setGroupId(String groupId) {
            this.groupId = groupId;
        }

        public String getGroupName() {
            return groupName;
        }

        public void setGroupName(String groupName) {
            this.groupName = groupName;
        }

        public String getGroupColor() {
            return groupColor;
        }

        public void setGroupColor(String groupColor) {
            this.groupColor = groupColor;
        }

        public String getRemark() {
            return remark;
        }

        public void setRemark(String remark) {
            this.remark = remark;
        }

        public String getDefaultGroup() {
            return defaultGroup;
        }

        public void setDefaultGroup(String defaultGroup) {
            this.defaultGroup = defaultGroup;
        }

        public String getVehicleCount() {
            return vehicleCount;
        }

        public void setVehicleCount(String vehicleCount) {
            this.vehicleCount = vehicleCount;
        }
    }

    static class FaceRepositoryGroup {
        private String repositoryId;
        private String repositoryName;
        private String color;
        private String colorName;
        private String memo;
        private String createTime;
        private String updateTime;
        private String facePersonCount;
        private String isFailed;
        private String thumbnail;

        public String getRepositoryId() {
            return repositoryId;
        }

        public void setRepositoryId(String repositoryId) {
            this.repositoryId = repositoryId;
        }

        public String getRepositoryName() {
            return repositoryName;
        }

        public void setRepositoryName(String repositoryName) {
            this.repositoryName = repositoryName;
        }

        public String getColor() {
            return color;
        }

        public void setColor(String color) {
            this.color = color;
        }

        public String getColorName() {
            return colorName;
        }

        public void setColorName(String colorName) {
            this.colorName = colorName;
        }

        public String getMemo() {
            return memo;
        }

        public void setMemo(String memo) {
            this.memo = memo;
        }

        public String getCreateTime() {
            return createTime;
        }

        public void setCreateTime(String createTime) {
            this.createTime = createTime;
        }

        public String getUpdateTime() {
            return updateTime;
        }

        public void setUpdateTime(String updateTime) {
            this.updateTime = updateTime;
        }

        public String getFacePersonCount() {
            return facePersonCount;
        }

        public void setFacePersonCount(String facePersonCount) {
            this.facePersonCount = facePersonCount;
        }

        public String getIsFailed() {
            return isFailed;
        }

        public void setIsFailed(String isFailed) {
            this.isFailed = isFailed;
        }

        public String getThumbnail() {
            return thumbnail;
        }

        public void setThumbnail(String thumbnail) {
            this.thumbnail = thumbnail;
        }
    }

    // método para codificação da imagem no resources para base64
    public static String encodeImageToBase64(String imagePath) throws IOException {
        java.nio.file.Path path = java.nio.file.Paths.get(imagePath);
        byte[] data = java.nio.file.Files.readAllBytes(path);
        return Base64.getEncoder().encodeToString(data);
    }

    //gera dinamicamente um número de cartão para não colidir com os cadastrados
    public static String generateRandomCardHex() {
        Random rand = new Random();
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < 8; i++) { // 8 dígitos hexadecimais
            hex.append(Integer.toHexString(rand.nextInt(16)).toUpperCase());
        }
        return hex.toString();
    }

}
