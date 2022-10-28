//package com.apiwiz.security.threatcheck;
//
//import com.apigee.flow.execution.Action;
//import com.apigee.flow.execution.ExecutionContext;
//import com.apigee.flow.execution.ExecutionResult;
//import com.apigee.flow.message.*;
//import com.apiwiz.security.threatcheck.ThreatCallout;
//
//import mockit.MockUp;
//import mockit.Mock;
//import org.apache.commons.lang3.StringEscapeUtils;
//
//import org.testng.Assert;
//import org.testng.annotations.AfterMethod;
//import org.testng.annotations.BeforeMethod;
//import org.testng.annotations.DataProvider;
//import org.testng.annotations.Test;
//
//import java.io.*;
//import java.util.*;
//import java.util.regex.Pattern;
//import static java.lang.System.out;
//
//import static org.fest.reflect.core.Reflection.method;
//
///**
// * Created by seanwilliams on 10/5/16.
// */
//public class ThreatCalloutTest {
//
//    MessageContext msgCtxt;
//    ExecutionContext exeCtxt;
//    //SQL
//    String pattern1 = StringEscapeUtils.unescapeXml("(?i)(&lt;\\s*script\\b[^>]*>[^&lt;]+&lt;\\s*.+\\s*[s][c][r][i][p][t]\\s*>)");
//    String pattern2 = "n\\s*\\\\\\\\\\s*slash";
//    String pattern3 = "n\\s*\\/\\s*slash";
//    String pattern4 = "n\\s*\\\\\"\\s*quotes";
//    String pattern5 = "n\\s*\\\\b\\s*space";
//    String pattern6 = "n\\s*\\\\f\\s*forwardfeed";
//    String pattern7 = "n\\s*\\\\n\\s*newline";
//    String pattern8 = "n\\s*\\\\r\\s*carria";
//    String pattern9 = "n\\s*\\\\t\\s*tab";
//    String pattern10 = "n\\s*\\\\uFFFF\\s*hex";
//    String pattern11 = "(?i)\\b(alter|create|delete|(drop\\s*table)|(truncate\\s*table)|exec(ute)?|(insert\\s*into)|merge|select|update|union( +all)?)\\b";
//    String pattern12 = "(?i)\\b\\d+\\b\\s*;\\s*(\\b(alter|create|delete|(drop\\s*table)|(truncate\\s*table)|exec(ute)?|(insert\\s*into)|merge|select|update|union( +all)?)\\b)\\s*\\w+";
//    String pattern13 = "(?i)\"\\s*\\bor\\b\\s*\"\\s*\"=\"";
//    //xpath threat
//    String pattern14 = "(?i)\\b(ancestor|ancestor-or-self|attribute|child|descendant|descendant-or-self|following|following-sibling|namespace|parent|preceding|preceding-sibling|self)\\b[\\s]*::.*=";
//    String pattern15 = "(?i)(/([\\w]+))(.*\\b(or)\\b)(.*(\\=))";
//    //SERVER SIDE
//    String pattern16 = StringEscapeUtils.unescapeXml("(?i)(&lt;!--\\s*#\\s*(include|exec|echo|config|printenv|fsize).*-->)");
//    String threatJS = "pattern_1,pattern_2,pattern_3,pattern_4,pattern_5,pattern_6,pattern_7,pattern_8,pattern_9,pattern_10";
//    String threatSQL = "pattern_11,pattern_12,pattern_13";
//    String threatServerSide = "pattern_16";
//    String threatXPath = "pattern_14,pattern_15";
//    String json1kb, json5kb, json10kb, json50kb, json100kb, json530kb, json530kbthreat, json530kbthreatSQLAndServer,
//            formDataWithBinaryData, formDataWithBinaryDataPng, formDataWithBinaryDataGif,
//            formDataWithBinaryDataGifWithThreat, formDataNoBoundary = null;
//
//
//
//    @DataProvider(name = "json1kb")
//    public Object[][] sample1kb(){
//        if(json1kb == null) {
//            json1kb = readFile("/sample_1KB.json");
//        }
//        return new Object[][]{{(Object)json1kb}};
//    }
//
//    @DataProvider(name = "json5kb")
//    public Object[][] sample5kb(){
//        if(json5kb == null) {
//            json5kb = readFile("/sample_5KB.json");
//        }
//        return new Object[][]{{(Object)json5kb}};
//    }
//
//    @DataProvider(name = "json10kb")
//    public Object[][] sample10kb(){
//        if(json10kb == null) {
//            json10kb = readFile("/sample_10KB.json");
//        }
//        return new Object[][]{{(Object)json10kb}};
//    }
//
//    @DataProvider(name = "json50kb")
//    public Object[][] sample50kb(){
//        if(json50kb == null) {
//           json50kb = "/sample_50KB.json";
//        }
//        return new Object[][]{{(Object)json50kb}};
//    }
//
//    @DataProvider(name = "json100kb")
//    public Object[][] sample100kb(){
//        if(json100kb == null) {
//           json100kb = readFile("/sample_100KB.json");
//        }
//        return new Object[][]{{(Object)json100kb}};
//    }
//
//    @DataProvider(name = "json530kb")
//    public Object[][] sample530kb(){
//        if(json530kb == null) {
//            json530kb = readFile("/sample_530KB.json");
//        }
//        return new Object[][]{{(Object)json530kb}};
//    }
//
//    @DataProvider(name = "json530kbthreat")
//    public Object[][] sample530kbthreat(){
//        if(json530kbthreat == null) {
//            json530kbthreat = readFile("/sample_530KBthreat.json");
//        }
//        return new Object[][]{{(Object)json530kbthreat}};
//    }
//
//    @DataProvider(name = "json530kbthreatSQLAndServer")
//    public Object[][] sample530kbthreatSQLAndThreat(){
//        if(json530kbthreatSQLAndServer == null) {
//            json530kbthreatSQLAndServer = readFile("/sample_530KBthreatSQLAndServer.json");
//        }
//        return new Object[][]{{(Object)json530kbthreatSQLAndServer}};
//    }
//
//
//    @DataProvider(name = "formDataWithBinaryData")
//    public Object[][] formDataWithBinaryData(){
//        if(formDataWithBinaryData == null) {
//            formDataWithBinaryData = readFile("/formPayloadWithFakeBinaryFile.txt");
//        }
//        return new Object[][]{{(Object)formDataWithBinaryData}};
//    }
//
//    @DataProvider(name = "formDataWithBinaryDataPng")
//    public Object[][] formDataWithBinaryDataPng(){
//        if(formDataWithBinaryDataPng == null) {
//            formDataWithBinaryDataPng = readFile("/formPayloadWithFakeBinaryPngFile.txt");
//        }
//        return new Object[][]{{(Object)formDataWithBinaryDataPng}};
//    }
//
//    @DataProvider(name = "formDataWithBinaryDataGif")
//    public Object[][] formDataWithBinaryDataGif(){
//        if(formDataWithBinaryDataGif == null) {
//            formDataWithBinaryDataGif = readFile("/formPayloadWithFakeBinaryGifFile.txt");
//        }
//        return new Object[][]{{(Object)formDataWithBinaryDataGif}};
//    }
//
//
//    @DataProvider(name = "formDataWithBinaryDataGifWithThreat")
//    public Object[][] formDataWithBinaryDataGifWithThreat(){
//        if(formDataWithBinaryDataGifWithThreat == null) {
//            formDataWithBinaryDataGifWithThreat = readFile("/formPayloadWithFakeBinaryGifFileWithThreat.txt");
//        }
//        return new Object[][]{{(Object)formDataWithBinaryDataGifWithThreat}};
//    }
//
//    @DataProvider(name = "formDataNoBoundary")
//    public Object[][] formDataNoBoundary(){
//        if(formDataNoBoundary == null) {
//            formDataNoBoundary = readFile("/formPayloadBinaryDataNoBoundary.txt");
//        }
//        return new Object[][]{{(Object)formDataNoBoundary}};
//    }
//
//    private String readFile(String filename){
//        StringBuilder sb = new StringBuilder();
//        try (BufferedReader br = new BufferedReader(
//                new InputStreamReader(ThreatCalloutTest.class.getResourceAsStream(filename)))) {
//            String line;
//            while ((line = br.readLine()) != null) {
//                sb.append(line);
//            }
//        } catch (IOException ex){
//            out.println("Unable to read sample_1kb.json file");
//        } finally {
//            return sb.toString();
//        }
//    }
//
//    @BeforeMethod
//    public void setUp() throws Exception {
//
//        msgCtxt = new MockUp<MessageContext>() {
//            private Map variables;
//            public void $init() {
//                variables = new HashMap();
//                //this constructor does not execute
//                //variables.put("request.content", "<script>console.log(test)</script>");
//            }
//
//            @Mock()
//            public <T> T getVariable(final String name){
//                if (variables == null) {
//                    variables = new HashMap();
//                }
//                return (T) variables.get(name);
//            }
//
//            @Mock()
//            public boolean setVariable(final String name, final Object value) {
//                if (variables == null) {
//                    variables = new HashMap();
//                }
//                variables.put(name, value);
//                return true;
//            }
//
//            @Mock()
//            public boolean removeVariable(final String name) {
//                if (variables == null) {
//                    variables = new HashMap();
//                }
//                if (variables.containsKey(name)) {
//                    variables.remove(name);
//                }
//                return true;
//            }
//
//        }.getMockInstance();
//
//        //msgCtxt.setVariable("request.content", "<script>console.log(test)</script>");
//
//        exeCtxt = new MockUp<ExecutionContext>(){ }.getMockInstance();
//    }
//
//    @AfterMethod
//    public void tearDown() throws Exception {
//
//    }
//
//    @Test(groups = { "private"})
//    public void testVarName() throws Exception {
//        Map<String, String> properties = new HashMap<>();
//
//        // GIVEN
//        String testVariable = "myvar";
//        ThreatCallout callout = new ThreatCallout(properties);
//
//        // WHEN
//        String result = method("varName").withReturnType(String.class).withParameterTypes(String.class).in(callout).invoke(testVariable);
//        // THEN
//        Assert.assertEquals(result, "threat_myvar");
//    }
//
//    @Test(groups = { "private"})
//    /*property values should be passed here*/
//    public void testResolvePropertyValue() throws Exception {
//        Map<String, String> properties = new HashMap<>();
//        properties.put("matchQueryParams", "true");
//        properties.put("matchHeaders", "true");
//        properties.put("match", "{request.content}");
//        properties.put("request.content", "<script>console.log(test)</script>");
//        msgCtxt.setVariable("request.content", "<script>console.log(test)</script>");
//
//        // GIVEN
//        String testVariable = "{request.content}";
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult calloutResult = callout.execute(msgCtxt, exeCtxt);
//        // WHEN
//        String result = method("resolvePropertyValue").withReturnType(String.class)
//                .withParameterTypes(String.class, MessageContext.class)
//                .in(callout)
//                .invoke(testVariable, msgCtxt);
//
//        // THEN
//        Assert.assertEquals(result, "<script>console.log(test)</script>");
//    }
//
//    @Test(groups = { "private"})
//    /*property values should be passed here*/
//    public void testResolvePropertyValueNoCurlyBraces() throws Exception {
//        Map<String, String> properties = new HashMap<>();
//        properties.put("matchQueryParams", "true");
//        properties.put("matchHeaders", "true");
//        properties.put("match", "{request.content}");
//        properties.put("request.content", "<script>console.log(test)</script>");
//
//        // GIVEN
//        String testVariable = "request.content";
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult calloutResult = callout.execute(msgCtxt, exeCtxt);
//        // WHEN
//        String result = method("resolvePropertyValue").withReturnType(String.class)
//                .withParameterTypes(String.class, MessageContext.class)
//                .in(callout)
//                .invoke(testVariable, msgCtxt);
//
//        // THEN
//        Assert.assertEquals(result, "request.content");
//    }
//
//    @Test(groups = { "private"})
//    public void testResolvePropertyValueBlank() throws Exception {
//        Map<String, String> properties = new HashMap<>();
//        properties.put("matchQueryParams", "true");
//        properties.put("matchHeaders", "true");
//        properties.put("match", "{request.content}");
//        properties.put("request.content", "<script>console.log(test)</script>");
//
//        // GIVEN
//        String testVariable = "";
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult calloutResult = callout.execute(msgCtxt, exeCtxt);
//        // WHEN
//        String result = method("resolvePropertyValue").withReturnType(String.class)
//                .withParameterTypes(String.class, MessageContext.class)
//                .in(callout)
//                .invoke(testVariable, msgCtxt);
//
//        // THEN
//        Assert.assertEquals(result, "");
//    }
//
//    @Test(groups = { "private"})
//    public void testResolvePropertyValueNull() throws Exception {
//        Map<String, String> properties = new HashMap<>();
//        properties.put("matchQueryParams", "true");
//        properties.put("matchHeaders", "true");
//        properties.put("match", "{request.content}");
//        properties.put("request.content", "<script>console.log(test)</script>");
//
//        // GIVEN
//        String testVariable = null;
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult calloutResult = callout.execute(msgCtxt, exeCtxt);
//        // WHEN
//        String result = method("resolvePropertyValue").withReturnType(String.class)
//                .withParameterTypes(String.class, MessageContext.class)
//                .in(callout)
//                .invoke(testVariable, msgCtxt);
//
//        // THEN
//        Assert.assertEquals(result, null);
//    }
//
//    @Test(groups = { "private"})
//    public void testGetPropertyValue() throws Exception {
//        Map<String, String> properties = new HashMap<>();
//        properties.put("matchQueryParams", "true");
//        properties.put("matchHeaders", "true");
//        properties.put("match", "{request.content}");
//        properties.put("request.content", "<script>console.log(test)</script>");
//        msgCtxt.setVariable("request.content", "<script>console.log(test)</script>");
//
//        // GIVEN
//        String testVariable = "match";
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult calloutResult = callout.execute(msgCtxt, exeCtxt);
//        // WHEN
//        String result = method("getProperty").withReturnType(String.class)
//                .withParameterTypes(String.class, MessageContext.class)
//                .in(callout)
//                .invoke(testVariable, msgCtxt);
//
//        // THEN
//        Assert.assertEquals(result, "<script>console.log(test)</script>");
//
//    }
//
//    @Test(groups = { "private"},
//            expectedExceptions = IllegalStateException.class)
//    public void testGetPropertyValueNull() throws Exception {
//        Map<String, String> properties = new HashMap<>();
//        properties.put("matchQueryParams", "true");
//        properties.put("matchHeaders", "true");
//        properties.put("match", "{request.content}");
//        properties.put("request.content", "<script>console.log(test)</script>");
//
//        // GIVEN
//        String testVariable = null;
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult calloutResult = callout.execute(msgCtxt, exeCtxt);
//        // WHEN
//        String result = method("getProperty").withReturnType(String.class)
//                .withParameterTypes(String.class, MessageContext.class)
//                .in(callout)
//                .invoke(testVariable, msgCtxt);
//
//    }
//
//    @Test(groups = { "private"},
//            expectedExceptions = IllegalStateException.class)
//    public void testGetPropertyValueBlank() throws Exception {
//        Map<String, String> properties = new HashMap<>();
//        properties.put("matchQueryParams", "true");
//        properties.put("matchHeaders", "true");
//        properties.put("match", "{request.content}");
//        properties.put("request.content", "<script>console.log(test)</script>");
//
//        // GIVEN
//        String testVariable = "";
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult calloutResult = callout.execute(msgCtxt, exeCtxt);
//        // WHEN
//        String result = method("getProperty").withReturnType(String.class)
//                .withParameterTypes(String.class, MessageContext.class)
//                .in(callout)
//                .invoke(testVariable, msgCtxt);
//
//    }
//
//    @Test(groups = { "private"},
//            expectedExceptions = IllegalStateException.class)
//    public void testGetPropertyValueDoesNotExist() throws Exception {
//        Map<String, String> properties = new HashMap<>();
//        properties.put("matchQueryParams", "true");
//        properties.put("matchHeaders", "true");
//        properties.put("match", "{request.content}");
//        properties.put("request.content", "<script>console.log(test)</script>");
//
//        // GIVEN
//        String testVariable = "test";
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult calloutResult = callout.execute(msgCtxt, exeCtxt);
//        // WHEN
//        String result = method("getProperty").withReturnType(String.class)
//                .withParameterTypes(String.class, MessageContext.class)
//                .in(callout)
//                .invoke(testVariable, msgCtxt);
//
//    }
//
//
//    @Test(groups = { "private"})
//    public void testGetOptionalPropertyValue() throws Exception {
//        Map<String, String> properties = new HashMap<>();
//        properties.put("matchQueryParams", "true");
//        properties.put("matchHeaders", "true");
//        properties.put("match", "{request.content}");
//        properties.put("request.content", "<script>console.log(test)</script>");
//        msgCtxt.setVariable("request.content", "<script>console.log(test)</script>");
//
//        // GIVEN
//        String testVariable = "match";
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult calloutResult = callout.execute(msgCtxt, exeCtxt);
//        // WHEN
//        String result = method("getOptionalProperty").withReturnType(String.class)
//                .withParameterTypes(String.class, MessageContext.class)
//                .in(callout)
//                .invoke(testVariable, msgCtxt);
//
//        // THEN
//        Assert.assertEquals(result, "<script>console.log(test)</script>");
//
//    }
//
//    /*
//    @Test(groups = { "private"},
//            expectedExceptions = IllegalStateException.class)
//     */
//    @Test(groups = { "private"})
//    public void testGetOptionalPropertyValueNull() throws Exception {
//        Map<String, String> properties = new HashMap<>();
//        properties.put("matchQueryParams", "true");
//        properties.put("matchHeaders", "true");
//        properties.put("match", "{request.content}");
//        properties.put("request.content", "<script>console.log(test)</script>");
//
//        // GIVEN
//        String testVariable = null;
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult calloutResult = callout.execute(msgCtxt, exeCtxt);
//        // WHEN
//        String result = method("getOptionalProperty").withReturnType(String.class)
//                .withParameterTypes(String.class, MessageContext.class)
//                .in(callout)
//                .invoke(testVariable, msgCtxt);
//
//    }
//
//    /*
//    @Test(groups = { "private"},
//            expectedExceptions = IllegalStateException.class)
//     */
//    @Test(groups = { "private"})
//    public void testGetOptionalPropertyValueBlank() throws Exception {
//        Map<String, String> properties = new HashMap<>();
//        properties.put("matchQueryParams", "true");
//        properties.put("matchHeaders", "true");
//        properties.put("match", "{request.content}");
//        properties.put("request.content", "<script>console.log(test)</script>");
//
//        // GIVEN
//        String testVariable = "";
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult calloutResult = callout.execute(msgCtxt, exeCtxt);
//        // WHEN
//        String result = method("getOptionalProperty").withReturnType(String.class)
//                .withParameterTypes(String.class, MessageContext.class)
//                .in(callout)
//                .invoke(testVariable, msgCtxt);
//    }
//
//    /*
//     @Test(groups = { "private"},
//            expectedExceptions = IllegalStateException.class)
//     */
//    @Test(groups = { "private"})
//    public void testGetOptionalPropertyValueDoesNotExist() throws Exception {
//        Map<String, String> properties = new HashMap<>();
//        properties.put("matchQueryParams", "true");
//        properties.put("matchHeaders", "true");
//        properties.put("match", "{request.content}");
//        properties.put("request.content", "<script>console.log(test)</script>");
//
//        // GIVEN
//        String testVariable = "test";
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult calloutResult = callout.execute(msgCtxt, exeCtxt);
//        // WHEN
//        String result = method("getOptionalProperty").withReturnType(String.class)
//                .withParameterTypes(String.class, MessageContext.class)
//                .in(callout)
//                .invoke(testVariable, msgCtxt);
//    }
//
//    @Test(groups = { "private"})
//    public void testListProperties() throws Exception {
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_1", "(?i)(&lt;\\s*script\\b[^>]*>[^&lt;]+&lt;\\s*.+\\s*[s][c][r][i][p][t]\\s*>)");
//        properties.put("pattern_2", "n\\s*\\\\\\\\\\s*slash");
//        properties.put("pattern_3", "n\\s*\\/\\s*slash");
//        properties.put("pattern_4", "n\\s*\\\\\"s*quotes");
//        properties.put("pattern_5", "n\\s*\\\\b\\s*space");
//        properties.put("pattern_6", "n\\s*\\\\f\\s*forwardfeed");
//        properties.put("pattern_7", "n\\s*\\\\n\\s*newline");
//
//        // GIVEN
//        String testVariable = "pattern_";
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult calloutResult = callout.execute(msgCtxt, exeCtxt);
//        // WHEN
//        Map<String, String> result = method("getListProperties").withReturnType(Map.class)
//                .withParameterTypes(String.class)
//                .in(callout)
//                .invoke(testVariable);
//
//        // THEN
//        Assert.assertEquals(result.size(), 7);
//    }
//
//    @Test(groups = { "private"})
//    public void testListPropertiesInvalidPrefix() throws Exception {
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_1", "(?i)(&lt;\\s*script\\b[^>]*>[^&lt;]+&lt;\\s*.+\\s*[s][c][r][i][p][t]\\s*>)");
//        properties.put("pattern_2", "n\\s*\\\\\\\\\\s*slash");
//        properties.put("pattern_3", "n\\s*\\/\\s*slash");
//        properties.put("pattern_4", "n\\s*\\\\\"s*quotes");
//        properties.put("pattern_5", "n\\s*\\\\b\\s*space");
//        properties.put("pattern_6", "n\\s*\\\\f\\s*forwardfeed");
//        properties.put("pattern_7", "n\\s*\\\\n\\s*newline");
//
//        // GIVEN
//        String testVariable = "talk";
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult calloutResult = callout.execute(msgCtxt, exeCtxt);
//        // WHEN
//        Map<String, String> result = method("getListProperties").withReturnType(Map.class)
//                .withParameterTypes(String.class)
//                .in(callout)
//                .invoke(testVariable);
//
//        // THEN
//        Assert.assertEquals(result.size(), 0);
//    }
//
//
//    @Test(groups = { "private"})
//    public void testGetThreatPatterns() throws Exception {
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_1", "(?i)(&lt;\\s*script\\b[^>]*>[^&lt;]+&lt;\\s*.+\\s*[s][c][r][i][p][t]\\s*>)");
//        properties.put("pattern_2", "n\\s*\\\\\\\\\\s*slash");
//        properties.put("pattern_3", "n\\s*\\/\\s*slash");
//        properties.put("pattern_4", "n\\s*\\\\\"s*quotes");
//        properties.put("pattern_5", "n\\s*\\\\b\\s*space");
//        properties.put("pattern_6", "n\\s*\\\\f\\s*forwardfeed");
//        properties.put("pattern_7", "n\\s*\\\\n\\s*newline");
//        properties.put("pattern_7", "n\\s*\\\\n\\s*newline");
//        properties.put("pattern_8", "n\\s*\\\\r\\s*carria");
//        properties.put("pattern_9", "n\\s*\\\\t\\s*tab");
//        properties.put("pattern_10", "n\\s*\\\\uFFFF\\s*hex");
//        properties.put("pattern_11", "(?i)';\\b(alter|create|delete|(drop\\s*table)|(truncate\\s*table)|exec(ute)?|(insert\\s*into)|merge|select|update|union( +all)?)\\b");
//        properties.put("pattern_12", "(?i)\\b\\d+\\b\\s*;\\s*(\\b(alter|create|delete|(drop\\s*table)|(truncate\\s*table)|exec(ute)?|(insert\\s*into)|merge|select|update|union( +all)?)\\b)\\s*\\w+");
//        properties.put("pattern_13", "(?i)\"\\s*\\bor\\b\\s*\"\\s*\"=\"");
//        properties.put("pattern_14", "(?i)\\b(ancestor|ancestor-or-self|attribute|child|descendant|descendant-or-self|following|following-sibling|namespace|parent|preceding|preceding-sibling|self)\\b[\\s]*::.*=");
//        properties.put("pattern_15", "(?i)(/([\\w]+))(.*\\b(or)\\b)(.*(\\=))");
//        properties.put("pattern_16", "(?i)(&lt;!--\\s*#\\s*(include|exec|echo|config|printenv|fsize).*-->)");
//        properties.put("threat_js", "pattern_1,pattern_2,pattern_3,pattern_4,pattern_5,pattern_6,pattern_7,pattern_8,pattern_9,pattern_10");
//        //properties.put("threat_sql", "pattern_11,pattern_12,pattern_13");
//        //properties.put("threat_xpath", "pattern_14,pattern_15");
//        //properties.put("threat_serverside", "pattern_16");
//
//        // GIVEN
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult calloutResult = callout.execute(msgCtxt, exeCtxt);
//        // WHEN
//        Map<String, List<Pattern>> result = method("getThreatPatterns").withReturnType(Map.class)
//                .withParameterTypes(MessageContext.class)
//                .in(callout)
//                .invoke(msgCtxt);
//
//        // THEN
//        Assert.assertEquals(result.size(), 1);
//        Assert.assertEquals(result.get("threat_js").size(), 10);
//    }
//
//    @Test(groups = { "private"})
//    public void testGetThreatPatternsMissingThreatPatterns() throws Exception {
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_1", "(?i)(&lt;\\s*script\\b[^>]*>[^&lt;]+&lt;\\s*.+\\s*[s][c][r][i][p][t]\\s*>)");
//        properties.put("pattern_2", "n\\s*\\\\\\\\\\s*slash");
//        properties.put("pattern_3", "n\\s*\\/\\s*slash");
//        properties.put("pattern_4", "n\\s*\\\\\"s*quotes");
//        properties.put("pattern_5", "n\\s*\\\\b\\s*space");
//        properties.put("pattern_6", "n\\s*\\\\f\\s*forwardfeed");
//        properties.put("pattern_7", "n\\s*\\\\n\\s*newline");
//        properties.put("pattern_7", "n\\s*\\\\n\\s*newline");
//        properties.put("pattern_8", "n\\s*\\\\r\\s*carria");
//        properties.put("pattern_9", "n\\s*\\\\t\\s*tab");
//        properties.put("pattern_10", "n\\s*\\\\uFFFF\\s*hex");
//        properties.put("pattern_11", "(?i)';\\b(alter|create|delete|(drop\\s*table)|(truncate\\s*table)|exec(ute)?|(insert\\s*into)|merge|select|update|union( +all)?)\\b");
//        properties.put("pattern_12", "(?i)\\b\\d+\\b\\s*;\\s*(\\b(alter|create|delete|(drop\\s*table)|(truncate\\s*table)|exec(ute)?|(insert\\s*into)|merge|select|update|union( +all)?)\\b)\\s*\\w+");
//        properties.put("pattern_13", "(?i)\"\\s*\\bor\\b\\s*\"\\s*\"=\"");
//        properties.put("pattern_14", "(?i)\\b(ancestor|ancestor-or-self|attribute|child|descendant|descendant-or-self|following|following-sibling|namespace|parent|preceding|preceding-sibling|self)\\b[\\s]*::.*=");
//        properties.put("pattern_15", "(?i)(/([\\w]+))(.*\\b(or)\\b)(.*(\\=))");
//        properties.put("pattern_16", "(?i)(&lt;!--\\s*#\\s*(include|exec|echo|config|printenv|fsize).*-->)");
//
//        // GIVEN
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult calloutResult = callout.execute(msgCtxt, exeCtxt);
//        // WHEN
//        Map<String, List<Pattern>> result = method("getThreatPatterns").withReturnType(Map.class)
//                .withParameterTypes(MessageContext.class)
//                .in(callout)
//                .invoke(msgCtxt);
//
//        // THEN
//        Assert.assertEquals(result, null);
//    }
//
//    @Test(groups = { "private"})
//    public void testGetThreatPatterns_ValidThreatMissingPattern() throws Exception {
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_1", "(?i)(&lt;\\s*script\\b[^>]*>[^&lt;]+&lt;\\s*.+\\s*[s][c][r][i][p][t]\\s*>)");
//        properties.put("pattern_2", "n\\s*\\\\\\\\\\s*slash");
//        properties.put("pattern_3", "n\\s*\\/\\s*slash");
//        properties.put("pattern_4", "n\\s*\\\\\"s*quotes");
//        properties.put("pattern_5", "n\\s*\\\\b\\s*space");
//        properties.put("pattern_6", "n\\s*\\\\f\\s*forwardfeed");
//        properties.put("pattern_7", "n\\s*\\\\n\\s*newline");
//        properties.put("pattern_7", "n\\s*\\\\n\\s*newline");
//        properties.put("pattern_8", "n\\s*\\\\r\\s*carria");
//        properties.put("pattern_9", "n\\s*\\\\t\\s*tab");
//        properties.put("threat_js", "pattern_1,pattern_2,pattern_3,pattern_4,pattern_5,pattern_6,pattern_7,pattern_8,pattern_9,pattern_10");
//
//        // GIVEN
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult calloutResult = callout.execute(msgCtxt, exeCtxt);
//        // WHEN
//        Map<String, List<Pattern>> result = method("getThreatPatterns").withReturnType(Map.class)
//                .withParameterTypes(MessageContext.class)
//                .in(callout)
//                .invoke(msgCtxt);
//
//        // THEN
//        Assert.assertEquals(result.size(), 1);
//        Assert.assertEquals(result.get("threat_js").size(), 9);
//    }
//
//    @Test(groups = { "private"})
//    public void testGetQueryParams_MatchQueryParamsIsFalse() throws Exception {
//        Map<String, String> properties = new HashMap<>();
//        properties.put("matchQueryParams", "false");
//
//        // GIVEN
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult calloutResult = callout.execute(msgCtxt, exeCtxt);
//        // WHEN
//        Map<String, Collection<String>> result = method("getQueryParams").withReturnType(Map.class)
//                .withParameterTypes(MessageContext.class)
//                .in(callout)
//                .invoke(msgCtxt);
//
//        // THEN
//        Assert.assertEquals(result, null);
//    }
//
//    @Test(groups = { "private"})
//    public void testGetQueryParams_MatchQueryParamsIsTrue() throws Exception {
//        Map<String, String> properties = new HashMap<>();
//        properties.put("matchQueryParams", "true");
//        msgCtxt.setVariable("request.queryparams.count", 4);
//        Collection<String> queryParamNames = new ArrayList<>();
//        queryParamNames.add("qp1");
//        queryParamNames.add("qp2");
//        queryParamNames.add("hackqp");
//        queryParamNames.add("qpempty");
//        queryParamNames = Collections.unmodifiableCollection(queryParamNames);
//        msgCtxt.setVariable("request.queryparams.names", queryParamNames);
//
//        Collection<String> queryParamValues = new ArrayList<>();
//        queryParamValues.add("queryvalue");
//
//        msgCtxt.setVariable("request.queryparam.qp1.values", Collections.unmodifiableCollection(queryParamValues));
//        queryParamValues = new ArrayList<>();
//        queryParamValues.add("queryparam2value1");
//        queryParamValues.add("queryParam2Value2");
//        msgCtxt.setVariable("request.queryparam.qp2.values", Collections.unmodifiableCollection(queryParamValues));
//
//        queryParamValues = new ArrayList<>();
//        queryParamValues.add("delete * from table");
//        queryParamValues.add("<script>console.log</script>");
//        msgCtxt.setVariable("request.queryparam.hackqp.values", Collections.unmodifiableCollection(queryParamValues));
//        msgCtxt.setVariable("request.queryparam.qpempty.values", null);
//
//        // GIVEN
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult calloutResult = callout.execute(msgCtxt, exeCtxt);
//        // WHEN
//        Map<String, Collection<String>> result = method("getQueryParams").withReturnType(Map.class)
//                .withParameterTypes(MessageContext.class)
//                .in(callout)
//                .invoke(msgCtxt);
//
//        // THEN
//        Assert.assertEquals(result.size(), 4);
//        Assert.assertEquals(result.get("qp1").size(), 1);
//        Assert.assertEquals(result.get("qp2").size(), 2);
//        Assert.assertEquals(result.get("hackqp").size(), 2);
//        Assert.assertEquals(result.get("qpempty"), null);
//    }
//
//
//    @Test(groups = { "private"})
//    public void testGetHeaders_MatchHeadersIsFalse() throws Exception {
//        Map<String, String> properties = new HashMap<>();
//        properties.put("matchHeaders", "false");
//
//        // GIVEN
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult calloutResult = callout.execute(msgCtxt, exeCtxt);
//        // WHEN
//        Map<String, Collection<String>> result = method("getHeaders").withReturnType(Map.class)
//                .withParameterTypes(MessageContext.class)
//                .in(callout)
//                .invoke(msgCtxt);
//
//        // THEN
//        Assert.assertEquals(result, null);
//    }
//
//    @Test(groups = { "private"})
//    public void testGetHeaders_MatchHeadersIsTrue() throws Exception {
//        Map<String, String> properties = new HashMap<>();
//        properties.put("matchHeaders", "true");
//
//        msgCtxt.setVariable("request.headers.count", 4);
//
//        Collection<String> headersNames = new ArrayList<>();
//        headersNames.add("header1");
//        headersNames.add("header2");
//        headersNames.add("hackheader");
//        headersNames.add("headerempty");
//        msgCtxt.setVariable("request.headers.names", Collections.unmodifiableCollection(headersNames));
//
//        Collection<String> headerValues = new ArrayList<>();
//        headerValues.add("headervalue");
//        msgCtxt.setVariable("request.header.header1.values", Collections.unmodifiableCollection(headerValues));
//
//        headerValues = new ArrayList<>();
//        headerValues.add("headervalue1");
//        headerValues.add("headerValue2");
//        msgCtxt.setVariable("request.header.header2.values", Collections.unmodifiableCollection(headerValues));
//
//        headerValues = new ArrayList<>();
//        headerValues.add("delete * from table");
//        headerValues.add("<script>console.log</script>");
//        msgCtxt.setVariable("request.header.hackheader.values", Collections.unmodifiableCollection(headerValues));
//        msgCtxt.setVariable("request.header.headerempty.values", null);
//
//        // GIVEN
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult calloutResult = callout.execute(msgCtxt, exeCtxt);
//        // WHEN
//        Map<String, Collection<String>> result = method("getHeaders").withReturnType(Map.class)
//                .withParameterTypes(MessageContext.class)
//                .in(callout)
//                .invoke(msgCtxt);
//
//        // THEN
//        Assert.assertEquals(result.size(), 4);
//        Assert.assertEquals(result.get("header1").size(), 1);
//        Assert.assertEquals(result.get("header2").size(), 2);
//        Assert.assertEquals(result.get("hackheader").size(), 2);
//        Assert.assertEquals(result.get("headerempty"), null);
//    }
//
//
//    @Test(groups = { "private"})
//    public void testGetPatterns_PatternIsNull() throws Exception {
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_1", "(?i)(&lt;\\s*script\\b[^>]*>[^&lt;]+&lt;\\s*.+\\s*[s][c][r][i][p][t]\\s*>)");
//        properties.put("pattern_2", "n\\s*\\\\\\\\\\s*slash");
//        properties.put("pattern_3", "n\\s*\\/\\s*slash");
//        properties.put("pattern_4", "n\\s*\\\\\"s*quotes");
//        properties.put("pattern_5", "n\\s*\\\\b\\s*space");
//        properties.put("pattern_6", "n\\s*\\\\f\\s*forwardfeed");
//        properties.put("pattern_7", "n\\s*\\\\n\\s*newline");
//        properties.put("pattern_7", "n\\s*\\\\n\\s*newline");
//        properties.put("pattern_8", "n\\s*\\\\r\\s*carria");
//        properties.put("pattern_9", "n\\s*\\\\t\\s*tab");
//
//        // GIVEN
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult calloutResult = callout.execute(msgCtxt, exeCtxt);
//        // WHEN
//        List<Pattern> result = method("getPatterns").withReturnType(List.class)
//                .withParameterTypes(MessageContext.class)
//                .in(callout)
//                .invoke(msgCtxt);
//
//        // THEN
//        Assert.assertEquals(result.size(), 9);
//    }
//
//    @Test(groups = { "private"},
//            expectedExceptions = IllegalStateException.class)
//    public void testGetPatterns_NoPatterns() throws Exception {
//        Map<String, String> properties = new HashMap<>();
//
//        // GIVEN
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult calloutResult = callout.execute(msgCtxt, exeCtxt);
//        // WHEN
//        List<Pattern> result = method("getPatterns").withReturnType(List.class)
//                .withParameterTypes(MessageContext.class)
//                .in(callout)
//                .invoke(msgCtxt);
//    }
//
//    /*
//    Test the pattern 1 detection in the payload
//     */
//    @Test
//    public void testExecute_Payload_Pattern1() throws Exception {
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_1", pattern1);
//        properties.put("threat_js", "pattern_1");
//        properties.put("matchQueryParams", "false");
//        properties.put("matchHeaders", "false");
//        properties.put("match", "{request.content}");
//
//        msgCtxt.setVariable("request.content", "<script>this is a test</script>");
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), "threat_js_");
//        String matchedPattern = msgCtxt.getVariable("threat_js_matched");
//        Assert.assertEquals(msgCtxt.getVariable("threat_js_matched"), pattern1);
//
//        callout = new ThreatCallout(properties);
//        msgCtxt.setVariable("request.content", "<script>console.log(password) < /script>");
//        result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), "threat_js_");
//        matchedPattern = msgCtxt.getVariable("threat_js_matched");
//        Assert.assertEquals(msgCtxt.getVariable("threat_js_matched"), StringEscapeUtils.unescapeXml("(?i)(&lt;\\s*script\\b[^>]*>[^&lt;]+&lt;\\s*.+\\s*[s][c][r][i][p][t]\\s*>)"));
//    }
//
//    /*
//   Test the pattern 1 detection in the header
//    */
//    @Test
//    public void testExecute_Header_Pattern1() throws Exception {
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_1", pattern1);
//        properties.put("threat_js", "pattern_1");
//        properties.put("matchQueryParams", "false");
//        properties.put("matchHeaders", "true");
//        properties.put("match", "{request.content}");
//
//        Map<String, String> headerNames = new HashMap<>();
//        headerNames.put("x-header", "<script>console.log(password)</script>");
//        setMsgCtxtHeaders(headerNames);
//
//        msgCtxt.setVariable("request.content", "ok");
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), "threat_js_x-header_");
//        String matchedPattern = msgCtxt.getVariable("threat_js_x-header_matched");
//        Assert.assertEquals(msgCtxt.getVariable("threat_js_x-header_matched"), pattern1);
//    }
//
//    /*
//   Test the pattern 1 detection in the query
//    */
//    @Test
//    public void testExecute_Query_Pattern1() throws Exception {
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_1", pattern1);
//        properties.put("threat_js", "pattern_1");
//        properties.put("matchQueryParams", "true");
//        properties.put("matchHeaders", "false");
//        properties.put("match", "{request.content}");
//
//        Map<String, String> queryParamNames = new HashMap<>();
//        queryParamNames.put("x-header", "<script>console.log(password)</script>");
//        setMsgCtxtQueryParams(queryParamNames);
//
//        msgCtxt.setVariable("request.content", "ok");
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), "threat_js_x-header_");
//        String matchedPattern = msgCtxt.getVariable("threat_js_x-header_matched");
//        Assert.assertEquals(msgCtxt.getVariable("threat_js_x-header_matched"), pattern1);
//    }
//
//    /*
//    Test all the Regex patterns in pattern 11 in the payload;
//     */
//    @Test
//    public void testExecute_Payload_Pattern11() throws Exception {
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_11", pattern11);
//        properties.put("threat_sql", "pattern_11");
//        properties.put("matchQueryParams", "false");
//        properties.put("matchHeaders", "false");
//        properties.put("match", "{request.content}");
//
//        String threatDescr = "threat_sql_";
//
//        // ALTER 1
//        msgCtxt.setVariable("request.content", "ALTER TABLE table_name ADD column_name datatype");
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        String matchedPattern = msgCtxt.getVariable(threatDescr + "matched");
//        Assert.assertEquals(msgCtxt.getVariable( threatDescr + "matched"), pattern11);
//
//        // ALTER 2
//        callout = new ThreatCallout(properties);
//        msgCtxt.setVariable("request.content", "<root></root> alter TABLE table_name DROP COLUMN column_name ");
//        result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable(threatDescr + "matched"), pattern11);
//
//        // CREATE
//        callout = new ThreatCallout(properties);
//        msgCtxt.setVariable("request.content", "<root></root> CREATE TABLE Persons\n" +
//                "(\n" +
//                "PersonID int,\n" +
//                "LastName varchar(255),\n" +
//                "FirstName varchar(255),\n" +
//                "Address varchar(255),\n" +
//                "City varchar(255)\n" +
//                ");");
//        result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable(threatDescr + "matched"), pattern11);
//
//
//        // CREATE
//        callout = new ThreatCallout(properties);
//        msgCtxt.setVariable("request.content", "<root></root> CREATE TABLE Persons\n" +
//                "(\n" +
//                "PersonID int,\n" +
//                "LastName varchar(255),\n" +
//                "FirstName varchar(255),\n" +
//                "Address varchar(255),\n" +
//                "City varchar(255)\n" +
//                ");");
//        result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable(threatDescr + "matched"), pattern11);
//
//        // CREATE
//        callout = new ThreatCallout(properties);
//        msgCtxt.setVariable("request.content", "<root></root> TRUNCATE TABLE tbl_name\n");
//        result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable(threatDescr + "matched"), pattern11);
//
//
//        // execute
//        callout = new ThreatCallout(properties);
//        msgCtxt.setVariable("request.content", "<root></root> execute myhack");
//        result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable(threatDescr + "matched"), pattern11);
//
//        // execute
//        callout = new ThreatCallout(properties);
//        msgCtxt.setVariable("request.content", "<root></root> exec myhack");
//        result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable(threatDescr + "matched"), pattern11);
//
//        // insert
//        callout = new ThreatCallout(properties);
//        msgCtxt.setVariable("request.content", "<root></root> INSERT INTO TABLE_NAME (column1, column2, column3)  \n" +
//                "VALUES (value1, value2, value3);");
//        result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable(threatDescr + "matched"), pattern11);
//
//        //merge
//        callout = new ThreatCallout(properties);
//        msgCtxt.setVariable("request.content", "<root></root> MERGE INTO Sales.SalesReason AS Target\n" +
//                "        USING (VALUES ('Recommendation','Other'), ('Review', 'Marketing'), ('Internet', 'Promotion'))\n" +
//                "        AS Source (NewName, NewReasonType)\n" +
//                "        ON Target.Name = Source.NewName");
//        result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable(threatDescr + "matched"), pattern11);
//
//        //select
//        callout = new ThreatCallout(properties);
//        msgCtxt.setVariable("request.content", "<root></root> select * from users");
//        result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable(threatDescr + "matched"), pattern11);
//
//        //update
//        callout = new ThreatCallout(properties);
//        msgCtxt.setVariable("request.content", "<root></root> UPDATE users\n" +
//                "SET username='username@email.com',password='password'\n" +
//                "WHERE username='myusername@email.com';");
//        result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable(threatDescr + "matched"), pattern11);
//
//        //union
//        callout = new ThreatCallout(properties);
//        msgCtxt.setVariable("request.content", "<root></root> SELECT column_name(s) FROM table1\n" +
//                "                UNION\n" +
//                "        SELECT column_name(s) FROM table2;");
//        result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable(threatDescr + "matched"), pattern11);
//    }
//
//    /*
//    Tests all the Regex patterns in pattern 12 in the payload.
//     */
//    @Test
//    public void testExecute_Payload_Pattern12() throws Exception {
//        String pattern = pattern12;
//        String threatDescr = "threat_sql_";
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_12", pattern);
//        properties.put("threat_sql", "pattern_12");
//        properties.put("matchQueryParams", "false");
//        properties.put("matchHeaders", "false");
//        properties.put("match", "{request.content}");
//
//        // ALTER 1
//        msgCtxt.setVariable("request.content", "1234 ; ALTER TABLE table_name ADD column_name datatype");
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable( threatDescr + "matched"), pattern);
//
//        // ALTER 1 - this one should succeed because pattern 12 requires a ; to be included
//        msgCtxt.setVariable("request.content", "ALTER TABLE table_name ADD column_name datatype");
//        callout = new ThreatCallout(properties);
//        result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result, ExecutionResult.SUCCESS);
//        //Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), null);
//        //Assert.assertEquals(msgCtxt.getVariable( threatDescr + "matched"), null);
//
//        // ALTER 2
//        callout = new ThreatCallout(properties);
//        msgCtxt.setVariable("request.content", " 1 ;      alter TABLE table_name DROP COLUMN column_name    ");
//        result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable(threatDescr + "matched"), pattern);
//
//        // CREATE
//        callout = new ThreatCallout(properties);
//        msgCtxt.setVariable("request.content", "  1 ;   CREATE TABLE Persons\n" +
//                "(\n" +
//                "PersonID int,\n" +
//                "LastName varchar(255),\n" +
//                "FirstName varchar(255),\n" +
//                "Address varchar(255),\n" +
//                "City varchar(255)\n" +
//                ");");
//        result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable(threatDescr + "matched"), pattern);
//
//
//        // CREATE
//        callout = new ThreatCallout(properties);
//        msgCtxt.setVariable("request.content", " 12 ;     CREATE TABLE Persons\n" +
//                "(\n" +
//                "PersonID int,\n" +
//                "LastName varchar(255),\n" +
//                "FirstName varchar(255),\n" +
//                "Address varchar(255),\n" +
//                "City varchar(255)\n" +
//                ");");
//        result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable(threatDescr + "matched"), pattern);
//
//        // CREATE
//        callout = new ThreatCallout(properties);
//        msgCtxt.setVariable("request.content", " 1 ;     TRUNCATE TABLE tbl_name\n");
//        result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable(threatDescr + "matched"), pattern);
//
//
//        // execute
//        callout = new ThreatCallout(properties);
//        msgCtxt.setVariable("request.content", " 1234 ;      execute myhack");
//        result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable(threatDescr + "matched"), pattern);
//
//        // execute
//        callout = new ThreatCallout(properties);
//        msgCtxt.setVariable("request.content", " 1234 ;      exec myhack");
//        result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable(threatDescr + "matched"), pattern);
//
//        // insert
//        callout = new ThreatCallout(properties);
//        msgCtxt.setVariable("request.content", " 1234 ;      INSERT INTO TABLE_NAME (column1, column2, column3)  \n" +
//                "VALUES (value1, value2, value3);");
//        result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable(threatDescr + "matched"), pattern);
//
//        //merge
//        callout = new ThreatCallout(properties);
//        msgCtxt.setVariable("request.content", " 1234 ;      MERGE INTO Sales.SalesReason AS Target\n" +
//                "        USING (VALUES ('Recommendation','Other'), ('Review', 'Marketing'), ('Internet', 'Promotion'))\n" +
//                "        AS Source (NewName, NewReasonType)\n" +
//                "        ON Target.Name = Source.NewName");
//        result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable(threatDescr + "matched"), pattern);
//
//        //update
//        callout = new ThreatCallout(properties);
//        msgCtxt.setVariable("request.content", " 9 ;      UPDATE users\n" +
//                "SET username='username@email.com',password='password'\n" +
//                "WHERE username='myusername@email.com';");
//        result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable(threatDescr + "matched"), pattern);
//
//        //union
//        callout = new ThreatCallout(properties);
//        msgCtxt.setVariable("request.content", " 1234 ;      SELECT column_name(s) FROM table1\n" +
//                "                UNION\n" +
//                "        SELECT column_name(s) FROM table2;");
//        result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable(threatDescr + "matched"), pattern);
//    }
//
//    /*
//    Not sure why this is failing... it could be an issue with how the Regex pattern is defined.
//    However, the same threat is detected by pattern 11 instead (see next threat below).
//     */
//    //@Test
//    public void testExecute_Pattern12SelectStatement() throws Exception {
//        String pattern = pattern12;
//        String threatDescr = "threat_sql_";
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_12", pattern);
//        properties.put("threat_sql", "pattern_12");
//        properties.put("matchQueryParams", "false");
//        properties.put("matchHeaders", "false");
//        properties.put("match", "{request.content}");
//
//        //select
//        ThreatCallout callout = new ThreatCallout(properties);
//        msgCtxt.setVariable("request.content", " 123 ; select * from users");
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable(threatDescr + "matched"), pattern);
//    }
//
//
//    /*
//    Tests all the select stmt pattern in pattern 11 in the payload.
//     */
//    @Test
//    public void testExecute_Payload_Pattern11SelectStatement() throws Exception {
//        String pattern = pattern11;
//        String threatDescr = "threat_sql_";
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_11", pattern);
//        properties.put("threat_sql", "pattern_11");
//        properties.put("matchQueryParams", "false");
//        properties.put("matchHeaders", "false");
//        properties.put("match", "{request.content}");
//
//        // ALTER 1
//        msgCtxt.setVariable("request.content", " 123 ; select * from users");
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable(threatDescr + "matched"), pattern);
//    }
//
//    /*
//    Test pattern 13 in the payload
//     */
//    @Test
//    public void testExecute_Payload_Pattern13() throws Exception {
//        String pattern = pattern13;
//        String threatDescr = "threat_sql_";
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_13", pattern);
//        properties.put("threat_sql", "pattern_13");
//        properties.put("matchQueryParams", "false");
//        properties.put("matchHeaders", "false");
//        properties.put("match", "{request.content}");
//
//        // ALTER 1
//        msgCtxt.setVariable("request.content", " \" or \" \"=\" 1");
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        String matchedPattern = msgCtxt.getVariable(threatDescr + "matched");
//        Assert.assertEquals(msgCtxt.getVariable( threatDescr + "matched"), pattern);
//    }
//
//    /*
//    Test what happens when there is the same threat in the header and payload
//     */
//    @Test
//    public void testExecute_Payload_Header_Pattern13() throws Exception {
//        String threatDescr = "threat_sql_x-header_";
//        String threat = " \" or \" \"=\" 1";
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_13", pattern13);
//        properties.put("threat_sql", "pattern_13");
//        properties.put("matchQueryParams", "false");
//        properties.put("matchHeaders", "true");
//        properties.put("match", "{request.content}");
//
//        // ALTER 1
//        msgCtxt.setVariable("request.content", threat);
//
//        Map<String, String> headerNames = new HashMap<>();
//        headerNames.put("x-header", threat);
//        setMsgCtxtHeaders(headerNames);
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        String matchedPattern = msgCtxt.getVariable(threatDescr + "matched");
//        Assert.assertEquals(msgCtxt.getVariable( "threat_sql_x-header_matched"), pattern13);
//        //Assert.assertEquals(msgCtxt.getVariable( "threat_sql_matched"), pattern13);
//    }
//
//    /*
//    Test what happens when there is a different threat in the header and payload.
//    This answers the question: what happens when you have a sql threat in the header and a different sql threat in the payload?
//     */
//    @Test
//    public void testExecute_Payload_Header_Pattern13_Pattern12() throws Exception {
//        String content = " \" or \" \"=\" 1";
//        String threatDescr = "threat_sql_x-header_";
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_12", pattern12);
//        properties.put("pattern_13", pattern13);
//        properties.put("threat_sql", "pattern_12,pattern_13");
//        properties.put("matchQueryParams", "false");
//        properties.put("matchHeaders", "true");
//        properties.put("match", "{request.content}");
//
//        // ALTER 1
//        msgCtxt.setVariable("request.content", content);
//
//        Map<String, String> headerNames = new HashMap<>();
//        headerNames.put("x-header", "1234 ; ALTER TABLE table_name ADD column_name datatype");
//        setMsgCtxtHeaders(headerNames);
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        String matchedPattern = msgCtxt.getVariable(threatDescr + "matched");
//        Assert.assertEquals(msgCtxt.getVariable( "threat_sql_x-header_matched"), pattern12);
//        //Assert.assertEquals(msgCtxt.getVariable( "threat_sql_matched"), pattern13);
//    }
//
//    /*
//    Test what happens when there is a different threat in the header and payload for different threat types.
//    This answers the question:
//    what happens when you have a sql threat in the header and a JavaScript threat in the payload?
//     */
//    @Test
//    public void testExecute_Payload_Header_Pattern1_Pattern12() throws Exception {
//        String content = "<xml><script>console.log(password)</script></xml>";
//        String threatDescr = "threat_sql_x-header_";
//
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_12", pattern12);
//        properties.put("pattern_1", pattern1);
//        properties.put("threat_js", "pattern_1");
//        properties.put("threat_sql", "pattern_12");
//        properties.put("matchQueryParams", "false");
//        properties.put("matchHeaders", "true");
//        properties.put("match", "{request.content}");
//
//        // ALTER 1
//        msgCtxt.setVariable("request.content", content);
//
//        Map<String, String> headerNames = new HashMap<>();
//        headerNames.put("x-header", "1234 ; ALTER TABLE table_name ADD column_name datatype");
//        setMsgCtxtHeaders(headerNames);
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        String matchedPattern = msgCtxt.getVariable(threatDescr + "matched");
//        Assert.assertEquals(msgCtxt.getVariable( "threat_sql_x-header_matched"), pattern12);
//        //Assert.assertEquals(msgCtxt.getVariable( "threat_js_matched"), pattern1);
//    }
//
//    /*
//    Empty Payload test! -> What should the result be3?
//    use case: if I submit a GET request (no payload) then this will fail and raise an exception.
//
//    Test what happens when there is a threat in the header and a different threat in the query param.
//    This answers the question:
//    what happens when you have a server side threat threat in the queryparam and a xpath threat in the header?
//     */
//    @Test
//    public void testExecute_queryparam_Header_Pattern14_Pattern16_EmptyPayload() throws Exception {
//        String content = "  ancestor::employee = ";
//        String threatDescr = "threat_server_queryparam2_";
//
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_14", pattern14); //xpath
//        properties.put("pattern_16", pattern16); //serverside includes
//        properties.put("threat_js", "pattern_14");
//        properties.put("threat_server", "pattern_16");
//        properties.put("matchQueryParams", "true");
//        properties.put("matchHeaders", "true");
//        properties.put("match", "{request.content}");
//
//        // ALTER 1
//        msgCtxt.setVariable("request.content", "");
//
//        Map<String, String> queryParamNames = new HashMap<>();
//        queryParamNames.put("queryparam1", "value1");
//        queryParamNames.put("queryparam2", "value2,<!--#include file=\"myhackerscript.exe\"-->");
//        setMsgCtxtQueryParams(queryParamNames);
//
//        Map<String, String> headerNames = new HashMap<>();
//        headerNames.put("x-header1", "headervalue1");
//        headerNames.put("x-header2", content);
//        setMsgCtxtHeaders(headerNames);
//
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable( "threat_server_queryparam2_matched"), pattern16);
//        Assert.assertEquals(msgCtxt.getVariable( "threat_js_matched"), null);
//    }
//
//    /*
//    Test what happens when there is a threat in the header and a different threat in the query param.
//    This answers the question:
//    what happens when you have a server side threat threat in the queryparam and a xpath threat in the header?
//     */
//    @Test
//    public void testExecute_queryparam_Header_Pattern14_Pattern16() throws Exception {
//        String content = "  ancestor::employee = ";
//        String threatDescr = "threat_server_queryparam2_";
//
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_14", pattern14); //xpath
//        properties.put("pattern_16", pattern16); //serverside includes
//        properties.put("threat_js", "pattern_14");
//        properties.put("threat_server", "pattern_16");
//        properties.put("matchQueryParams", "true");
//        properties.put("matchHeaders", "true");
//        properties.put("match", "{request.content}");
//
//        // ALTER 1
//        msgCtxt.setVariable("request.content", "temp");
//
//        Map<String, String> queryParamNames = new HashMap<>();
//        queryParamNames.put("queryparam1", "value1");
//        queryParamNames.put("queryparam2", "value2,<!--#include file=\"myhackerscript.exe\"-->");
//        setMsgCtxtQueryParams(queryParamNames);
//
//        Map<String, String> headerNames = new HashMap<>();
//        headerNames.put("x-header1", "headervalue1");
//        headerNames.put("x-header2", content);
//        setMsgCtxtHeaders(headerNames);
//
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable( "threat_server_queryparam2_matched"), pattern16);
//        Assert.assertEquals(msgCtxt.getVariable( "threat_js_x-header2_matched"), null);
//
//    }
//
//
//    /*
//    Test: what happens when I specify a pattern in a threat but it is not included it as a property?.
//    threat_warnings is populated with an error for the pattern.
//
//     */
//    @Test
//    public void testExecute_queryparam_Header_Pattern14_Pattern16_MissingPattern15() throws Exception {
//        String content = "  ancestor::employee = ";
//        String threatDescr = "threat_server_queryparam2_";
//        String threatWarning = "pattern_15 is not specified or is empty.|";
//
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_14", pattern14); //xpath
//        properties.put("pattern_16", pattern16); //serverside includes
//        properties.put("threat_js", "pattern_14, pattern_15");//pattern 15 is missing
//        properties.put("threat_server", "pattern_16");
//        properties.put("matchQueryParams", "true");
//        properties.put("matchHeaders", "true");
//        properties.put("match", "{request.content}");
//
//        // ALTER 1
//        msgCtxt.setVariable("request.content", "temp");
//
//        Map<String, String> queryParamNames = new HashMap<>();
//        queryParamNames.put("queryparam1", "value1");
//        queryParamNames.put("queryparam2", "value2,<!--#include file=\"myhackerscript.exe\"-->");
//        setMsgCtxtQueryParams(queryParamNames);
//
//        Map<String, String> headerNames = new HashMap<>();
//        headerNames.put("x-header1", "headervalue1");
//        headerNames.put("x-header2", content);
//        setMsgCtxtHeaders(headerNames);
//
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable( "threat_server_queryparam2_matched"), pattern16);
//        Assert.assertEquals(msgCtxt.getVariable( "threat_js_x-header2_matched"), null);
//        Assert.assertEquals(msgCtxt.getVariable("threat_warnings"), threatWarning);
//    }
//
//    /*
//    Test: What happens if I include an invalid regular expression?.
//    result: an error will be thrown from the callout (Execution.ABORT)
//     */
//    @Test
//    public void testExecute_InvalidRegex () throws Exception {
//        String content = "  ancestor::employee = ";
//        String threatDescr = "threat_server_queryparam2_";
//
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_invalid", "(? [x 2"); //xpath
//        properties.put("threat_js", "pattern_invalid");//pattern 15 is missing
//        properties.put("matchQueryParams", "false");
//        properties.put("matchHeaders", "false");
//        properties.put("match", "{request.content}");
//
//        // ALTER 1
//        msgCtxt.setVariable("request.content", "temp");
//
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), null);
//        boolean containsException = ((String)msgCtxt.getVariable( "threat_error")).contains("java.util.regex.PatternSyntaxException");
//        Assert.assertEquals(containsException, true);
//        Assert.assertEquals(msgCtxt.getVariable( "threat_reason"), "Unknown inline modifier near index 2\n" +
//                "(? [x 2\n" +
//                "  ^");
//        Assert.assertNotEquals(msgCtxt.getVariable( "threat_stacktrace"), null);
//
//    }
//
//    /*
//    Test: what happens if matchHeaders is missing?.
//    ThreatCallout should throw an exception!
//     */
//    @Test
//    public void testExecute_matchHeadersIsMissing() throws Exception {
//        String content = "  ancestor::employee = ";
//        String threatDescr = "threat_server_queryparam2_";
//
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_14", pattern14); //xpath
//        properties.put("pattern_16", pattern16); //serverside includes
//        properties.put("threat_js", "pattern_14, pattern_15");//pattern 15 is missing
//        properties.put("threat_server", "pattern_16");
//        properties.put("matchQueryParams","false");
//        properties.put("match", "{request.content}");
//
//        // ALTER 1
//        msgCtxt.setVariable("request.content", "temp");
//
//        Map<String, String> headerNames = new HashMap<>();
//        headerNames.put("x-header1", "headervalue1");
//        headerNames.put("x-header2", content);
//        setMsgCtxtHeaders(headerNames);
//
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), null);
//        //System.out.println(msgCtxt.getVariable("threat_error"));
//        boolean containsException = ((String)msgCtxt.getVariable( "threat_error")).contains("java.lang.IllegalStateException: matchHeaders is not specified or is empty.");
//        Assert.assertEquals(containsException, true);
//        Assert.assertEquals(msgCtxt.getVariable( "threat_reason"), "matchHeaders is not specified or is empty.");
//        Assert.assertNotEquals(msgCtxt.getVariable( "threat_stacktrace"), null);
//    }
//
//    /*
//    Test: what happens if I matchHeaders does not contain a valid value?.
//    ThreatCallout should raise an exception.
//     */
//    @Test
//    public void testExecute_matchHeadersIsBlank() throws Exception {
//        String content = "  ancestor::employee = ";
//        String threatDescr = "threat_server_queryparam2_";
//
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_14", pattern14); //xpath
//        properties.put("pattern_16", pattern16); //serverside includes
//        properties.put("threat_js", "pattern_14, pattern_15");//pattern 15 is missing
//        properties.put("threat_server", "pattern_16");
//        properties.put("matchQueryParams", "false");
//        properties.put("matchHeaders", "");
//        properties.put("match", "{request.content}");
//
//        // ALTER 1
//        msgCtxt.setVariable("request.content", "temp");
//
//        Map<String, String> headerNames = new HashMap<>();
//        headerNames.put("x-header1", "headervalue1");
//        headerNames.put("x-header2", content);
//        setMsgCtxtHeaders(headerNames);
//
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), null);
//        //System.out.println(msgCtxt.getVariable("threat_error"));
//        boolean containsException = ((String)msgCtxt.getVariable( "threat_error")).contains("java.lang.IllegalStateException: matchHeaders is not specified or is empty.");
//        Assert.assertEquals(containsException, true);
//        Assert.assertEquals(msgCtxt.getVariable( "threat_reason"), "matchHeaders is not specified or is empty.");
//        Assert.assertNotEquals(msgCtxt.getVariable( "threat_stacktrace"), null);
//    }
//
//
//    /*
//   Test: what happens when matchqueryparams missing?.
//   ThreatCallout should raise an exception
//    */
//    @Test
//    public void testExecute_matchQueryParams_Missing() throws Exception {
//        String content = "  ancestor::employee = ";
//        String threatDescr = "threat_server_queryparam2_";
//
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_14", pattern14); //xpath
//        properties.put("pattern_16", pattern16); //serverside includes
//        properties.put("threat_js", "pattern_14, pattern_15");//pattern 15 is missing
//        properties.put("threat_server", "pattern_16");
//        properties.put("matchHeaders", "false");
//        properties.put("match", "{request.content}");
//
//        // ALTER 1
//        msgCtxt.setVariable("request.content", "temp");
//
//        Map<String, String> queryParamNames = new HashMap<>();
//        queryParamNames.put("queryparam1", "value1");
//        queryParamNames.put("queryparam2", "value2,<!--#include file=\"myhackerscript.exe\"-->");
//        setMsgCtxtQueryParams(queryParamNames);
//
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), null);
//        //System.out.println(msgCtxt.getVariable("threat_error"));
//        boolean containsException = ((String)msgCtxt.getVariable( "threat_error")).contains("java.lang.IllegalStateException: matchQueryParams is not specified or is empty.");
//        Assert.assertEquals(containsException, true);
//        Assert.assertEquals(msgCtxt.getVariable( "threat_reason"), "matchQueryParams is not specified or is empty.");
//    }
//
//    /*
//   Test: what happens when matchqueryparams is blank?.
//   ThreatCallout should raise an exception
//    */
//    @Test
//    public void testExecute_matchQueryParams_IsBlank() throws Exception {
//        String content = "  ancestor::employee = ";
//        String threatDescr = "threat_server_queryparam2_";
//
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_14", pattern14); //xpath
//        properties.put("pattern_16", pattern16); //serverside includes
//        properties.put("threat_js", "pattern_14, pattern_15");//pattern 15 is missing
//        properties.put("threat_server", "pattern_16");
//        properties.put("matchHeaders", "false");
//        properties.put("matchQueryParams", "");
//        properties.put("match", "{request.content}");
//
//        // ALTER 1
//        msgCtxt.setVariable("request.content", "temp");
//
//        Map<String, String> queryParamNames = new HashMap<>();
//        queryParamNames.put("queryparam1", "value1");
//        queryParamNames.put("queryparam2", "value2,<!--#include file=\"myhackerscript.exe\"-->");
//        setMsgCtxtQueryParams(queryParamNames);
//
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), null);
//        //System.out.println(msgCtxt.getVariable("threat_error"));
//        boolean containsException = ((String)msgCtxt.getVariable( "threat_error")).contains("java.lang.IllegalStateException: matchQueryParams is not specified or is empty.");
//        Assert.assertEquals(containsException, true);
//        Assert.assertEquals(msgCtxt.getVariable( "threat_reason"), "matchQueryParams is not specified or is empty.");
//    }
//
//    /*
//  Test: what happens when matchqueryparams contains an invalid value?.
//  ThreatCallout should raise an exception
//   */
//    @Test
//    public void testExecute_matchQueryParams_IsInvalid() throws Exception {
//        String content = "  ancestor::employee = ";
//        String threatDescr = "threat_server_queryparam2_";
//
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_14", pattern14); //xpath
//        properties.put("pattern_16", pattern16); //serverside includes
//        properties.put("threat_js", "pattern_14, pattern_15");//pattern 15 is missing
//        properties.put("threat_server", "pattern_16");
//        properties.put("matchHeaders", "false");
//        properties.put("matchQueryParams", "ffalse");
//        properties.put("match", "{request.content}");
//
//        // ALTER 1
//        msgCtxt.setVariable("request.content", "temp");
//
//        Map<String, String> queryParamNames = new HashMap<>();
//        queryParamNames.put("queryparam1", "value1");
//        queryParamNames.put("queryparam2", "value2,<!--#include file=\"myhackerscript.exe\"-->");
//        setMsgCtxtQueryParams(queryParamNames);
//
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), null);
//        boolean containsException = ((String)msgCtxt.getVariable( "threat_error")).contains("java.lang.IllegalStateException: matchQueryParams contains an invalid value. Expecting true or false but it contains 'ffalse'");
//        Assert.assertEquals(containsException, true);
//        Assert.assertEquals(msgCtxt.getVariable( "threat_reason"), "matchQueryParams contains an invalid value. Expecting true or false but it contains 'ffalse'");
//    }
//
//    /*
// Test: what sql threat passed in query parameter.
// ThreatCallout should raise an exception
//  */
//    @Test
//    public void testExecute_SQLThreatInQueryParam() throws Exception {
//        String content = "  test ";
//        String threatDescr = "threat_sql_queryparam2_";
//
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_11", pattern11);
//        //properties.put("threat_js", "pattern_14, pattern_15");//pattern 15 is missing
//        properties.put("threat_sql", "pattern_11");
//        properties.put("matchHeaders", "false");
//        properties.put("matchQueryParams", "true");
//        properties.put("match", "{request.content}");
//
//        // ALTER 1
//        msgCtxt.setVariable("request.content", "temp");
//
//        Map<String, String> queryParamNames = new HashMap<>();
//        queryParamNames.put("queryparam1", "value1");
//        queryParamNames.put("queryparam2", ";alter");
//        setMsgCtxtQueryParams(queryParamNames);
//
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable( "threat_sql_queryparam2_matched"), pattern11);
//    }
//
//
//    /*
//    what happens if the match property is not included in the Java Callout?
//    result: request.content should be checked instead.
//     */
//    @Test
//    public void testExecute_matchPropertyIsNotIncluded() throws Exception {
//        String content = "  ancestor::employee = ";
//        String threatDescr = "threat_xpath_";
//
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_14", pattern14); //xpath
//        properties.put("pattern_16", pattern16); //serverside includes
//        properties.put("threat_xpath", "pattern_14");//pattern 15 is missing
//        properties.put("threat_server", "pattern_16");
//        properties.put("matchHeaders", "false");
//        properties.put("matchQueryParams", "false");
//
//        // ALTER 1
//        msgCtxt.setVariable("request.content", content);
//
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable("threat_xpath_matched"), pattern14);
//    }
//
//    /*
//    what happens if the match property is included in the Java Callout, but evaluates to blank?
//    result: request.content should be checked instead.
//     */
//    @Test
//    public void testExecute_matchPropertyIncludedButEvaluatesToNullOrBlank() throws Exception {
//        String content = "  ancestor::employee = ";
//        String threatDescr = "threat_xpath_";
//
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_14", pattern14); //xpath
//        properties.put("pattern_16", pattern16); //serverside includes
//        properties.put("threat_xpath", "pattern_14");//pattern 15 is missing
//        properties.put("threat_server", "pattern_16");
//        properties.put("matchHeaders", "false");
//        properties.put("matchQueryParams", "false");
//        properties.put("match", "{response.content}");
//
//        // ALTER 1
//        msgCtxt.setVariable("request.content", content);
//
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable("threat_xpath_matched"), pattern14);
//    }
//
//    /*
//   Test a 1KB JSON payload
//   result: No threat detected in this payload.
//    */
//    @Test(dataProvider = "json1kb")
//    public void testExecute_1KBJsonPayload(String json) throws Exception {
//        String content = json;
//        String threatDescr = null;
//
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_1", pattern1);
//        properties.put("pattern_2", pattern2);
//        properties.put("pattern_3", pattern3);
//        properties.put("pattern_4", pattern4);
//        properties.put("pattern_5", pattern5);
//        properties.put("pattern_6", pattern6);
//        properties.put("pattern_7", pattern7);
//        properties.put("pattern_8", pattern8);
//        properties.put("pattern_9", pattern9);
//        properties.put("pattern_10", pattern10);
//        properties.put("pattern_11", pattern11);
//        properties.put("pattern_12", pattern12);
//        properties.put("pattern_13", pattern13);
//        properties.put("pattern_14", pattern14);
//        properties.put("pattern_15", pattern15); //xpath
//        properties.put("pattern_16", pattern16); //serverside includes
//        properties.put("threat_xpath", threatXPath);//pattern 15 is missing
//        properties.put("threat_server", threatServerSide);
//        properties.put("threat_sql", threatSQL);
//        properties.put("threat_js", threatJS);
//        properties.put("matchHeaders", "false");
//        properties.put("matchQueryParams", "false");
//        properties.put("match", "{response.content}");
//
//        msgCtxt.setVariable("request.content", content);
//
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result, ExecutionResult.SUCCESS);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable("threat_xpath_matched"), null);
//    }
//
//    /*
//  Test a 5KB JSON payload
//  result: No threat detected in this payload.
//   */
//    @Test(dataProvider = "json5kb")
//    public void testExecute_5KBJsonPayload(String json) throws Exception {
//        String content = json;
//        String threatDescr = null;
//
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_1", pattern1);
//        properties.put("pattern_2", pattern2);
//        properties.put("pattern_3", pattern3);
//        properties.put("pattern_4", pattern4);
//        properties.put("pattern_5", pattern5);
//        properties.put("pattern_6", pattern6);
//        properties.put("pattern_7", pattern7);
//        properties.put("pattern_8", pattern8);
//        properties.put("pattern_9", pattern9);
//        properties.put("pattern_10", pattern10);
//        properties.put("pattern_11", pattern11);
//        properties.put("pattern_12", pattern12);
//        properties.put("pattern_13", pattern13);
//        properties.put("pattern_14", pattern14);
//        properties.put("pattern_15", pattern15); //xpath
//        properties.put("pattern_16", pattern16); //serverside includes
//        properties.put("threat_xpath", threatXPath);//pattern 15 is missing
//        properties.put("threat_server", threatServerSide);
//        properties.put("threat_sql", threatSQL);
//        properties.put("threat_js", threatJS);
//        properties.put("matchHeaders", "false");
//        properties.put("matchQueryParams", "false");
//        properties.put("match", "{request.content}");
//
//        msgCtxt.setVariable("request.content", content);
//
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result, ExecutionResult.SUCCESS);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable("threat_xpath_matched"), null);
//    }
//
//    /*
//Test a 10KB JSON payload
//result: No threat detected in this payload.
// */
//    @Test(dataProvider = "json10kb")
//    public void testExecute_10KBJsonPayload(String json) throws Exception {
//        String content = json;
//        String threatDescr = null;
//
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_1", pattern1);
//        properties.put("pattern_2", pattern2);
//        properties.put("pattern_3", pattern3);
//        properties.put("pattern_4", pattern4);
//        properties.put("pattern_5", pattern5);
//        properties.put("pattern_6", pattern6);
//        properties.put("pattern_7", pattern7);
//        properties.put("pattern_8", pattern8);
//        properties.put("pattern_9", pattern9);
//        properties.put("pattern_10", pattern10);
//        properties.put("pattern_11", pattern11);
//        properties.put("pattern_12", pattern12);
//        properties.put("pattern_13", pattern13);
//        properties.put("pattern_14", pattern14);
//        properties.put("pattern_15", pattern15); //xpath
//        properties.put("pattern_16", pattern16); //serverside includes
//        properties.put("threat_xpath", threatXPath);//pattern 15 is missing
//        properties.put("threat_server", threatServerSide);
//        properties.put("threat_sql", threatSQL);
//        properties.put("threat_js", threatJS);
//        properties.put("matchHeaders", "false");
//        properties.put("matchQueryParams", "false");
//        properties.put("toMatch", "{request.content}");
//
//        msgCtxt.setVariable("request.content", content);
//
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result, ExecutionResult.SUCCESS);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable("threat_xpath_matched"), null);
//    }
//
//    /*
//Test a 50KB JSON payload
//result: No threat detected in this payload.
// */
//    @Test(dataProvider = "json50kb")
//    public void testExecute_50KBJsonPayload(String json) throws Exception {
//        String content = json;
//        String threatDescr = null;
//
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_1", pattern1);
//        properties.put("pattern_2", pattern2);
//        properties.put("pattern_3", pattern3);
//        properties.put("pattern_4", pattern4);
//        properties.put("pattern_5", pattern5);
//        properties.put("pattern_6", pattern6);
//        properties.put("pattern_7", pattern7);
//        properties.put("pattern_8", pattern8);
//        properties.put("pattern_9", pattern9);
//        properties.put("pattern_10", pattern10);
//        properties.put("pattern_11", pattern11);
//        properties.put("pattern_12", pattern12);
//        properties.put("pattern_13", pattern13);
//        properties.put("pattern_14", pattern14);
//        properties.put("pattern_15", pattern15); //xpath
//        properties.put("pattern_16", pattern16); //serverside includes
//        properties.put("threat_xpath", threatXPath);//pattern 15 is missing
//        properties.put("threat_server", threatServerSide);
//        properties.put("threat_sql", threatSQL);
//        properties.put("threat_js", threatJS);
//        properties.put("matchHeaders", "false");
//        properties.put("matchQueryParams", "false");
//        properties.put("toMatch", "{request.content}");
//
//        msgCtxt.setVariable("request.content", content);
//
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result, ExecutionResult.SUCCESS);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable("threat_xpath_matched"), null);
//    }
//
//    /*
//Test a 100KB JSON payload
//result: No threat detected in this payload.
// */
//    @Test(dataProvider = "json100kb")
//    public void testExecute_100KBJsonPayload(String json) throws Exception {
//        String content = json;
//        String threatDescr = null;
//
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_1", pattern1);
//        properties.put("pattern_2", pattern2);
//        properties.put("pattern_3", pattern3);
//        properties.put("pattern_4", pattern4);
//        properties.put("pattern_5", pattern5);
//        properties.put("pattern_6", pattern6);
//        properties.put("pattern_7", pattern7);
//        properties.put("pattern_8", pattern8);
//        properties.put("pattern_9", pattern9);
//        properties.put("pattern_10", pattern10);
//        properties.put("pattern_11", pattern11);
//        properties.put("pattern_12", pattern12);
//        properties.put("pattern_13", pattern13);
//        properties.put("pattern_14", pattern14);
//        properties.put("pattern_15", pattern15); //xpath
//        properties.put("pattern_16", pattern16); //serverside includes
//        properties.put("threat_xpath", threatXPath);//pattern 15 is missing
//        properties.put("threat_server", threatServerSide);
//        properties.put("threat_sql", threatSQL);
//        properties.put("threat_js", threatJS);
//        properties.put("matchHeaders", "false");
//        properties.put("matchQueryParams", "false");
//        properties.put("toMatch", "{request.content}");
//
//        msgCtxt.setVariable("request.content", content);
//
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result, ExecutionResult.SUCCESS);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable("threat_xpath_matched"), null);
//    }
//
//    /*
//    Test a 530KB JSON payload
//    result: No threat detected in this payload.
//     */
//    @Test(dataProvider = "json530kb")
//    public void testExecute_530KBJsonPayload(String json) throws Exception {
//        String content = json;
//        String threatDescr = null;
//
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_1", pattern1);
//        properties.put("pattern_2", pattern2);
//        properties.put("pattern_3", pattern3);
//        properties.put("pattern_4", pattern4);
//        properties.put("pattern_5", pattern5);
//        properties.put("pattern_6", pattern6);
//        properties.put("pattern_7", pattern7);
//        properties.put("pattern_8", pattern8);
//        properties.put("pattern_9", pattern9);
//        properties.put("pattern_10", pattern10);
//        properties.put("pattern_11", pattern11);
//        properties.put("pattern_12", pattern12);
//        properties.put("pattern_13", pattern13);
//        properties.put("pattern_14", pattern14);
//        properties.put("pattern_15", pattern15); //xpath
//        properties.put("pattern_16", pattern16); //serverside includes
//        properties.put("threat_xpath", threatXPath);//pattern 15 is missing
//        properties.put("threat_server", threatServerSide);
//        properties.put("threat_sql", threatSQL);
//        properties.put("threat_js", threatJS);
//        properties.put("matchHeaders", "false");
//        properties.put("matchQueryParams", "false");
//        properties.put("toMatch", "{request.content}");
//
//        msgCtxt.setVariable("request.content", content);
//
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result, ExecutionResult.SUCCESS);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable("threat_xpath_matched"), null);
//    }
//
//    /*
//    Test a 530KBthreat JSON payload
//    result: Threat detected in this payload.
//     */
//    @Test(dataProvider = "json530kbthreat")
//    public void testExecute_530KBthreatJsonPayload(String json) throws Exception {
//        String content = json;
//        String threatDescr = "threat_sql_";
//
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_1", pattern1);
//        properties.put("pattern_2", pattern2);
//        properties.put("pattern_3", pattern3);
//        properties.put("pattern_4", pattern4);
//        properties.put("pattern_5", pattern5);
//        properties.put("pattern_6", pattern6);
//        properties.put("pattern_7", pattern7);
//        properties.put("pattern_8", pattern8);
//        properties.put("pattern_9", pattern9);
//        properties.put("pattern_10", pattern10);
//        properties.put("pattern_11", pattern11);
//        properties.put("pattern_12", pattern12);
//        properties.put("pattern_13", pattern13);
//        properties.put("pattern_14", pattern14);
//        properties.put("pattern_15", pattern15); //xpath
//        properties.put("pattern_16", pattern16); //serverside includes
//        properties.put("threat_xpath", threatXPath);//pattern 15 is missing
//        properties.put("threat_server", threatServerSide);
//        properties.put("threat_sql", threatSQL);
//        properties.put("threat_js", threatJS);
//        properties.put("matchHeaders", "false");
//        properties.put("matchQueryParams", "false");
//        properties.put("toMatch", "{request.content}");
//
//        msgCtxt.setVariable("request.content", content);
//
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable("threat_sql_matched"), pattern11);
//    }
//
//    /*
//    Test a 530KBthreat JSON payload with SQL and Server threats
//    result: Threat detected in this payload.
//     */
//    @Test(dataProvider = "json530kbthreatSQLAndServer")
//    public void testExecute_530KBthreatJsonPayloadSQLAndServerThreat(String json) throws Exception {
//        String content = json;
//        String threatDescr = "threat_server_threat_sql_";
//
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_1", pattern1);
//        properties.put("pattern_2", pattern2);
//        properties.put("pattern_3", pattern3);
//        properties.put("pattern_4", pattern4);
//        properties.put("pattern_5", pattern5);
//        properties.put("pattern_6", pattern6);
//        properties.put("pattern_7", pattern7);
//        properties.put("pattern_8", pattern8);
//        properties.put("pattern_9", pattern9);
//        properties.put("pattern_10", pattern10);
//        properties.put("pattern_11", pattern11);
//        properties.put("pattern_12", pattern12);
//        properties.put("pattern_13", pattern13);
//        properties.put("pattern_14", pattern14);
//        properties.put("pattern_15", pattern15); //xpath
//        properties.put("pattern_16", pattern16); //serverside includes
//        properties.put("threat_xpath", threatXPath);//pattern 15 is missing
//        properties.put("threat_server", threatServerSide);
//        properties.put("threat_sql", threatSQL);
//        properties.put("threat_js", threatJS);
//        properties.put("matchHeaders", "false");
//        properties.put("matchQueryParams", "false");
//        properties.put("toMatch", "{request.content}");
//
//        msgCtxt.setVariable("request.content", content);
//
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable("threat_sql_matched"), pattern11);
//        Assert.assertEquals(msgCtxt.getVariable("threat_server_matched"), pattern16);
//    }
//
//    /*
//  Test a 530KBthreat JSON payload with SQL and Server threats
//  result: Threat detected in this payload.
//   */
//    @Test(dataProvider = "formDataWithBinaryData")
//    public void testExecute_binaryContent(String payload) throws Exception {
//        String content = payload;
//        String threatDescr = "threat_server_threat_sql_";
//
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_1", pattern1);
//        properties.put("pattern_2", pattern2);
//        properties.put("pattern_3", pattern3);
//        properties.put("pattern_4", pattern4);
//        properties.put("pattern_5", pattern5);
//        properties.put("pattern_6", pattern6);
//        properties.put("pattern_7", pattern7);
//        properties.put("pattern_8", pattern8);
//        properties.put("pattern_9", pattern9);
//        properties.put("pattern_10", pattern10);
//        properties.put("pattern_11", pattern11);
//        properties.put("pattern_12", pattern12);
//        properties.put("pattern_13", pattern13);
//        properties.put("pattern_14", pattern14);
//        properties.put("pattern_15", pattern15); //xpath
//        properties.put("pattern_16", pattern16); //serverside includes
//        properties.put("threat_xpath", threatXPath);//pattern 15 is missing
//        properties.put("threat_server", threatServerSide);
//        properties.put("threat_sql", threatSQL);
//        properties.put("threat_js", threatJS);
//        properties.put("matchHeaders", "false");
//        properties.put("matchQueryParams", "false");
//        properties.put("toMatch", "{request.content}");
//
//        msgCtxt.setVariable("request.content", content);
//        msgCtxt.setVariable("request.header.Content-type", "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW");
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.CONTINUE);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), null);
//        //Assert.assertEquals(msgCtxt.getVariable("threat_sql_matched"), pattern11);
//        //Assert.assertEquals(msgCtxt.getVariable("threat_server_matched"), pattern16);
//    }
//
//    @Test(dataProvider = "formDataWithBinaryDataPng")
//    public void testExecute_PngbinaryContent(String payload) throws Exception {
//        String content = payload;
//        String threatDescr = "threat_server_threat_sql_";
//
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_1", pattern1);
//        properties.put("pattern_2", pattern2);
//        properties.put("pattern_3", pattern3);
//        properties.put("pattern_4", pattern4);
//        properties.put("pattern_5", pattern5);
//        properties.put("pattern_6", pattern6);
//        properties.put("pattern_7", pattern7);
//        properties.put("pattern_8", pattern8);
//        properties.put("pattern_9", pattern9);
//        properties.put("pattern_10", pattern10);
//        properties.put("pattern_11", pattern11);
//        properties.put("pattern_12", pattern12);
//        properties.put("pattern_13", pattern13);
//        properties.put("pattern_14", pattern14);
//        properties.put("pattern_15", pattern15); //xpath
//        properties.put("pattern_16", pattern16); //serverside includes
//        properties.put("threat_xpath", threatXPath);//pattern 15 is missing
//        properties.put("threat_server", threatServerSide);
//        properties.put("threat_sql", threatSQL);
//        properties.put("threat_js", threatJS);
//        properties.put("matchHeaders", "false");
//        properties.put("matchQueryParams", "false");
//        properties.put("toMatch", "{request.content}");
//
//        msgCtxt.setVariable("request.content", content);
//        msgCtxt.setVariable("request.header.Content-type", "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW");
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.CONTINUE);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), null);
//        //Assert.assertEquals(msgCtxt.getVariable("threat_sql_matched"), pattern11);
//        //Assert.assertEquals(msgCtxt.getVariable("threat_server_matched"), pattern16);
//    }
//
//
//    /*
//    a threat is included in the content of the payload, however, it is in the
//    multipart payload for the file image.  This content should NOT
//    be checked when the image ext is .jpg, .jpeg, .gif, .tiff.
//    This is functioning correctly.
//     */
//    @Test(dataProvider = "formDataWithBinaryDataGif")
//    public void testExecute_GifbinaryContent(String payload) throws Exception {
//        String content = payload;
//        String threatDescr = "threat_server_threat_sql_";
//
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_1", pattern1);
//        properties.put("pattern_2", pattern2);
//        properties.put("pattern_3", pattern3);
//        properties.put("pattern_4", pattern4);
//        properties.put("pattern_5", pattern5);
//        properties.put("pattern_6", pattern6);
//        properties.put("pattern_7", pattern7);
//        properties.put("pattern_8", pattern8);
//        properties.put("pattern_9", pattern9);
//        properties.put("pattern_10", pattern10);
//        properties.put("pattern_11", pattern11);
//        properties.put("pattern_12", pattern12);
//        properties.put("pattern_13", pattern13);
//        properties.put("pattern_14", pattern14);
//        properties.put("pattern_15", pattern15); //xpath
//        properties.put("pattern_16", pattern16); //serverside includes
//        properties.put("threat_xpath", threatXPath);//pattern 15 is missing
//        properties.put("threat_server", threatServerSide);
//        properties.put("threat_sql", threatSQL);
//        properties.put("threat_js", threatJS);
//        properties.put("matchHeaders", "false");
//        properties.put("matchQueryParams", "false");
//        properties.put("toMatch", "{request.content}");
//
//        msgCtxt.setVariable("request.content", content);
//        msgCtxt.setVariable("request.header.Content-type", "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW");
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.CONTINUE);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), null);
//        //Assert.assertEquals(msgCtxt.getVariable("threat_sql_matched"), pattern11);
//        //Assert.assertEquals(msgCtxt.getVariable("threat_server_matched"), pattern16);
//    }
//
//    /*
//    a threat is included in the content of the payload.
//    This content SHOULD BE checked even when the image ext is .jpg, .jpeg, .gif, .tiff.
//            */
//    @Test(dataProvider = "formDataWithBinaryDataGifWithThreat")
//    public void testExecute_GifbinaryContentWithThreat(String payload) throws Exception {
//        String content = payload;
//        String threatDescr = "threat_sql_";
//
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_1", pattern1);
//        properties.put("pattern_2", pattern2);
//        properties.put("pattern_3", pattern3);
//        properties.put("pattern_4", pattern4);
//        properties.put("pattern_5", pattern5);
//        properties.put("pattern_6", pattern6);
//        properties.put("pattern_7", pattern7);
//        properties.put("pattern_8", pattern8);
//        properties.put("pattern_9", pattern9);
//        properties.put("pattern_10", pattern10);
//        properties.put("pattern_11", pattern11);
//        properties.put("pattern_12", pattern12);
//        properties.put("pattern_13", pattern13);
//        properties.put("pattern_14", pattern14);
//        properties.put("pattern_15", pattern15); //xpath
//        properties.put("pattern_16", pattern16); //serverside includes
//        properties.put("threat_xpath", threatXPath);//pattern 15 is missing
//        properties.put("threat_server", threatServerSide);
//        properties.put("threat_sql", threatSQL);
//        properties.put("threat_js", threatJS);
//        properties.put("matchHeaders", "false");
//        properties.put("matchQueryParams", "false");
//        properties.put("toMatch", "{request.content}");
//
//        msgCtxt.setVariable("request.content", content);
//        msgCtxt.setVariable("request.header.Content-type", "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW");
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        Assert.assertEquals(msgCtxt.getVariable("threat_sql_matched"), pattern11);
//        //Assert.assertEquals(msgCtxt.getVariable("threat_server_matched"), pattern16);
//    }
//
//    /*
//    a threat is included in the content of the payload, however, it is in the
//    multipart payload for the file image.  This content should NOT
//    be checked when the image ext is .jpg, .jpeg, .gif, .tiff.
//
//    Valid Content type header with boundary
//    Payload does not have a boundary, just simulated binary data.
//    fileame is filename="test.gif"
//    Threat Should be detected.
//     */
//    @Test(dataProvider = "formDataNoBoundary")
//    public void testExecute_GifbinaryContentNoBoundary_ValidContentType(String payload) throws Exception {
//        String content = payload;
//        String threatDescr = "threat_js_";
//
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_1", pattern1);
//        properties.put("pattern_2", pattern2);
//        properties.put("pattern_3", pattern3);
//        properties.put("pattern_4", pattern4);
//        properties.put("pattern_5", pattern5);
//        properties.put("pattern_6", pattern6);
//        properties.put("pattern_7", pattern7);
//        properties.put("pattern_8", pattern8);
//        properties.put("pattern_9", pattern9);
//        properties.put("pattern_10", pattern10);
//        properties.put("pattern_11", pattern11);
//        properties.put("pattern_12", pattern12);
//        properties.put("pattern_13", pattern13);
//        properties.put("pattern_14", pattern14);
//        properties.put("pattern_15", pattern15); //xpath
//        properties.put("pattern_16", pattern16); //serverside includes
//        properties.put("threat_xpath", threatXPath);//pattern 15 is missing
//        properties.put("threat_server", threatServerSide);
//        properties.put("threat_sql", threatSQL);
//        properties.put("threat_js", threatJS);
//        properties.put("matchHeaders", "false");
//        properties.put("matchQueryParams", "false");
//        properties.put("toMatch", "{request.content}");
//
//        msgCtxt.setVariable("request.content", content);
//        msgCtxt.setVariable("request.header.Content-type", "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW");
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        //Assert.assertEquals(msgCtxt.getVariable("threat_sql_matched"), pattern11);
//        //Assert.assertEquals(msgCtxt.getVariable("threat_server_matched"), pattern16);
//    }
//
//
//
//
//    /*
//    a threat is included in the content of the payload, however, it is in the
//    multipart payload for the file image.  This content should NOT
//    be checked when the image ext is .jpg, .jpeg, .gif, .tiff.
//    However, since this has an invalid content-type header (missing "boundary=", then this content
//    is checked and a threat is detected.
//     */
//    @Test(dataProvider = "formDataNoBoundary")
//    public void testExecute_GifbinaryContentNoBoundary_InvalidContentType(String payload) throws Exception {
//        String content = payload;
//        String threatDescr = "threat_js_";
//
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_1", pattern1);
//        properties.put("pattern_2", pattern2);
//        properties.put("pattern_3", pattern3);
//        properties.put("pattern_4", pattern4);
//        properties.put("pattern_5", pattern5);
//        properties.put("pattern_6", pattern6);
//        properties.put("pattern_7", pattern7);
//        properties.put("pattern_8", pattern8);
//        properties.put("pattern_9", pattern9);
//        properties.put("pattern_10", pattern10);
//        properties.put("pattern_11", pattern11);
//        properties.put("pattern_12", pattern12);
//        properties.put("pattern_13", pattern13);
//        properties.put("pattern_14", pattern14);
//        properties.put("pattern_15", pattern15); //xpath
//        properties.put("pattern_16", pattern16); //serverside includes
//        properties.put("threat_xpath", threatXPath);//pattern 15 is missing
//        properties.put("threat_server", threatServerSide);
//        properties.put("threat_sql", threatSQL);
//        properties.put("threat_js", threatJS);
//        properties.put("matchHeaders", "false");
//        properties.put("matchQueryParams", "false");
//        properties.put("toMatch", "{request.content}");
//
//        msgCtxt.setVariable("request.content", content);
//        msgCtxt.setVariable("request.header.Content-type", "multipart/form-data");
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        //Assert.assertEquals(msgCtxt.getVariable("threat_sql_matched"), pattern11);
//        //Assert.assertEquals(msgCtxt.getVariable("threat_server_matched"), pattern16);
//    }
//
//    /*
//    a threat is included in the content of the payload, however, it is in the
//    multipart payload for the file image.  This content should NOT
//    be checked when the image ext is .jpg, .jpeg, .gif, .tiff.
//
//    boundary=xyz which is invalid, so the entire content should be included in the threat check
//    Threat should be detected.
//
//     */
//    @Test(dataProvider = "formDataWithBinaryDataGif")
//    public void testExecute_GifbinaryContent_ValidContentType_InvalidBoundary(String payload) throws Exception {
//        String content = payload;
//        String threatDescr = "threat_js_";
//
//        Map<String, String> properties = new HashMap<>();
//        properties.put("pattern_1", pattern1);
//        properties.put("pattern_2", pattern2);
//        properties.put("pattern_3", pattern3);
//        properties.put("pattern_4", pattern4);
//        properties.put("pattern_5", pattern5);
//        properties.put("pattern_6", pattern6);
//        properties.put("pattern_7", pattern7);
//        properties.put("pattern_8", pattern8);
//        properties.put("pattern_9", pattern9);
//        properties.put("pattern_10", pattern10);
//        properties.put("pattern_11", pattern11);
//        properties.put("pattern_12", pattern12);
//        properties.put("pattern_13", pattern13);
//        properties.put("pattern_14", pattern14);
//        properties.put("pattern_15", pattern15); //xpath
//        properties.put("pattern_16", pattern16); //serverside includes
//        properties.put("threat_xpath", threatXPath);//pattern 15 is missing
//        properties.put("threat_server", threatServerSide);
//        properties.put("threat_sql", threatSQL);
//        properties.put("threat_js", threatJS);
//        properties.put("matchHeaders", "false");
//        properties.put("matchQueryParams", "false");
//        properties.put("toMatch", "{request.content}");
//
//        msgCtxt.setVariable("request.content", content);
//        msgCtxt.setVariable("request.header.Content-type", "multipart/form-data; boundary=xyz");
//        ThreatCallout callout = new ThreatCallout(properties);
//        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
//
//        Assert.assertEquals(result.getAction(), Action.ABORT);
//        Assert.assertEquals(msgCtxt.getVariable("detectedThreats"), threatDescr);
//        //Assert.assertEquals(msgCtxt.getVariable("threat_sql_matched"), pattern11);
//        //Assert.assertEquals(msgCtxt.getVariable("threat_server_matched"), pattern16);
//    }
//
//    /*
//    Helper function to set headers for a test case;
//    Single value: .put("x-header", "value"
//    Multiple values: .put("x-header", "value1,value2,value3"
//     */
//    public void setMsgCtxtHeaders(Map<String, String> headers){
//        msgCtxt.setVariable("request.headers.count", headers.size());
//        ArrayList<String> headerNames = new ArrayList<>();
//
//        for(Map.Entry<String, String> headerEntry: headers.entrySet()){
//            headerNames.add(headerEntry.getKey());
//            String [] valuesArray = headerEntry.getValue().split(",");
//            List<String> values = Arrays.asList(valuesArray);
//            msgCtxt.setVariable("request.header." + headerEntry.getKey() + ".values", values);
//        }
//        msgCtxt.setVariable("request.headers.names", Collections.unmodifiableCollection(headerNames));
//    }
//
//    /*
//    Helper function to set query parameters for a test case;
//    Single value: .put("queryparam", "value"
//    Multiple values: .put("queryparam", "value1,value2,value3"
//     */
//    public void setMsgCtxtQueryParams(Map<String, String> queryparams){
//        msgCtxt.setVariable("request.queryparams.count", queryparams.size());
//        ArrayList<String> queryParamNames = new ArrayList<>();
//
//        for(Map.Entry<String, String> queryParamEntry: queryparams.entrySet()){
//            queryParamNames.add(queryParamEntry.getKey());
//            String [] valuesArray = queryParamEntry.getValue().split(",");
//            List<String> values = Arrays.asList(valuesArray);
//            msgCtxt.setVariable("request.queryparam." + queryParamEntry.getKey() + ".values", values);
//        }
//        msgCtxt.setVariable("request.queryparams.names", Collections.unmodifiableCollection(queryParamNames));
//    }
//
//
//}