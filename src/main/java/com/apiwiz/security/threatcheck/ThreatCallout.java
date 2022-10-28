package com.apiwiz.security.threatcheck;

import java.io.FileNotFoundException;
import java.util.*;
import java.util.regex.Matcher;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.PropertiesConfiguration;

import java.util.regex.Pattern;

public class ThreatCallout {

    private final Map<String, String> properties;
    private static final String _varPrefix = "threat_";
    private static final int DEFAULT_NUM_THREATS = 5;
    private static final String TRUE = "true";
    private static final String FALSE = "false";
    private final String fileNamePattern = "filename=\".*\"";
    private final Pattern pattern;
    private final String[] validFileExts;
    private final String multipartFormData = "multipart/form-data";
    private final String CRCL = "\r\n";
    private final String BOUNDARY = "boundary=";

    public ThreatCallout(final Map properties) throws FileNotFoundException {
        this.pattern = Pattern.compile("filename=\".*\"");
        this.validFileExts = new String[]{".jpg", ".png", ".jpeg", ".bmp", ".gif", ".tiff"};
        final Map<String, String> m = new HashMap<String, String>();
        for (final Object key : properties.keySet()) {
            final Object value = properties.get(key);
            if (key instanceof String && value instanceof String) {
                m.put((String) key, (String) value);
            }
        }
        this.properties = m;
    }

    private static final String varName(final String s) {
        return "threat_" + s;
    }

    private String getProperty(final String prop, final Request request) throws IllegalStateException {
        return this.properties.get(prop);
    }

    private Map<String, String> getListProperties(final String propPrefix) {
        final Map<String, String> listProps = new HashMap<String, String>(5);
        for (final String key : this.properties.keySet()) {
            if (key.startsWith(propPrefix)) {
                listProps.put(key, this.properties.get(key));
            }
        }
        return listProps;
    }

    private List<Pattern> getPatterns(final Request request) throws IllegalStateException {
        List<Pattern> patterns = null;
        String pattern = null;
        try {
            pattern = this.getProperty("pattern", request);
        } catch (IllegalStateException e) {
            pattern = null;
        }
        if (pattern != null) {
            patterns = new ArrayList<Pattern>(1);
            patterns.add(Pattern.compile(pattern));
        } else {
            final Map<String, String> patternProps = this.getListProperties("pattern_");
            if (patternProps != null && patternProps.size() > 0) {
                patterns = new ArrayList<Pattern>(patternProps.size());
                for (final Map.Entry<String, String> entry : patternProps.entrySet()) {
                    final String p = entry.getValue();
                    patterns.add(Pattern.compile(p));
                }
            }
        }
        if (patterns == null || patterns.isEmpty()) {
            throw new IllegalStateException("Pattern is not specified or is empty.");
        }
        return patterns;
    }

    private Map<String, List<Pattern>> getThreatPatterns(final Request request) {
        Map<String, List<Pattern>> m = null;
        final Map<String, String> threatProps = this.getListProperties("threat_");
        final StringBuffer warnings = new StringBuffer();
        if (threatProps.size() > 0) {
            m = new HashMap<String, List<Pattern>>();
            for (final Map.Entry<String, String> entry : threatProps.entrySet()) {
                final String threat = entry.getKey();
                final String[] plist = entry.getValue().split("\\s*,\\s*");
                final ArrayList<Pattern> patterns = new ArrayList<Pattern>(plist.length);
                for (final String p : plist) {
                    String pattern = null;
                    try {
                        pattern = this.getProperty(p, request);
                    } catch (Exception e) {
                        warnings.append(e.getMessage());
                        warnings.append("|");
                    }
                    if (pattern != null && !pattern.equals("")) {
                        patterns.add(Pattern.compile(pattern));
                    }
                }
                m.put(threat, patterns);
            }
        }
        if (!warnings.equals("")) {
            request.setVariable("threat_warnings", warnings.toString());
        }
        return m;
    }

    private Map<String, Object> getQueryParams(final Request request) {
        try {
            Map<String, Object> qps = null;
            if ("true".equalsIgnoreCase(this.getProperty("queryParams", request))) {
                final int size = request.getQueryParams().entrySet().size();

                qps = new HashMap<String, Object>(size);
                for (Map.Entry<String, Object> entry : request.getQueryParams().entrySet()) {
                    String key = entry.getKey();
                    Object value = entry.getValue();
                    qps.put(key, value);
                }
            }
            return qps;
        } catch (NullPointerException ex) {
            return null;
        }
    }


    private Map<String, Object> getFormParams(final Request request) {
        try {
            Map<String, Object> fps = null;
            if ("true".equalsIgnoreCase(this.getProperty("formParams", request))) {
                final int size = request.getFormParams().entrySet().size();

                fps = new HashMap<String, Object>(size);
                for (Map.Entry<String, Object> entry : request.getFormParams().entrySet()) {
                    String key = entry.getKey();
                    Object value = entry.getValue();
                    fps.put(key, value);
                }
            }
            return fps;
        } catch (NullPointerException ex) {
            return null;
        }
    }

    private Map<String, Object> getHeaderParams(final Request request) {
        try {
            Map<String, Object> hps = null;
            if ("true".equalsIgnoreCase(this.getProperty("headerParams", request))) {
                final int size = request.getHeaderParams().entrySet().size();

                hps = new HashMap<String, Object>(size);
                for (Map.Entry<String, Object> entry : request.getHeaderParams().entrySet()) {
                    String key = entry.getKey();
                    Object value = entry.getValue();
                    hps.put(key, value);
                }
            }
            return hps;
        } catch (NullPointerException ex) {
            return null;
        }
    }


    private Map<String, Object> getPathParams(final Request request) {
        try {
            Map<String, Object> pps = null;
            if ("true".equalsIgnoreCase(this.getProperty("pathParams", request))) {
                final int size = request.getPathParams().entrySet().size();

                pps = new HashMap<String, Object>(size);
                for (Map.Entry<String, Object> entry : request.getPathParams().entrySet()) {
                    String key = entry.getKey();
                    Object value = entry.getValue();
                    pps.put(key, value);
                }
            }
            return pps;
        } catch (NullPointerException ex) {
            return null;
        }
    }

    private Map<String, Object> getPath(final Request request) {
        try {
            Map<String, Object> paths = new HashMap<>();
            if ("true".equalsIgnoreCase(this.getProperty("path", request))) {
                String key = "path";
                Object value = request.getPath();
                paths.put(key, value);
            }
            return paths;
        } catch (NullPointerException ex) {
            return null;
        }
    }

    private Map<String, Object> getRequestBody(final Request request) {
        try {
            Map<String, Object> paths = new HashMap<>();
            if ("true".equalsIgnoreCase(this.getProperty("requestBody", request))) {
                String key = "requestBody";
                Object value = request.getRequestBody();
                paths.put(key, value);
            }
            return paths;
        } catch (NullPointerException ex) {
            return null;
        }
    }

    public static void main(String[] args) throws Exception {
        String jsonReq =args[0];
        ObjectMapper mapper = new ObjectMapper();
        Request reqObj = mapper.readValue(jsonReq, Request.class);

        Map<String, String> properties = new HashMap<>();
        Configuration configuration = new PropertiesConfiguration("application.properties");

        try {
            for (Iterator<String> it = configuration.getKeys(); it.hasNext(); ) {
                String key = it.next();
                properties.put(key, configuration.getString(key));
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        // GIVEN
        ThreatCallout callout = new ThreatCallout(properties);
        Object res = callout.execute(reqObj);
        System.out.println("Result:::" + res.toString());
    }

    public Object execute(final Request request) {
        final StringBuffer detectedThreatsHps = new StringBuffer("");
        final StringBuffer detectedThreatsFps = new StringBuffer("");
        final StringBuffer detectedThreatsQps = new StringBuffer("");
        final StringBuffer detectedThreatsPps = new StringBuffer("");
        final StringBuffer detectedThreatsPaths = new StringBuffer("");
        final StringBuffer detectedThreatsreqbody = new StringBuffer("");
        final StringBuffer detectedThreatscontent = new StringBuffer("");
         StringBuffer detectedThreats = new StringBuffer("");


        boolean isThreatDetected = false;

        try {
            final Map<String, List<Pattern>> threatPatterns = this.getThreatPatterns(request);
            String toMatch = this.getProperty("match", request);
            if (toMatch == null || toMatch.equals("")) {
                toMatch = String.valueOf(request.getRequestBody());
            }
            final Map<String, Object> qps = this.getQueryParams(request);
            final Map<String, Object> fps = this.getFormParams(request);
            final Map<String, Object> hps = this.getHeaderParams(request);
            final Map<String, Object> pps = this.getPathParams(request);
            final Map<String, Object> paths = this.getPath(request);
            final Map<String, Object> requestBody = this.getRequestBody(request);
            final String matchQueryParams = this.getProperty("queryParams", request);
            final String matchFormParams = this.getProperty("formParams", request);
            final String matchHeaderParams = this.getProperty("headerParams", request);
            final String matchPathParams = this.getProperty("pathParams", request);
            final String matchPath = this.getProperty("path", request);
            final String matchRequestBody = this.getProperty("requestBody", request);


            if (!this.isValidOption(matchQueryParams)) {
                throw new IllegalStateException(
                        "matchQueryParams contains an invalid value. Expecting true or false but it contains '"
                                + matchQueryParams + "'");
            }
            if (qps != null && matchQueryParams.equals("true")) {
                detectedThreatsQps.append(this.checkRequestForThreats(request, qps, threatPatterns).trim());
                detectedThreats.append(detectedThreatsQps);
                if (!detectedThreatsQps.toString().equals("")) {
                    isThreatDetected = true;
                }
            }
            if (!this.isValidOption(matchFormParams)) {
                throw new IllegalStateException(
                        "matchFormParams contains an invalid value. Expecting true or false but it contains '"
                                + matchFormParams + "'");
            }
            if (fps != null && matchFormParams.equals("true")) {
                detectedThreatsFps.append(this.checkRequestForThreats(request, fps, threatPatterns).trim());
                detectedThreats.append(detectedThreatsFps);
                if (!detectedThreatsFps.toString().equals("")) {
                    isThreatDetected = true;
                }
            }
            if (!this.isValidOption(matchHeaderParams)) {
                throw new IllegalStateException(
                        "matchHeaderParams contains an invalid value. Expecting true or false but it contains '"
                                + matchHeaderParams + "'");
            }

            if (hps != null && matchHeaderParams.equals("true")) {
                detectedThreatsHps.append(this.checkRequestForThreats(request, hps, threatPatterns).trim());
                detectedThreats.append(detectedThreatsHps);
                if (!detectedThreatsHps.toString().equals("")) {
                    isThreatDetected = true;
                }
            }
            if (!this.isValidOption(matchPathParams)) {
                throw new IllegalStateException(
                        "matchPathParams contains an invalid value. Expecting true or false but it contains '"
                                + matchPathParams + "'");
            }

            if (pps != null && matchPathParams.equals("true")) {
                detectedThreatsPps.append(this.checkRequestForThreats(request, pps, threatPatterns).trim());
                detectedThreats.append(detectedThreatsPps);
                if (!detectedThreatsPps.toString().equals("")) {
                    isThreatDetected = true;
                }
            }

            if (!this.isValidOption(matchPath)) {
                throw new IllegalStateException(
                        "matchPath contains an invalid value. Expecting true or false but it contains '"
                                + matchPath + "'");
            }

            if (paths != null && matchPath.equals("true")) {
                detectedThreatsPaths.append(this.checkRequestForThreats(request, paths, threatPatterns).trim());
                detectedThreats.append(detectedThreatsPaths);
                if (!detectedThreatsPaths.toString().equals("")) {
                    isThreatDetected = true;
                }
            }

            if (!this.isValidOption(matchRequestBody)) {
                throw new IllegalStateException(
                        "matchRequestBody contains an invalid value. Expecting true or false but it contains '"
                                + matchRequestBody + "'");
            }

            if (requestBody != null && matchRequestBody.equals("true")) {
                detectedThreatsreqbody.append(this.checkRequestForThreats(request, requestBody, threatPatterns).trim());
                detectedThreats.append(detectedThreatsreqbody);
                if (!detectedThreatsreqbody.toString().equals("")) {
                    isThreatDetected = true;
                }
            }

            if (!isThreatDetected && !toMatch.equals("")) {
                if (request.getHeaderParams().containsKey("Content-Type")) {
                    final String contentType = String.valueOf(request.getHeaderParams().containsKey("Content-Type"));
                    if (contentType.contains("multipart/form-data") && contentType.contains("boundary=")) {
                        toMatch = this.parseMultiformPayload(request);
                    }
                }
                detectedThreatscontent.append(this.checkPayloadForThreats(request, threatPatterns, toMatch).trim());
                detectedThreats.append(detectedThreatscontent);
                if (!detectedThreatscontent.toString().equals("")) {
                    isThreatDetected = true;
                }
            }
            if (isThreatDetected) {
                List<Object> buffer = new ArrayList<Object>();
                String obj2 = detectedThreats.toString();
                Object objcontent = detectedThreatscontent.toString();
                Object objpps = detectedThreatsPps.toString();
                Object objfps = detectedThreatsFps.toString();
                Object objhps = detectedThreatsHps.toString();
                Object objpath = detectedThreatsPaths.toString();
                Object objreqbody = detectedThreatsreqbody.toString();
                buffer.add(objcontent);
                buffer.add(objpath);
                buffer.add(objfps);
                buffer.add(objhps);
                buffer.add(objpps);
                buffer.add(objreqbody);
                    if (obj2.contains("threat_js")) {
                        System.out.println(Result.JAVASCRIPT_THREAT_DETECTED);
                    }
                    if (obj2.contains("threat_sql")) {
                        System.out.println(Result.SQL_THREAT_DETECTED);
                    }
                    if (obj2.contains("threat_xpath")) {
                        System.out.println(Result.XPATH_THREAT_DETECTED);
                    }
                    if (obj2.contains("threat_serverside")) {
                        System.out.println(Result.SERVERSIDE_THREAT_DETECTED);
                    }

                buffer.removeAll(Arrays.asList("", null));
                return buffer;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return Result.EXCEPTION_OCCURRED;
        }
        return Result.SUCCESS;
    }


    private String parseMultiformPayload(final Request request) {
        String contentType = "";
        if (request.getHeaderParams().containsKey("Content-Type")) {
            contentType = (String) request.getHeaderParams().get("Content-Type");
        }
        final StringBuilder remainingContent = new StringBuilder();
        String formBoundary = contentType.split("=")[1];
        formBoundary = "--" + formBoundary;
        final String content = String.valueOf(request.getRequestBody());
        if (content != null && content != "") {
            final String[] bodyParts = content.split(formBoundary.trim());
            if (bodyParts.length == 1) {
                remainingContent.append(bodyParts[0]);
                return remainingContent.toString();
            }
            remainingContent.append(formBoundary + "\r\n");
            for (int i = 0; i < bodyParts.length; ++i) {
                final Matcher m = this.pattern.matcher(bodyParts[i]);
                if (m.find()) {
                    boolean validExtFound = false;
                    final String fileNameText = m.group(0);
                    final String fileName = fileNameText.substring(10, fileNameText.length() - 1);
                    for (int p = 0; p < this.validFileExts.length; ++p) {
                        if (fileName.endsWith(this.validFileExts[p])) {
                            validExtFound = true;
                            break;
                        }
                    }
                    if (!validExtFound) {
                        this.appendToRemainingContent(remainingContent, bodyParts[i], formBoundary + "\r\n");
                    }
                } else if (!bodyParts[i].equals("") && !bodyParts[i].equals("--")) {
                    this.appendToRemainingContent(remainingContent, bodyParts[i], formBoundary + "\r\n");
                }
            }
            remainingContent.append("--");
        }
        return remainingContent.toString();
    }

    private void appendToRemainingContent(final StringBuilder remainingContent, final String content,
                                          final String formBoundary) {
        remainingContent.append(content + "\r\n");
        remainingContent.append(formBoundary);
    }

    private boolean isValidOption(final String property) {
        return property.equalsIgnoreCase("true") || property.equalsIgnoreCase("false");
    }

    private String checkRequestForThreats(final Request request,
                                          final Map<String, Object> collection, final Map<String, List<Pattern>> threatPatterns)
            throws InterruptedException, IllegalStateException {
        StringBuffer detectedThreats = null;
        final List<RegularExpressionChecker> runQueue = new ArrayList<>(threatPatterns.size());
        if (collection != null && collection.size() > 0) {
            for (final Map.Entry<String, List<Pattern>> entry : threatPatterns.entrySet()) {
            final RegularExpressionChecker rec = new RegularExpressionCheckerMap(entry.getValue(), collection,
                         entry.getKey());
                rec.start();
                runQueue.add(rec);
            }
        }
        detectedThreats = this.joinThreads(request, runQueue);
        if (detectedThreats == null) {
            return "";
        }
        return detectedThreats.toString();
    }

    private String checkPayloadForThreats(final Request request, final Map<String, List<Pattern>> threatPatterns,
                                          final String toMatch) throws InterruptedException, IllegalStateException {
        StringBuffer detectedThreats = null;
        final List<RegularExpressionChecker> runQueue = new ArrayList<>(threatPatterns.size());
        for (final Map.Entry<String, List<Pattern>> entry : threatPatterns.entrySet()) {
            final RegularExpressionChecker rec = new RegularExpressionChecker(entry.getValue(), toMatch,
                    entry.getKey());
            rec.start();
            runQueue.add(rec);
        }
        detectedThreats = this.joinThreads(request, runQueue);
        if (detectedThreats == null) {
            return "";
        }
        return detectedThreats.toString();
    }

    private StringBuffer joinThreads(final Request request, final List<RegularExpressionChecker> runQueue)
            throws InterruptedException {
        StringBuffer detectedThreats = null;

        for (final RegularExpressionChecker r : runQueue) {
            r.join();
            if (r.isMatched()) {
                if (detectedThreats == null) {
                    detectedThreats = new StringBuffer();
                }
                detectedThreats.append(r.getName());
            }
        }
        return detectedThreats;
    }
}