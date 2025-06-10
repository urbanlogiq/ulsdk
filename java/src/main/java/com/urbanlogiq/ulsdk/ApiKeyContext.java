// Copyright (c), CommunityLogiq Software

package com.urbanlogiq.ulsdk;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.http.HttpResponse;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.URI;
import java.net.URLEncoder;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

public final class ApiKeyContext extends RequestContext {
    private static String canonicalizePath(String path) {
        if (path == null || path == "") {
            return "/";
        }

        if (!path.startsWith("/")) {
            return "/" + path;
        }

        return path;
    }

    private static String canonicalizeQueryString(List<Pair<String, String>> query) {
        if (query.isEmpty()) {
            return "";
        }

        query.sort((a, b) -> { return a.first().compareTo(b.first()); });

        ArrayList<String> components = new ArrayList();
        for (Pair<String, String> pair : query) {
            if (pair.first() == "X-UL-Signature") {
                continue;
            }

            String component = pair.first() + "=" + URLEncoder.encode(pair.second());
            components.add(component);
        }

        return String.join("&", components);
    }
    
    private static String canonicalizeHeaders(List<String> signedHeaders, HashMap<String, String> headers) {
        ArrayList<String> sortedSignedHeaders = new ArrayList();
        for (String header : signedHeaders) {
            sortedSignedHeaders.add(header.toLowerCase());
        }
        sortedSignedHeaders.sort(null);

        ArrayList<String> canonicalHeaderParts = new ArrayList();

        for (String v : sortedSignedHeaders) {
            try {
                String value = headers.get(v);
                canonicalHeaderParts.add(String.format("%s:%s", v, value));
            } catch (Exception e) {
                continue;
            }
        }

        return String.join("\n", canonicalHeaderParts);
    }

    private static Pair<String, String> canonicalizeRequest(String method, String path, List<Pair<String, String>> query, HashMap<String, String> headers, List<String> signedHeadersList, byte[] body) {
        String canonicalPath = canonicalizePath(path);
        String canonicalQueryString = canonicalizeQueryString(query);
        String canonicalHeaders = canonicalizeHeaders(signedHeadersList, headers);
        String signedHeaders = String.join(";", signedHeadersList);

        String s = String.format("%s\n%s\n%s\n%s\n%s\n%s",
            method.toUpperCase(),
            canonicalPath,
            canonicalQueryString,
            canonicalHeaders,
            signedHeaders,
            DigestUtils.sha256Hex(body)
        );

        return new Pair(DigestUtils.sha256Hex(s), signedHeaders);
    }

    private static String generateAuthHeader(Key key, String method, String path, List<Pair<String, String>> query, HashMap<String, String> headers, byte[] body) {
        long unixTime = System.currentTimeMillis() / 1000;
        String unixTimeString = Long.toString(unixTime);

        headers.put(HEADER_X_UL_DATE, unixTimeString);

        Pair<String, String> result = canonicalizeRequest(method, path, query, headers, SIGNED_HEADERS, body);
        String requestHash = result.first();
        String signedHeaders = result.second();

        String scope = String.format("%s/%s/%s/%s", key.userId().toString(), unixTimeString, key.region().toString(), REQUEST_TYPE);
        String signingString = String.format("%s\n%s\n%s", SIGNATURE_V1, scope, requestHash);
        byte[] signingBytes = signingString.getBytes();

        Ed25519PrivateKeyParameters params = new Ed25519PrivateKeyParameters(key.secretKey());
        Ed25519Signer signer = new Ed25519Signer();

        signer.init(true, params);
        signer.update(signingBytes, 0, signingBytes.length);
        byte[] signatureBytes = signer.generateSignature();

        String signature = Hex.encodeHexString(signatureBytes);

        return String.format(
            "%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
            SIGNATURE_V1,
            key.accessKey(),
            scope,
            signedHeaders,
            signature
        );
    }

    public ApiKeyContext(Key key, Environment environment) {
        this._key = key;
        this._environment = environment;
    }

    public Region region() {
        return this._key.region();
    }

    public Environment environment() {
        return this._environment;
    }

    public byte[] get(String path, List<Pair<String, String>> params, HashMap<String, String> headers) throws URISyntaxException, IOException, InterruptedException {
        String host = this.getHost(this.region(), this.environment());
        String authorizationHeader = generateAuthHeader(this._key, "GET", path, params, headers, new byte[0]);

        String query = null;

        if (params.size() > 0) {
            query = canonicalizeQueryString(params);
        }

        URI uri = new URI("https", host, path, query, null);

        ArrayList<String> headerStrings = new ArrayList();
        for (String k : headers.keySet()) {
            headerStrings.add(k);
            headerStrings.add(headers.get(k));
        }
        headerStrings.add("authorization");
        headerStrings.add(authorizationHeader);

        String[] headerStringsArray = new String[headerStrings.size()];
        headerStringsArray = headerStrings.toArray(headerStringsArray);

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest.Builder builder = HttpRequest.newBuilder().uri(uri);

        if (headerStringsArray.length > 0) {
            builder = builder.headers(headerStringsArray);
        }

        HttpRequest request = builder
            .GET()
            .build();

        HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
        int statusCode = response.statusCode();

        if (statusCode < 200 || statusCode >= 300) {
            throw new FailedRequestException(response);
        }

        return response.body();
    }

    public byte[] put(String path, byte[] body, String mimetype, List<Pair<String, String>> params, HashMap<String, String> headers) throws URISyntaxException, IOException, InterruptedException {
        if (body == null) {
            body = new byte[0];
        }

        String host = this.getHost(this.region(), this.environment());
        String authorizationHeader = generateAuthHeader(this._key, "PUT", path, params, headers, body);

        String query = null;

        if (params.size() > 0) {
            query = canonicalizeQueryString(params);
        }

        URI uri = new URI("https", host, path, query, null);

        ArrayList<String> headerStrings = new ArrayList();
        for (String k : headers.keySet()) {
            headerStrings.add(k);
            headerStrings.add(headers.get(k));
        }
        headerStrings.add("authorization");
        headerStrings.add(authorizationHeader);

        String[] headerStringsArray = new String[headerStrings.size()];
        headerStringsArray = headerStrings.toArray(headerStringsArray);

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest.Builder builder = HttpRequest.newBuilder().uri(uri);

        if (headerStringsArray.length > 0) {
            builder = builder.headers(headerStringsArray);
        }

        HttpRequest request = builder
            .PUT(HttpRequest.BodyPublishers.ofByteArray(body))
            .build();

        HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
        int statusCode = response.statusCode();

        if (statusCode < 200 || statusCode >= 300) {
            throw new FailedRequestException(response);
        }

        return response.body();
    }

    public byte[] post(String path, byte[] body, String mimetype, List<Pair<String, String>> params, HashMap<String, String> headers) throws URISyntaxException, IOException, InterruptedException {
        if (body == null) {
            body = new byte[0];
        }

        String host = this.getHost(this.region(), this.environment());
        String authorizationHeader = generateAuthHeader(this._key, "POST", path, params, headers, body);

        String query = null;

        if (params.size() > 0) {
            query = canonicalizeQueryString(params);
        }

        URI uri = new URI("https", host, path, query, null);

        ArrayList<String> headerStrings = new ArrayList();
        for (String k : headers.keySet()) {
            headerStrings.add(k);
            headerStrings.add(headers.get(k));
        }
        headerStrings.add("authorization");
        headerStrings.add(authorizationHeader);

        String[] headerStringsArray = new String[headerStrings.size()];
        headerStringsArray = headerStrings.toArray(headerStringsArray);

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest.Builder builder = HttpRequest.newBuilder().uri(uri);

        if (headerStringsArray.length > 0) {
            builder = builder.headers(headerStringsArray);
        }

        HttpRequest request = builder
            .POST(HttpRequest.BodyPublishers.ofByteArray(body))
            .build();

        HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
        int statusCode = response.statusCode();

        if (statusCode < 200 || statusCode >= 300) {
            throw new FailedRequestException(response);
        }

        return response.body();
    }

    public byte[] upload(String path, List<File> files) throws URISyntaxException, IOException, InterruptedException {
        long ts = System.currentTimeMillis();
        String boundary = String.format("UL1-multipart-%d", ts);
        byte[] dash = new byte[]{'-', '-'};
        byte[] boundaryStream = boundary.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] crlf = new byte[]{'\r', '\n'};

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (int i = 0; i < files.size(); i++) {
            File file = files.get(i);
            body.write(dash, 0, dash.length);
            body.write(boundaryStream, 0, boundaryStream.length);
            body.write(crlf, 0, crlf.length);

            String dispositionHeader = String.format("Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\nContent-Type: %s\r\n\r\n", file.getName(), file.getName(), file.getMimetype());
            byte[] dispositionHeaderBytes = dispositionHeader.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            body.write(dispositionHeaderBytes, 0, dispositionHeaderBytes.length);

            byte[] data = file.getData();
            body.write(data, 0, data.length);
        }

        body.write(dash, 0, dash.length);
        body.write(boundaryStream, 0, boundaryStream.length);
        body.write(dash, 0, dash.length);

        String mimetype = String.format("multipart/form-data; boundary=\"%s\"", boundary);

        List<Pair<String, String>> params = new ArrayList();
        HashMap<String, String> headers = new HashMap();

        return this.post(path, body.toByteArray(), mimetype, params, headers);
    }

    public byte[] delete(String path, List<Pair<String, String>> params, HashMap<String, String> headers) throws URISyntaxException, IOException, InterruptedException {
        String host = this.getHost(this.region(), this.environment());
        String authorizationHeader = generateAuthHeader(this._key, "DELETE", path, params, headers, new byte[0]);

        String query = null;

        if (params.size() > 0) {
            query = canonicalizeQueryString(params);
        }

        URI uri = new URI("https", host, path, query, null);

        ArrayList<String> headerStrings = new ArrayList();
        for (String k : headers.keySet()) {
            headerStrings.add(k);
            headerStrings.add(headers.get(k));
        }
        headerStrings.add("authorization");
        headerStrings.add(authorizationHeader);

        String[] headerStringsArray = new String[headerStrings.size()];
        headerStringsArray = headerStrings.toArray(headerStringsArray);

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest.Builder builder = HttpRequest.newBuilder().uri(uri);

        if (headerStringsArray.length > 0) {
            builder = builder.headers(headerStringsArray);
        }

        HttpRequest request = builder
            .DELETE()
            .build();

        HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
        int statusCode = response.statusCode();

        if (statusCode < 200 || statusCode >= 300) {
            throw new FailedRequestException(response);
        }

        return response.body();
    }

    private Key _key;
    private Environment _environment;
    private static final String REQUEST_TYPE = "ul1_request";
    private static final String SIGNATURE_V1 = "UL1-ED25519";
    private static final String HEADER_AUTHORIZATION = "authorization";
    private static final String HEADER_X_UL_DATE = "x-ul-date";
    private static final String HEADER_CONTENT_TYPE = "content-type";
    private static final List<String> SIGNED_HEADERS = Collections.unmodifiableList(Arrays.asList(HEADER_X_UL_DATE));
}
