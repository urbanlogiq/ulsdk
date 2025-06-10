// Copyright (c), CommunityLogiq Software

package com.urbanlogiq.ulsdk;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
import com.urbanlogiq.ulsdk.ApiKeyContext;

public final class TestContext extends RequestContext {
    ApiKeyContext _context;
    byte[] _response;

    public Region region() {
        return this._context.region();
    }

    public Environment environment() {
        return this._context.environment();
    }

    public TestContext(ApiKeyContext context) {
        this._context = context;
    }

    public void setResponse(byte[] response) {
        this._response = response;
    }

    public byte[] get(String path, List<Pair<String, String>> params, HashMap<String, String> headers) throws URISyntaxException, IOException, InterruptedException {
        String echoPath = "/v1/echo/";
        this._context.get(echoPath, params, headers);
        byte[] response = this._response;
        this._response = null;
        return response;
    }

    public byte[] put(String path, byte[] body, String mimetype, List<Pair<String, String>> params, HashMap<String, String> headers) throws URISyntaxException, IOException, InterruptedException {
        String echoPath = "/v1/echo/";
        
        // roundtrip the _expected result_ through the echo endpoint to make
        // sure that a) we get it back unchanged and b) we can deserialize it
        // properly.
        byte[] response = this._context.put(echoPath, this._response, mimetype, params, headers);

        if (this._response != null) {
            if (!java.util.Arrays.equals(response, this._response)) {
                throw new RuntimeException("Test failure, expected response to match request");
            }
        }

        this._response = null;
        return response;
    }

    public byte[] post(String path, byte[] body, String mimetype, List<Pair<String, String>> params, HashMap<String, String> headers) throws URISyntaxException, IOException, InterruptedException {
        String echoPath = "/v1/echo/";

        // roundtrip the _expected result_ through the echo endpoint to make
        // sure that a) we get it back unchanged and b) we can deserialize it
        // properly.
        byte[] response = this._context.post(echoPath, this._response, mimetype, params, headers);

        if (this._response != null) {
            if (!java.util.Arrays.equals(response, this._response)) {
                throw new RuntimeException("Test failure, expected response to match request");
            }
        }

        this._response = null;
        return response;
    }

    public byte[] upload(String path, List<File> files) throws URISyntaxException, IOException, InterruptedException {
        String echoPath = "/v1/echo/";
        this._context.upload(echoPath, files);
        byte[] response = this._response;
        this._response = null;
        return response;
    }

    public byte[] delete(String path, List<Pair<String, String>> params, HashMap<String, String> headers) throws URISyntaxException, IOException, InterruptedException {
        String echoPath = "/v1/echo/";
        this._context.delete(echoPath, params, headers);

        byte[] response = this._response;
        this._response = null;
        return response;
    }
}
