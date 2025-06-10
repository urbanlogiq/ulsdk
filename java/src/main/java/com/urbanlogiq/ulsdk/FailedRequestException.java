// Copyright (c), CommunityLogiq Software

package com.urbanlogiq.ulsdk;

import java.net.http.HttpResponse;

public class FailedRequestException extends RuntimeException {
    HttpResponse<byte[]> _response;

    public HttpResponse<byte[]> getResponse() {
        return this._response;
    }

    public FailedRequestException(HttpResponse<byte[]> response) {
        super(String.format("HTTP Request to %s failed with status code %d", response.uri().toString(), response.statusCode()));

        this._response = response;
    }
}

