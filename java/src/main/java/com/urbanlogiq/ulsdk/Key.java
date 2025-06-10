// Copyright (c), CommunityLogiq Software

package com.urbanlogiq.ulsdk;

import java.util.Base64;
import java.util.UUID;

public final class Key {
    public Key(UUID userId, Region region, String accessKey, String secretKey) {
        String paddedSecretKey = secretKey + "==";

        byte[] decodedSecretKey = Base64.getDecoder().decode(paddedSecretKey);

        this._userId = userId;
        this._region = region;
        this._accessKey = accessKey;
        this._secretKey = java.util.Arrays.copyOfRange(decodedSecretKey, 0, 32);
    }

    public UUID userId() {
        return this._userId;
    }

    public Region region() {
        return this._region;
    }

    public String accessKey() {
        return this._accessKey;
    }

    public byte[] secretKey() {
        return this._secretKey;
    }

    private UUID _userId;
    private Region _region;
    private String _accessKey;
    private byte[] _secretKey;
}
