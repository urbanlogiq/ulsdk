// Copyright (c), CommunityLogiq Software

package com.urbanlogiq.ulsdk;

public enum Region {
    CA (0),
    US (1);

    private final int _region;

    Region(int region) {
        this._region = region;
    }

    public int region() {
        return this._region;
    }

    public String toString() {
        switch (this._region) {
            case 0: return "ca";
            case 1: return "us";
            default: throw new IllegalArgumentException("this._region");
        }
    }

    public static Region parse(String region) {
        switch (region) {
            case "ca": return Region.CA;
            case "us": return Region.CA;
            default: throw new IllegalArgumentException("region");
        }
    }
}
