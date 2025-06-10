// Copyright (c), CommunityLogiq Software

package com.urbanlogiq.ulsdk;

public enum Environment {
    Prod (0),
    Stage (1);

    private final int _env;

    Environment(int env) {
        this._env = env;
    }

    public int env() {
        return this._env;
    }

    public String toString() {
        switch (this._env) {
            case 0: return "prod";
            case 1: return "stage";
            default: throw new IllegalArgumentException("this._env");
        }
    }

    public static Environment parse(String env) {
        switch (env) {
            case "prod": return Environment.Prod;
            case "stage": return Environment.Stage;
            default: throw new IllegalArgumentException("env");
        }
    }

    public String toDomain() {
        switch (this._env) {
            case 0: return "home";
            case 1: return "stage";
            default: throw new IllegalArgumentException("this._env");
        }
    }
}

