// Copyright (c), CommunityLogiq Software

package com.urbanlogiq.ulsdk;

public class InvalidVariantException extends RuntimeException {
    public InvalidVariantException(String u, Object value) {
        super("Attempt to initialize union-type object " + u + " with invalid variant of type " + value.getClass());
    }
}
