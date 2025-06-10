// Copyright (c), CommunityLogiq Software

package com.urbanlogiq.ulsdk;

public final class Pair<X, Y> {
    public Pair(X first, Y second) {
        this._first = first;
        this._second = second;
    }

    public X first() {
        return this._first;
    }

    public Y second() {
        return this._second;
    }

    private X _first;
    private Y _second;
}
