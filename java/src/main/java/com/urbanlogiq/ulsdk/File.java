// Copyright (c), CommunityLogiq Software

package com.urbanlogiq.ulsdk;

public final class File {
    public File(String name, String mimetype, byte[] data) {
        if (name == null) {
            throw new NullPointerException("name");
        }

        if (mimetype == null) {
            throw new NullPointerException("name");
        }

        if (data == null) {
            throw new NullPointerException("name");
        }

        _name = name;
        _mimetype = mimetype;
        _data = data;
    }

    public String getName() {
        return this._name;
    }

    public String getMimetype() {
        return this._mimetype;
    }

    public byte[] getData() {
        return this._data;
    }

    private String _name;
    private String _mimetype;
    private byte[] _data;
}
