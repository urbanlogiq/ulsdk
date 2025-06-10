// Copyright (c), CommunityLogiq Software

package com.urbanlogiq.ulsdk;

import java.util.HashMap;
import java.util.List;
import java.net.URISyntaxException;
import com.urbanlogiq.ulsdk.Region;
import com.urbanlogiq.ulsdk.Environment;
import com.urbanlogiq.ulsdk.File;
import java.io.IOException;

public abstract class RequestContext {
    abstract Region region();
    abstract Environment environment();

    public abstract byte[] get(String path, List<Pair<String, String>> params, HashMap<String, String> headers) throws URISyntaxException, IOException, InterruptedException;
    public abstract byte[] put(String path, byte[] body, String mimetype, List<Pair<String, String>> params, HashMap<String, String> headers) throws URISyntaxException, IOException, InterruptedException;
    public abstract byte[] post(String path, byte[] body, String mimetype, List<Pair<String, String>> params, HashMap<String, String> headers) throws URISyntaxException, IOException, InterruptedException;
    public abstract byte[] upload(String path, List<File> files) throws URISyntaxException, IOException, InterruptedException;
    public abstract byte[] delete(String path, List<Pair<String, String>> params, HashMap<String, String> headers) throws URISyntaxException, IOException, InterruptedException;

    String getHost(Region region, Environment environment) {
        return String.format("%s.urbanlogiq.%s", environment.toDomain(), region.toString());
    }
}
