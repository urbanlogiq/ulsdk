// Copyright (c), CommunityLogiq Software

import { RequestContext } from './request_context';

export enum Region {
  CA = 'ca',
  US = 'us',
}

export enum Environment {
  Prod = 'prod',
  Stage = 'stage',
}

function getEndpoint(
  region: Region,
  environment: Environment,
  path: string
): string {
  const subdomain = environment === Environment.Prod ? 'api' : 'stage';
  const tld = region === Region.CA ? 'ca' : 'us';
  return `https://${subdomain}.urbanlogiq.${tld}${path}`;
}

function buildQueryString(params: [string, string][]): string {
  if (params.length === 0) {
    return '';
  }

  const encoded = params.map(
    ([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`
  );
  return '?' + encoded.join('&');
}

/**
 * A RequestContext implementation that authenticates using a JWT bearer token
 * passed in the HTTP Authorization header.
 */
export class BearerTokenContext extends RequestContext {
  private _token: string;
  private _region: Region;
  private _environment: Environment;

  constructor(token: string, region: Region, environment: Environment) {
    super();
    this._token = token;
    this._region = region;
    this._environment = environment;
  }

  get region(): Region {
    return this._region;
  }

  get environment(): Environment {
    return this._environment;
  }

  private _authHeaders(
    headers: Record<string, string>
  ): Record<string, string> {
    return {
      ...headers,
      Authorization: `Bearer ${this._token}`,
    };
  }

  private async _request(
    method: string,
    path: string,
    params: [string, string][],
    headers: Record<string, string>,
    body?: Uint8Array | null,
    contentType?: string
  ): Promise<Uint8Array> {
    const url =
      getEndpoint(this._region, this._environment, path) +
      buildQueryString(params);

    const reqHeaders = this._authHeaders(headers);
    if (contentType) {
      reqHeaders['content-type'] = contentType;
    }

    const init: RequestInit = {
      method,
      headers: reqHeaders,
    };

    if (body != null) {
      init.body = body;
    }

    const response = await fetch(url, init);

    if (!response.ok) {
      const text = await response.text();
      throw new Error(
        `Request failed: ${method} ${path} returned ${response.status}: ${text}`
      );
    }

    const arrayBuffer = await response.arrayBuffer();
    return new Uint8Array(arrayBuffer);
  }

  async get(
    path: string,
    params: [string, string][],
    headers: Record<string, string>
  ): Promise<Uint8Array> {
    return this._request('GET', path, params, headers);
  }

  async post(
    path: string,
    body: Uint8Array | null,
    contentType: string,
    params: [string, string][],
    headers: Record<string, string>
  ): Promise<Uint8Array> {
    return this._request('POST', path, params, headers, body, contentType);
  }

  async put(
    path: string,
    body: Uint8Array | null,
    contentType: string,
    params: [string, string][],
    headers: Record<string, string>
  ): Promise<Uint8Array> {
    return this._request('PUT', path, params, headers, body, contentType);
  }

  async delete(
    path: string,
    params: [string, string][],
    headers: Record<string, string>
  ): Promise<Uint8Array> {
    return this._request('DELETE', path, params, headers);
  }

  async upload(
    path: string,
    files: File[],
    params: [string, string][],
    headers: Record<string, string>
  ): Promise<Uint8Array> {
    const url =
      getEndpoint(this._region, this._environment, path) +
      buildQueryString(params);

    const formData = new FormData();
    for (const file of files) {
      formData.append(file.name, file);
    }

    const reqHeaders = this._authHeaders(headers);

    const response = await fetch(url, {
      method: 'POST',
      headers: reqHeaders,
      body: formData,
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(
        `Upload failed: POST ${path} returned ${response.status}: ${text}`
      );
    }

    const arrayBuffer = await response.arrayBuffer();
    return new Uint8Array(arrayBuffer);
  }
}
