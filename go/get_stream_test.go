// Copyright (c), CommunityLogiq Software

package ulsdk

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/urbanlogiq/ulsdk/api"
	"github.com/urbanlogiq/ulsdk/api/drive"
	"github.com/urbanlogiq/ulsdk/types/id"
)

var (
	_ api.StreamContext = (*ApiKeyContext)(nil)
	_ api.StreamContext = (*TestContext)(nil)
)

const waitTime = 10 * time.Second

// toServer sends each request to a test server.
type toServer struct {
	target *url.URL
}

func (s toServer) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme = s.target.Scheme
	req.URL.Host = s.target.Host
	return http.DefaultTransport.RoundTrip(req)
}

// serve returns a context whose requests go to handler.
func serve(t *testing.T, handler http.HandlerFunc) *ApiKeyContext {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	key := &Key{
		UserID:    uuid.New(),
		Region:    RegionCA,
		AccessKey: "test-access-key",
		SecretKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}
	ctx := NewApiKeyContext(key, EnvironmentStage)
	ctx.client = &http.Client{Transport: toServer{target}}
	return ctx
}

func testBody(size int) []byte {
	body := make([]byte, size)
	for i := range body {
		body[i] = byte(i % 251)
	}
	return body
}

func TestGetStreamReadsTheBodyInParts(t *testing.T) {
	body := testBody(200_000)
	first, rest := body[:100_000], body[100_000:]
	readFirst := make(chan struct{})
	readInTime := make(chan bool, 1)
	var request *http.Request

	ctx := serve(t, func(w http.ResponseWriter, r *http.Request) {
		request = r
		w.Write(first)
		w.(http.Flusher).Flush()
		// A client that reads the complete body first never closes the channel.
		select {
		case <-readFirst:
			readInTime <- true
		case <-time.After(waitTime):
			readInTime <- false
		}
		w.Write(rest)
	})

	file := id.ObjectId{B: bytes.Repeat([]byte{7}, 16)}
	stream, err := drive.GetFileStream(ctx, file, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	received := make([]byte, len(first))
	if _, err := io.ReadFull(stream, received); err != nil {
		t.Fatal(err)
	}
	close(readFirst)
	tail, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}

	if !<-readInTime {
		t.Error("the context read the complete body before it returned the first part")
	}
	if !bytes.Equal(append(received, tail...), body) {
		t.Error("the stream does not have the bytes of the body")
	}
	if want := "/v1/api/ulv2/drive/file/" + file.String(); request.URL.Path != want {
		t.Errorf("path = %q, want %q", request.URL.Path, want)
	}
	if auth := request.Header.Get("authorization"); !strings.HasPrefix(auth, signatureV1) {
		t.Errorf("authorization = %q, want a %s signature", auth, signatureV1)
	}
}

func TestGetFileStreamSendsTheRangeHeaders(t *testing.T) {
	var sent [][2]string
	ctx := serve(t, func(w http.ResponseWriter, r *http.Request) {
		sent = append(sent, [2]string{r.Header.Get("range"), r.Header.Get("if-range")})
	})
	file := id.ObjectId{B: bytes.Repeat([]byte{7}, 16)}
	byteRange, tag := "bytes=6-", `"tag"`

	for _, values := range [][2]*string{{nil, nil}, {&byteRange, &tag}} {
		stream, err := drive.GetFileStream(ctx, file, values[0], values[1])
		if err != nil {
			t.Fatal(err)
		}
		stream.Close()
	}

	if want := [][2]string{{"", ""}, {byteRange, tag}}; !reflect.DeepEqual(sent, want) {
		t.Errorf("range headers = %q, want %q", sent, want)
	}
}

func TestGetFileStreamRejectsAHeaderValueWithALineBreak(t *testing.T) {
	requests := 0
	ctx := serve(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
	})
	file := id.ObjectId{B: bytes.Repeat([]byte{7}, 16)}
	byteRange := "bytes=0-\r\nx-other: 1"

	stream, err := drive.GetFileStream(ctx, file, &byteRange, nil)
	if err == nil {
		stream.Close()
		t.Fatal("expected an error for a header value with a line break")
	}
	if requests != 0 {
		t.Errorf("the server got %d requests, want none", requests)
	}
}

func TestGetStreamSendsTheParameters(t *testing.T) {
	var query string
	ctx := serve(t, func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
	})

	stream, err := ctx.GetStream("/v1/echo/", [][2]string{{"a", "b c"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	data, err := io.ReadAll(stream)
	if err != nil || len(data) != 0 {
		t.Errorf("read %d bytes with error %v, want an empty body", len(data), err)
	}
	if query != "a=b+c" {
		t.Errorf("query = %q, want %q", query, "a=b+c")
	}
}

func TestGetStreamReturnsTheBodyOfAnError(t *testing.T) {
	ctx := serve(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no such file", http.StatusNotFound)
	})

	stream, err := ctx.GetStream("/v1/api/ulv2/drive/file/1234", nil, nil)
	if err == nil {
		stream.Close()
		t.Fatal("expected an error for status 404")
	}
	if !strings.Contains(err.Error(), "404") || !strings.Contains(err.Error(), "no such file") {
		t.Errorf("error = %q, want the status and the body", err)
	}
}

func TestGetStreamFailsOnAShortBody(t *testing.T) {
	ctx := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-length", "2000")
		w.Write(make([]byte, 1000))
	})

	stream, err := ctx.GetStream("/v1/api/ulv2/drive/file/1234", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	if _, err := io.ReadAll(stream); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("error = %v, want %v", err, io.ErrUnexpectedEOF)
	}
}

func TestGetStreamCloseStopsTheDownload(t *testing.T) {
	stopped := make(chan struct{})
	ctx := serve(t, func(w http.ResponseWriter, r *http.Request) {
		block := make([]byte, 1<<16)
		for {
			if _, err := w.Write(block); err != nil {
				close(stopped)
				return
			}
		}
	})

	stream, err := ctx.GetStream("/v1/api/ulv2/drive/file/1234", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(stream, make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	stream.Close()

	select {
	case <-stopped:
	case <-time.After(waitTime):
		t.Error("the server continued to send after the stream closed")
	}
}

// bufferedContext is a context without GetStream.
type bufferedContext struct {
	paths []string
}

func (c *bufferedContext) Get(path string, params [][2]string, headers map[string]string) ([]byte, error) {
	c.paths = append(c.paths, path)
	return []byte("content"), nil
}

func (c *bufferedContext) Post(path string, body []byte, contentType string, params [][2]string, headers map[string]string) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (c *bufferedContext) Put(path string, body []byte, contentType string, params [][2]string, headers map[string]string) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (c *bufferedContext) Delete(path string, params [][2]string, headers map[string]string) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func TestGetStreamWithoutAStreamContextReadsTheCompleteBody(t *testing.T) {
	ctx := &bufferedContext{}

	stream, err := api.GetStream(ctx, "/v1/echo/", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(stream)
	if err != nil || string(data) != "content" {
		t.Errorf("read %q with error %v, want %q", data, err, "content")
	}
	if err := stream.Close(); err != nil {
		t.Error(err)
	}
	if len(ctx.paths) != 1 || ctx.paths[0] != "/v1/echo/" {
		t.Errorf("paths = %v, want one request to /v1/echo/", ctx.paths)
	}
}
