/*
Copyright The Helm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package driver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rspb "helm.sh/helm/v4/pkg/release/v1"
)

func TestHTTPName(t *testing.T) {
	driver, _ := NewHTTP("http://example.com", nil)
	if driver.Name() != HTTPDriverName {
		t.Errorf("Expected driver name %q, got %q", HTTPDriverName, driver.Name())
	}
}

func TestHTTPGet(t *testing.T) {
	// Setup test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/releases/default/sh.helm.release.v1.test.v1" {
			release := &rspb.Release{
				Name:      "test",
				Version:   1,
				Namespace: "default",
			}
			json.NewEncoder(w).Encode(release)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	driver, err := NewHTTP(ts.URL, nil)
	require.NoError(t, err)

	// Test successful get
	release, err := driver.Get("sh.helm.release.v1.test.v1")
	require.NoError(t, err)
	assert.Equal(t, "test", release.Name)
	assert.Equal(t, 1, release.Version)

	// Test release not found
	_, err = driver.Get("sh.helm.release.v1.nonexistent.v1")
	assert.Equal(t, ErrReleaseNotFound, err)
}

func TestHTTPCreate(t *testing.T) {
	// Setup test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/releases/default/sh.helm.release.v1.test.v1" {
			w.WriteHeader(http.StatusCreated)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/releases/default/sh.helm.release.v1.exists.v1" {
			w.WriteHeader(http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	driver, err := NewHTTP(ts.URL, nil)
	require.NoError(t, err)

	// Test successful create
	release := &rspb.Release{Name: "test", Version: 1, Namespace: "default"}
	err = driver.Create("sh.helm.release.v1.test.v1", release)
	require.NoError(t, err)

	// Test release exists
	err = driver.Create("sh.helm.release.v1.exists.v1", release)
	assert.Equal(t, ErrReleaseExists, err)
}

func TestHTTPDelete(t *testing.T) {
	// Setup test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/releases/default/sh.helm.release.v1.test.v1" {
			if r.Method == http.MethodGet {
				release := &rspb.Release{Name: "test", Version: 1, Namespace: "default"}
				json.NewEncoder(w).Encode(release)
				return
			}
			if r.Method == http.MethodDelete {
				w.WriteHeader(http.StatusOK)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	driver, err := NewHTTP(ts.URL, nil)
	require.NoError(t, err)

	// Test successful delete
	release, err := driver.Delete("sh.helm.release.v1.test.v1")
	require.NoError(t, err)
	assert.Equal(t, "test", release.Name)

	// Test release not found
	_, err = driver.Delete("sh.helm.release.v1.nonexistent.v1")
	assert.Equal(t, ErrReleaseNotFound, err)
}
