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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	rspb "helm.sh/helm/v4/pkg/release/v1"
)

var _ Driver = (*HTTP)(nil)

const (
	// HTTPDriverName is the string name of this driver.
	HTTPDriverName = "HTTP"
)

// HTTP is the HTTP storage driver implementation.
type HTTP struct {
	client    *http.Client
	serverURL string
	namespace string
	headers   map[string]string
}

type HelmRelease struct {
	InstallID string

	Key string

	// See https://github.com/helm/helm/blob/c9fe3d118caec699eb2565df9838673af379ce12/pkg/storage/driver/secrets.go#L231
	Type string

	// The rspb.Release body, as a base64-encoded string
	Body string

	// Release "labels" that can be used as filters in the storage.Query(labels map[string]string)
	// we implemented. Note that allowing Helm users to filter against new dimensions will require a
	// new migration to be added, and the Create and/or update functions to be updated accordingly.
	Name       string
	Namespace  string
	Version    int
	Status     string
	Owner      string
	CreatedAt  int
	ModifiedAt int
}

// NewHTTP initializes a new HTTP driver.
func NewHTTP(serverURL string, headers map[string]string) (*HTTP, error) { // Accept headers as a parameter
	if _, err := url.Parse(serverURL); err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}

	return &HTTP{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		serverURL: strings.TrimSuffix(serverURL, "/"),
		namespace: "default",
		headers:   headers,
	}, nil
}

// SetNamespace sets a specific namespace in which releases will be accessed.
func (h *HTTP) SetNamespace(ns string) {
	h.namespace = ns
}

// Name returns the name of the driver.
func (h *HTTP) Name() string {
	return HTTPDriverName
}

// Get returns the release named by key or returns ErrReleaseNotFound.
func (h *HTTP) Get(key string) (*rspb.Release, error) {
	endpoint := fmt.Sprintf("%s/releases/%s/%s", h.serverURL, h.namespace, url.PathEscape(key))

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrReleaseNotFound
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get release: %s", resp.Status)
	}

	var release rspb.Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}

	return &release, nil
}

// List returns the list of all releases such that filter(release) == true
func (h *HTTP) List(filter func(*rspb.Release) bool) ([]*rspb.Release, error) {
	endpoint := fmt.Sprintf("%s/releases/%s", h.serverURL, h.namespace)

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list releases: %s", resp.Status)
	}

	var releases []*rspb.Release
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return nil, err
	}

	var filtered []*rspb.Release
	for _, rls := range releases {
		if filter(rls) {
			filtered = append(filtered, rls)
		}
	}

	return filtered, nil
}

// Query returns the set of releases that match the provided set of labels
func (h *HTTP) Query(keyvals map[string]string) ([]*rspb.Release, error) {
	params := url.Values{}
	for k, v := range keyvals {
		params.Add(k, v)
	}

	endpoint := fmt.Sprintf("%s/releases/%s/query?%s", h.serverURL, h.namespace, params.Encode())

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrReleaseNotFound
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to query releases: %s", resp.Status)
	}

	var releases []*rspb.Release
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return nil, err
	}

	return releases, nil
}

// Create creates a new release or returns ErrReleaseExists.
func (h *HTTP) Create(key string, rls *rspb.Release) error {
	// For backwards compatibility, we protect against an unset namespace
	namespace := rls.Namespace
	if namespace == "" {
		namespace = "default"
	}
	h.SetNamespace(namespace)

	data, err := json.Marshal(rls)
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf("%s/releases/%s/%s", h.serverURL, h.namespace, url.PathEscape(key))

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		return ErrReleaseExists
	}

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create release: %s, %s", resp.Status, body)
	}

	return nil
}

// Update updates a release or returns ErrReleaseNotFound.
func (h *HTTP) Update(key string, rls *rspb.Release) error {
	// For backwards compatibility, we protect against an unset namespace
	namespace := rls.Namespace
	if namespace == "" {
		namespace = "default"
	}
	h.SetNamespace(namespace)

	data, err := json.Marshal(rls)
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf("%s/releases/%s/%s", h.serverURL, h.namespace, url.PathEscape(key))

	req, err := http.NewRequest(http.MethodPut, endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return ErrReleaseNotFound
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to update release: %s, %s", resp.Status, body)
	}

	return nil
}

// Delete deletes a release or returns ErrReleaseNotFound.
func (h *HTTP) Delete(key string) (*rspb.Release, error) {
	release, err := h.Get(key)
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/releases/%s/%s", h.serverURL, h.namespace, url.PathEscape(key))

	req, err := http.NewRequest(http.MethodDelete, endpoint, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrReleaseNotFound
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to delete release: %s, %s", resp.Status, body)
	}

	return release, nil
}
