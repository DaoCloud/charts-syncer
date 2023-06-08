package jfrog

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/juju/errors"

	"github.com/bitnami-labs/charts-syncer/api"
	"github.com/bitnami-labs/charts-syncer/internal/utils"
)

// Container allows to operate a chart repository.
type Container struct {
	url      *url.URL
	username string
	password string
	insecure bool
}

const defaultDeploymentRepo = "addon-images-local"

// New creates a Repo object from an api.Repo object.
func New(registry string, containers *api.Containers, insecure bool) (*Container, error) {
	if registry == "" && containers.GetAuth() != nil {
		registry = containers.GetAuth().GetRegistry()
	}

	u := url.URL{Host: registry}
	transport := http.DefaultTransport
	if insecure {
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	client := &http.Client{Transport: transport}

	resp, err := client.Get(getPingURL("https", registry))
	if err == nil && resp.StatusCode == http.StatusOK {
		u.Scheme = "https"
	} else {
		resp, err := http.Get(getPingURL("http", registry))
		if err != nil {
			return nil, errors.Trace(err)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, errors.Trace(fmt.Errorf("failed to ping jfrog %s registry", registry))
		}
		u.Scheme = "http"
	}

	c := Container{url: &u, insecure: insecure}
	if auth := containers.GetAuth(); auth != nil {
		c.username = auth.GetUsername()
		c.password = auth.GetPassword()
	}

	// create local repo
	repo := struct {
		Key          string   `json:"key"`
		Environments []string `json:"environments"`
		Rclass       string   `json:"rclass"`
		PackageType  string   `json:"packageType"`
	}{
		Key:          defaultDeploymentRepo,
		Environments: []string{"PROD"},
		Rclass:       "local",
		PackageType:  "docker",
	}

	data, err := json.Marshal(&repo)
	if err != nil {
		return nil, err
	}

	err = c.createRepository(defaultDeploymentRepo, data)
	if err != nil && !strings.Contains(err.Error(), "repository key already exists") {
		return nil, err
	}
	return &c, nil
}

// GetPingURL  returns the URL to upload a chart
func getPingURL(scheme, host string) string {
	u := url.URL{}
	u.Scheme = scheme
	u.Host = host
	u.Path = "artifactory/api/system/ping"
	return u.String()
}

// GetRepositoryURL returns the URL to upload a chart
func (c *Container) GetRepositoryURL() string {
	u := *c.url
	u.Path = "artifactory/api/repositories"
	return u.String()
}

func (c *Container) checkRepository(repository string) error {
	u := c.GetRepositoryURL()
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/%s", u, repository), nil)
	if err != nil {
		return errors.Trace(err)
	}
	req.Header.Add("content-type", "application/json")
	if c.username != "" && c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	client := utils.DefaultClient
	if c.insecure {
		client = utils.InsecureClient
	}
	res, err := client.Do(req)
	if err != nil {
		return errors.Annotatef(err, "create %q repository", repository)
	}
	defer res.Body.Close()

	if err := (res.StatusCode < 200 || res.StatusCode > 299) && res.StatusCode != 409; err {
		bodyStr := utils.HTTPResponseBody(res)
		return errors.Errorf("unable to create %q repository, got HTTP Status: %s, Resp: %v", repository, res.Status, bodyStr)
	}
	return nil
}

func (c *Container) CreateRepository(repository string) error {
	target := strings.Split(repository, "/")
	if len(target) < 3 {
		return nil
	}
	repository = target[len(target)-2]

	err := c.checkRepository(repository)
	if err == nil {
		return nil
	}

	repo := struct {
		Key                   string   `json:"key"`
		Environments          []string `json:"environments"`
		Rclass                string   `json:"rclass"`
		PackageType           string   `json:"packageType"`
		DefaultDeploymentRepo string   `json:"defaultDeploymentRepo"`
		Repositories          []string `json:"repositories"`
	}{
		Key:                   repository,
		Environments:          []string{"PROD"},
		Rclass:                "virtual",
		PackageType:           "docker",
		DefaultDeploymentRepo: defaultDeploymentRepo,
		Repositories:          []string{defaultDeploymentRepo},
	}

	data, err := json.Marshal(&repo)
	if err != nil {
		return err
	}

	return c.createRepository(repository, data)
}

func (c *Container) createRepository(repository string, data []byte) error {
	body := &bytes.Buffer{}
	body.Write(data)

	u := c.GetRepositoryURL()
	req, err := http.NewRequest("PUT", fmt.Sprintf("%s/%s", u, repository), body)
	if err != nil {
		return errors.Trace(err)
	}
	req.Header.Add("content-type", "application/json")
	if c.username != "" && c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	client := utils.DefaultClient
	if c.insecure {
		client = utils.InsecureClient
	}
	res, err := client.Do(req)
	if err != nil {
		return errors.Annotatef(err, "create %q repository", repository)
	}
	defer res.Body.Close()

	if err := (res.StatusCode < 200 || res.StatusCode > 299) && res.StatusCode != 409; err {
		bodyStr := utils.HTTPResponseBody(res)
		return errors.Errorf("unable to create %q repository, got HTTP Status: %s, Resp: %v", repository, res.Status, bodyStr)
	}

	return nil
}
