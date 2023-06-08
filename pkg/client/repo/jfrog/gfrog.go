package jfrog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/juju/errors"
	"helm.sh/helm/v3/pkg/chart"
	"k8s.io/klog/v2"

	"github.com/bitnami-labs/charts-syncer/api"
	"github.com/bitnami-labs/charts-syncer/internal/cache"
	"github.com/bitnami-labs/charts-syncer/internal/utils"
	"github.com/bitnami-labs/charts-syncer/pkg/client/repo/helmclassic"
	"github.com/bitnami-labs/charts-syncer/pkg/client/types"
)

// Repo allows to operate a chart repository.
type Repo struct {
	url      *url.URL
	username string
	password string
	insecure bool

	helm *helmclassic.Repo

	cache cache.Cacher
}

const defaultDeploymentRepo = "addon-charts-local"

// New creates a Repo object from an api.Repo object.
func New(repo *api.Repo, c cache.Cacher, insecure bool) (*Repo, error) {
	u, err := url.Parse(repo.GetUrl())
	if err != nil {
		return nil, errors.Trace(err)
	}

	r, err := NewRaw(u, repo.GetAuth().GetUsername(), repo.GetAuth().GetPassword(), c, insecure)
	if err != nil {
		return nil, errors.Trace(err)
	}

	repoReq := struct {
		Key          string   `json:"key"`
		Environments []string `json:"environments"`
		Rclass       string   `json:"rclass"`
		PackageType  string   `json:"packageType"`
	}{
		Key:          defaultDeploymentRepo,
		Environments: []string{"PROD"},
		Rclass:       "local", // "virtual",
		PackageType:  "helm",
	}

	data, err := json.Marshal(&repoReq)
	if err != nil {
		return nil, err
	}

	err = r.createRepository(defaultDeploymentRepo, data)
	if err != nil && !strings.Contains(err.Error(), "repository key already exists") {
		return nil, err
	}

	return r, nil
}

// NewRaw creates a Repo object.
func NewRaw(u *url.URL, user string, pass string, c cache.Cacher, insecure bool) (*Repo, error) {
	helm, err := helmclassic.NewRaw(u, user, pass, c, insecure)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return &Repo{url: u, username: user, password: pass, helm: helm, cache: c, insecure: insecure}, nil
}

// GetUploadURL returns the URL to upload a chart
func (r *Repo) GetUploadURL(chartName string) string {
	return fmt.Sprintf("%s/%s", r.url.String(), chartName)
}

// GetRepositoryURL returns the URL to upload a chart
func (r *Repo) GetRepositoryURL() string {
	u := *r.url
	u.Path = "artifactory/api/repositories"
	return u.String()
}

func (r *Repo) checkRepository(repository string) error {
	u := r.GetRepositoryURL()
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/%s", u, repository), nil)
	if err != nil {
		return errors.Trace(err)
	}
	req.Header.Add("content-type", "application/json")
	if r.username != "" && r.password != "" {
		req.SetBasicAuth(r.username, r.password)
	}

	client := utils.DefaultClient
	if r.insecure {
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

func (r *Repo) CreateRepository(repository string) error {
	target := strings.Split(repository, "/")
	if len(target) < 3 {
		return nil
	}
	repository = target[len(target)-1]

	err := r.checkRepository(repository)
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
		PackageType:           "helm",
		DefaultDeploymentRepo: defaultDeploymentRepo,
		Repositories:          []string{defaultDeploymentRepo},
	}

	data, err := json.Marshal(&repo)
	if err != nil {
		return err
	}
	return r.createRepository(repository, data)
}

func (r *Repo) createRepository(repository string, data []byte) error {
	body := &bytes.Buffer{}
	body.Write(data)

	u := r.GetRepositoryURL()
	req, err := http.NewRequest("PUT", fmt.Sprintf("%s/%s", u, repository), body)
	if err != nil {
		return errors.Trace(err)
	}
	req.Header.Add("content-type", "application/json")
	if r.username != "" && r.password != "" {
		req.SetBasicAuth(r.username, r.password)
	}

	client := utils.DefaultClient
	if r.insecure {
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

// Upload uploads a chart to the repo.
func (r *Repo) Upload(file string, metadata *chart.Metadata) error {
	f, err := os.Open(file)
	if err != nil {
		return errors.Trace(err)
	}
	defer f.Close()

	// Invalidate cache to avoid inconsistency between an old cache result and
	// the chart repo
	if err := r.cache.Invalidate(filepath.Base(file)); err != nil {
		return errors.Trace(err)
	}

	// Write file to the multipart and cache writers at the same time.
	cachew, err := r.cache.Writer(filepath.Base(file))
	if err != nil {
		return errors.Trace(err)
	}
	defer cachew.Close()

	u := r.GetUploadURL(fmt.Sprintf("%s-%s.tgz", metadata.Name, metadata.Version))
	req, err := http.NewRequest("PUT", u, f)
	if err != nil {
		return errors.Trace(err)
	}
	req.Header.Add("content-type", "binary/octet-stream")
	if r.username != "" && r.password != "" {
		req.SetBasicAuth(r.username, r.password)
	}

	reqID := utils.EncodeSha1(u + file)
	klog.V(4).Infof("[%s] PUT %q", reqID, u)
	client := utils.DefaultClient
	if r.insecure {
		client = utils.InsecureClient
	}

	res, err := client.Do(req)
	if err != nil {
		return errors.Annotatef(err, "uploading %q chart", file)
	}
	defer res.Body.Close()

	bodyStr := utils.HTTPResponseBody(res)
	if ok := res.StatusCode >= 200 && res.StatusCode <= 299; !ok {
		return errors.Errorf("unable to upload %q chart, got HTTP Status: %s, Resp: %v", file, res.Status, bodyStr)
	}
	klog.V(4).Infof("[%s] HTTP Status: %s, Resp: %v", reqID, res.Status, bodyStr)

	return nil
}

// Fetch downloads a chart from the repo
func (r *Repo) Fetch(name string, version string) (string, error) {
	return r.helm.Fetch(name, version)
}

// List lists all chart names in the repo
func (r *Repo) List() ([]string, error) {
	return r.helm.List()
}

// ListChartVersions lists all versions of a chart
func (r *Repo) ListChartVersions(name string) ([]string, error) {
	return r.helm.ListChartVersions(name)
}

// Has checks if a repo has a specific chart
func (r *Repo) Has(name string, version string) (bool, error) {
	return r.helm.Has(name, version)
}

// GetChartDetails returns the details of a chart
func (r *Repo) GetChartDetails(name string, version string) (*types.ChartDetails, error) {
	return r.helm.GetChartDetails(name, version)
}

// Reload reloads the index
func (r *Repo) Reload() error {
	return r.helm.Reload()
}
