package local

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"sort"

	"github.com/juju/errors"
	"k8s.io/klog/v2"

	"github.com/bitnami-labs/charts-syncer/internal/utils"
	"github.com/bitnami-labs/charts-syncer/pkg/client/types"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
)

// Repo allows to operate a chart repository.
type Repo struct {
	dir string
	// entries maps chart name -> chart version -> package path
	entries map[string]map[string]string
}

// New creates a Repo object from an api.Repo object.
func New(dir string) (*Repo, error) {
	d, err := filepath.Abs(dir)
	if err != nil {
		return nil, errors.Trace(err)
	}
	if err := os.MkdirAll(d, 0755); err != nil {
		return nil, errors.Trace(err)
	}

	// Populate entries from the Chart.yaml of each package, so file names do not matter
	r := &Repo{dir: d, entries: make(map[string]map[string]string)}
	matches, err := filepath.Glob(filepath.Join(d, "*.tgz"))
	if err != nil {
		return nil, errors.Trace(err)
	}
	for _, m := range matches {
		ch, err := loader.LoadFile(m)
		if err != nil {
			klog.Warningf("Skipping %q: not a valid chart package: %v", m, err)
			continue
		}
		r.add(ch.Metadata.Name, ch.Metadata.Version, m)
	}

	return r, nil
}

func (r *Repo) add(name, version, file string) {
	if r.entries[name] == nil {
		r.entries[name] = make(map[string]string)
	}
	if old, ok := r.entries[name][version]; ok {
		klog.Warningf("Chart %s-%s found in both %q and %q, using the latter", name, version, old, file)
	}
	r.entries[name][version] = file
}

// List lists all chart names in a repo
func (r *Repo) List() ([]string, error) {
	var names []string
	for name := range r.entries {
		names = append(names, name)
	}
	return names, nil
}

// ListChartVersions lists all versions of a chart
func (r *Repo) ListChartVersions(name string) ([]string, error) {
	versions := []string{}
	for v := range r.entries[name] {
		versions = append(versions, v)
	}
	sort.Strings(versions)
	return versions, nil
}

// Fetch fetches a chart
func (r *Repo) Fetch(name string, version string) (string, error) {
	file, ok := r.entries[name][version]
	if !ok {
		return "", errors.NotFoundf("%s-%s chart in %q", name, version, r.dir)
	}
	return file, nil
}

// Has checks if a repo has a specific chart
func (r *Repo) Has(name string, version string) (bool, error) {
	_, ok := r.entries[name][version]
	return ok, nil
}

func (r *Repo) CreateRepository(repository string) error {
	return nil
}

// Upload uploads a chart to the repo
func (r *Repo) Upload(filepath string, metadata *chart.Metadata) error {
	name := metadata.Name
	version := metadata.Version
	if _, ok := r.entries[name][version]; ok {
		return errors.AlreadyExistsf("%s-%s", name, version)
	}

	input, err := ioutil.ReadFile(filepath)
	if err != nil {
		return errors.Annotatef(err, "reading %q", filepath)
	}

	out := path.Join(r.dir, fmt.Sprintf("%s-%s.tgz", name, version))
	if err := ioutil.WriteFile(out, input, 0644); err != nil {
		return errors.Annotatef(err, "creating %q", out)
	}

	r.add(name, version, out)

	return nil
}

// GetChartDetails returns the details of a chart
func (r *Repo) GetChartDetails(name string, version string) (*types.ChartDetails, error) {
	return &types.ChartDetails{
		PublishedAt: utils.UnixEpoch,
		Digest:      "deadbuff",
	}, nil
}

// Reload reloads the index
func (r *Repo) Reload() error {
	return nil
}
