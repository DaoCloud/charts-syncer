package local_test

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/bitnami-labs/charts-syncer/pkg/client/repo/local"
	"github.com/bitnami-labs/charts-syncer/pkg/client/types"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/time"
)

func TestFetch(t *testing.T) {
	c, err := local.New("../../../../testdata/charts")
	if err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	chartPath, err := c.Fetch("etcd", "4.8.0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(chartPath); err != nil {
		t.Errorf("chart package does not exist")
	}
}

func TestHas(t *testing.T) {
	c, err := local.New("../../../../testdata/charts")
	if err != nil {
		t.Fatal(err)
	}
	has, err := c.Has("etcd", "4.8.0")
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Errorf("chart not found in index")
	}
}

func TestList(t *testing.T) {
	c, err := local.New("../../../../testdata/charts")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"common", "etcd", "kafka", "zookeeper"}
	got, err := c.List()
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(want)
	sort.Strings(got)
	if !reflect.DeepEqual(want, got) {
		t.Errorf("unexpected list of charts. got: %v, want: %v", got, want)
	}
}

func TestListChartVersions(t *testing.T) {
	c, err := local.New("../../../../testdata/charts")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"4.8.0"}
	got, err := c.ListChartVersions("etcd")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(want)
	sort.Strings(got)
	if !reflect.DeepEqual(want, got) {
		t.Errorf("unexpected list of charts. got: %v, want: %v", got, want)
	}
}

func TestGetChartDetails(t *testing.T) {
	c, err := local.New("../../../../testdata/charts")
	if err != nil {
		t.Fatal(err)
	}
	want := types.ChartDetails{
		PublishedAt: time.Now().Time,
		Digest:      "deadbuff",
	}
	got, err := c.GetChartDetails("etcd", "4.8.0")
	if err != nil {
		t.Fatal(err)
	}
	if want.Digest != got.Digest {
		t.Errorf("unexpected digest in chart. got: %v, want: %v", got, want)
	}
}

func TestNewReadsChartMetadata(t *testing.T) {
	dir := t.TempDir()
	for _, md := range []*chart.Metadata{
		{APIVersion: "v2", Name: "kubean", Version: "v0.40.0"},
		{APIVersion: "v2", Name: "ghippo", Version: "0.50.0-rc2"},
		{APIVersion: "v2", Name: "app-1.2.3-beta", Version: "0.1.0"},
	} {
		if _, err := chartutil.Save(&chart.Chart{Metadata: md}, dir); err != nil {
			t.Fatal(err)
		}
	}
	// File names must not matter
	if err := os.Rename(filepath.Join(dir, "ghippo-0.50.0-rc2.tgz"), filepath.Join(dir, "renamed.tgz")); err != nil {
		t.Fatal(err)
	}
	// Non-chart packages must be skipped
	if err := os.WriteFile(filepath.Join(dir, "broken.tgz"), []byte("not a chart"), 0644); err != nil {
		t.Fatal(err)
	}

	c, err := local.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	for name, version := range map[string]string{"kubean": "v0.40.0", "ghippo": "0.50.0-rc2", "app-1.2.3-beta": "0.1.0"} {
		got, err := c.ListChartVersions(name)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, []string{version}) {
			t.Errorf("unexpected versions for %q. got: %v, want: [%s]", name, got, version)
		}
		if _, err := c.Fetch(name, version); err != nil {
			t.Errorf("unexpected error fetching %s-%s: %v", name, version, err)
		}
	}
	if p, _ := c.Fetch("ghippo", "0.50.0-rc2"); filepath.Base(p) != "renamed.tgz" {
		t.Errorf("unexpected path for ghippo. got: %q", p)
	}
	if _, err := c.Fetch("kubean", "v9.9.9"); err == nil {
		t.Errorf("expected error fetching a missing chart")
	}
}

func TestUpload(t *testing.T) {
	c, err := local.New("../../../../testdata/charts")
	if err != nil {
		t.Fatal(err)
	}
	cMetadata := chart.Metadata{
		Name:    "apache",
		Version: "7.3.15",
	}
	err = c.Upload("../../../../testdata/apache-7.3.15.tgz", &cMetadata)
	if err != nil {
		t.Fatal(err)
	}
	expectedChartPath := "../../../../testdata/charts/apache-7.3.15.tgz"
	if _, err := os.Stat(expectedChartPath); err != nil {
		t.Errorf("chart package does not exist after upload method")
	}
	if err := os.Remove(expectedChartPath); err != nil {
		t.Errorf("error cleaning chart path from %q after successful upload", expectedChartPath)
	}
}
