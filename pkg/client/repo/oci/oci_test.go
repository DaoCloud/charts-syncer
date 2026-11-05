package oci_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/bitnami-labs/charts-syncer/api"
	"github.com/bitnami-labs/charts-syncer/internal/utils"
	"github.com/bitnami-labs/charts-syncer/pkg/client/repo/oci"
	"github.com/bitnami-labs/charts-syncer/pkg/client/types"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	"helm.sh/helm/v3/pkg/chart"
)

var (
	ociRepo = &api.Repo{
		Kind: api.Kind_OCI,
		Auth: &api.Auth{
			Username: "user",
			Password: "password",
		},
		DisableChartsIndex: true,
	}
)

func TestFetch(t *testing.T) {
	c := oci.PrepareHttpServer(t, ociRepo)
	chartPath, err := c.Fetch("kafka", "12.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(chartPath); err != nil {
		t.Errorf("chart package does not exist")
	}
	contentType, err := utils.GetFileContentType(chartPath)
	if err != nil {
		t.Fatalf("error checking contentType of %s file", chartPath)
	}
	if contentType != "application/x-gzip" {
		t.Errorf("incorrect content type, got: %s, want: %s.", contentType, "application/x-gzip")
	}
}

func TestHas(t *testing.T) {
	c := oci.PrepareHttpServer(t, ociRepo)
	has, err := c.Has("kafka", "12.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Errorf("chart not found in index")
	}
}

func TestHasAnonymousBearer(t *testing.T) {
	manifest, err := os.ReadFile("../../../../testdata/oci/kafka-12.2.1-oci-manifest.json")
	if err != nil {
		t.Fatal(err)
	}

	// Mimics Harbor: anonymous pulls require a token from the token service
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const scope = "repository:someproject/charts/kafka:pull"
		switch {
		case r.URL.Path == "/service/token":
			if got := r.URL.Query().Get("scope"); got != scope {
				t.Errorf("unexpected token scope %q", got)
			}
			fmt.Fprint(w, `{"token": "secret"}`)
		case r.Header.Get("Authorization") != "Bearer secret":
			w.Header().Set("Www-Authenticate", fmt.Sprintf(`Bearer realm="%s/service/token",service="harbor-registry",scope="%s"`, srv.URL, scope))
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/v2/someproject/charts/kafka/manifests/12.2.1":
			w.Write(manifest)
		case strings.HasSuffix(r.URL.Path, "/tags/list"):
			t.Errorf("tags must not be listed to check a single version")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	// A broken docker config must not prevent anonymous access
	for desc, dockerConfig := range map[string]string{"no docker config": "", "broken docker config": "{not json"} {
		t.Run(desc, func(t *testing.T) {
			dir := t.TempDir()
			if dockerConfig != "" {
				if err := os.WriteFile(path.Join(dir, "config.json"), []byte(dockerConfig), 0644); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("DOCKER_CONFIG", dir)

			c := oci.PrepareTest(t, &api.Repo{Kind: api.Kind_OCI, Url: srv.URL + "/someproject/charts", DisableChartsIndex: true})
			for version, want := range map[string]bool{"12.2.1": true, "9.9.9": false} {
				has, err := c.Has("kafka", version)
				if err != nil {
					t.Fatal(err)
				}
				if has != want {
					t.Errorf("Has(kafka, %s) = %v, want %v", version, has, want)
				}
			}
		})
	}
}

func TestList(t *testing.T) {
	c := oci.PrepareHttpServer(t, ociRepo)
	want := []string{}
	got, err := c.List()
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(want)
	sort.Strings(got)
	if !reflect.DeepEqual(want, got) {
		t.Errorf("unexpected list of charts names. got: %v, want: %v", got, want)
	}
}

func TestListChartVersions(t *testing.T) {
	c := oci.PrepareHttpServer(t, ociRepo)
	want := []string{"12.2.1"}
	got, err := c.ListChartVersions("kafka")
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
	c := oci.PrepareHttpServer(t, ociRepo)
	want := types.ChartDetails{
		PublishedAt: time.Now(),
		Digest:      "sha256:11e974d88391a39e4dd6d7d6c4350b237b1cca1bf32f2074bba41109eaa5f438",
	}
	got, err := c.GetChartDetails("kafka", "12.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if want.Digest != got.Digest {
		t.Errorf("unexpected digest in chart. got: %v, want: %v", got, want)
	}
}

func TestReload(t *testing.T) {
	c := oci.PrepareHttpServer(t, ociRepo)
	expectedError := "reload method is not supported yet"
	err := c.Reload()
	if err.Error() != expectedError {
		t.Errorf("unexpected error message. got: %q, want: %q", err.Error(), expectedError)
	}
}

func TestGetDownloadURL(t *testing.T) {
	c := oci.PrepareHttpServer(t, ociRepo)
	u, err := url.Parse(ociRepo.Url)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = path.Join("v2", u.Path, "kafka/blobs/sha256:11e974d88391a39e4dd6d7d6c4350b237b1cca1bf32f2074bba41109eaa5f438")
	want := u.String()
	got, err := c.GetDownloadURL("kafka", "12.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("wrong download URL. got: %v, want: %v", got, want)
	}
}

func TestUpload(t *testing.T) {
	oci.PrepareOciServer(t, ociRepo)
	c := oci.PrepareTest(t, ociRepo)
	chartMetadata := &chart.Metadata{
		Name:    "apache",
		Version: "7.3.15",
	}
	if err := c.Upload("../../../../testdata/apache-7.3.15.tgz", chartMetadata); err != nil {
		t.Fatal(err)
	}
	chartPath, err := c.Fetch("apache", "7.3.15")
	if _, err := os.Stat(chartPath); err != nil {
		t.Errorf("chart package does not exist")
	}
	contentType, err := utils.GetFileContentType(chartPath)
	if err != nil {
		t.Fatalf("error checking contentType of %s file", chartPath)
	}
	if contentType != "application/x-gzip" {
		t.Errorf("incorrect content type, got: %s, want: %s.", contentType, "application/x-gzip")
	}
}
