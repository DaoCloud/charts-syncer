package repo

import (
	"io"
	"net/http"
	"os"

	"github.com/bitnami-labs/chart-repository-syncer/api"
	"github.com/bitnami-labs/chart-repository-syncer/pkg/utils"
	"github.com/juju/errors"
	"k8s.io/klog"
)

// download downloads a packaged from the given repo
func download(filepath string, name string, version string, downloadURL string, sourceRepo *api.Repo) error {
	// Get the data
	req, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		return errors.Annotate(err, "Error getting chart")
	}
	if sourceRepo.Auth != nil && sourceRepo.Auth.Username != "" && sourceRepo.Auth.Password != "" {
		klog.V(12).Info("Source repo configures basic authentication. Downloading chart...")
		req.SetBasicAuth(sourceRepo.Auth.Username, sourceRepo.Auth.Password)
	}
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return errors.Annotate(err, "Error doing request")
	}
	defer res.Body.Close()

	// Check status code
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return errors.Errorf("Error downloading chart %s-%s. Status code is %d", name, version, res.StatusCode)
	}
	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return errors.Annotatef(err, "Error creating %s file", filepath)
	}
	defer out.Close()

	// Write the body to file
	if _, err = io.Copy(out, res.Body); err != nil {
		return errors.Annotatef(err, "Error write to file %s", filepath)
	}

	// Check contentType
	contentType, err := utils.GetFileContentType(filepath)
	if err != nil {
		return errors.Annotatef(err, "Error checking contentType of %s file", filepath)
	}
	if contentType != "application/x-gzip" {
		return errors.Errorf("The downloaded chart %s is not a gzipped tarball", filepath)
	}
	return errors.Trace(err)
}
