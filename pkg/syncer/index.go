package syncer

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/juju/errors"
	"github.com/mkmik/multierror"
	"github.com/philopon/go-toposort"
	"k8s.io/klog/v2"

	"github.com/bitnami-labs/charts-syncer/api"
	"github.com/bitnami-labs/charts-syncer/internal/chart"
	"github.com/bitnami-labs/charts-syncer/internal/utils"
	"github.com/bitnami-labs/charts-syncer/pkg/util/chartutil"
)

// Chart describes a chart, including dependencies
type Chart struct {
	Name         string
	Version      string
	Dependencies []string
	SkipImages   bool

	TgzPath string
}

// ChartIndex is a map linking a chart reference with its Chart
type ChartIndex map[string]*Chart

// func (i ChartIndex) Equal(ii ChartIndex) bool {
// 	var missing []string
// 	for ni, ich := range i {
// 		if iich, ok := ii[ni]; !ok {
// 			return false
// 		}
// 		missing = append(missing, ni)

// 	}
// }

// getIndex returns the chart index
func (s *Syncer) getIndex() ChartIndex {
	if s.index == nil {
		s.index = make(ChartIndex)
	}
	return s.index
}

// Add adds a chart in the index
func (i ChartIndex) Add(id string, chart *Chart) error {
	if _, ok := i[id]; ok {
		return errors.Errorf("%q is already indexed", id)
	}
	i[id] = chart
	return nil
}

// Get returns an index chart
func (i ChartIndex) Get(id string) *Chart {
	if c, ok := i[id]; ok {
		return c
	}
	return nil
}

// loadCharts loads the charts map into the index from the source repo
func (s *Syncer) loadCharts(charts ...*api.Charts) error {
	specifiedCharts := false
	if len(charts) == 0 {
		if !s.autoDiscovery {
			return errors.Errorf("unable to discover charts to sync")
		}
		srcCharts, err := s.cli.src.List()
		if err != nil {
			return errors.Trace(err)
		}
		if len(srcCharts) == 0 {
			if len(s.source.GetIntermediateBundlesPath()) > 0 {
				return errors.Errorf("not found charts in %s to sync", s.source.GetIntermediateBundlesPath())
			}
			return errors.Errorf("not found charts in %s to sync", s.source.GetRepo().Url)
		}

		for _, name := range srcCharts {
			charts = append(charts, &api.Charts{Name: name})
		}
	} else {
		specifiedCharts = true
	}
	// Sort chart names
	sort.Slice(charts, func(i, j int) bool {
		return charts[i].Name > charts[j].Name
	})

	// Create basic layout for date and parse flag to time type
	publishingThreshold, err := utils.GetDateThreshold(s.fromDate)
	if err != nil {
		return errors.Trace(err)
	}
	klog.V(4).Infof("Publishing threshold set to %q", publishingThreshold.String())

	// Iterate over charts in source index
	var errs error
	for _, chart := range charts {
		if err := chartutil.ValidateChartName(chart.Name); err != nil {
			klog.V(3).Infof("Indexing %q charts name is invalid SKIPPED...", chart.Name)
			continue
		}

		if shouldSkipChart(chart.Name, s.skipCharts) {
			klog.V(3).Infof("Indexing %q charts SKIPPED...", chart.Name)
			continue
		}

		versions, err := s.cli.src.ListChartVersions(chart.Name)
		if err != nil {
			errs = multierror.Append(errs, errors.Trace(err))
			continue
		}

		if specifiedCharts && s.verify {
			source := s.source.GetIntermediateBundlesPath()
			if len(source) == 0 {
				source = s.source.GetRepo().Url
			}

			if len(versions) == 0 {
				return errors.Trace(fmt.Errorf("chart %s in %s does not exist", chart.Name, source))
			}

			if ver, ok := verifyChartsVersion(chart.Versions, versions); !ok {
				if len(ver) > 1 {
					return errors.Trace(fmt.Errorf("versions %s of chart %s in %s do not exist", strings.Join(ver, ","), chart.Name, source))
				} else {
					return errors.Trace(fmt.Errorf("version %s of chart %s in %s does not exist", strings.Join(ver, ","), chart.Name, source))
				}
			}
			return nil
		}

		klog.V(5).Infof("Found %d versions for %q chart: %v", len(versions), chart.Name, versions)
		klog.V(3).Infof("Indexing %q charts...", chart.Name)
		if s.latestVersionOnly {
			vs := make([]*semver.Version, len(versions))
			for i, r := range versions {
				v, err := semver.NewVersion(r)
				if err != nil {
					return errors.Trace(err)
				}
				vs[i] = v
			}
			sort.Sort(semver.Collection(vs))
			// The last element of the array is the latest version
			version := vs[len(vs)-1].String()
			if err := s.processVersion(chart.Name, version, chart.SkipImages, publishingThreshold); err != nil {
				klog.Warningf("Failed processing %s:%s chart. The index will remain incomplete.", chart.Name, version)
				errs = multierror.Append(errs, errors.Trace(err))
				continue
			}
		} else {
			for _, version := range versions {
				if len(chart.Versions) > 0 && shouldSkipChartVersion(version, chart.Versions) {
					klog.V(3).Infof("Indexing %q %q charts SKIPPED...", chart.Name, version)
					continue
				}

				if err := chartutil.ValidateChartVersion(version); err != nil {
					klog.V(3).Infof("Indexing %q %q charts version is invalid SKIPPED...", chart.Name, version)
					continue
				}

				if err := s.processVersion(chart.Name, version, chart.SkipImages, publishingThreshold); err != nil {
					klog.Warningf("Failed processing %s:%s chart. The index will remain incomplete.", chart.Name, version)
					errs = multierror.Append(errs, errors.Trace(err))
					continue
				}
			}
		}
	}

	return errors.Trace(errs)
}

// processVersion takes care of loading a specific version of the chart into the index
func (s *Syncer) processVersion(name, version string, skipImages bool, publishingThreshold time.Time) error {
	details, err := s.cli.src.GetChartDetails(name, version)
	if err != nil {
		return err
	}

	id := fmt.Sprintf("%s-%s", name, version)
	klog.V(5).Infof("Details for %q chart: %+v", id, details)
	if details.PublishedAt.Before(publishingThreshold) {
		klog.V(5).Infof("Skipping %q chart: Published before %q", id, publishingThreshold.String())
		return nil
	}

	if ok, err := s.cli.dst.Has(name, version); err != nil {
		klog.Errorf("unable to explore target repo to check %q chart: %v", id, err)
		return err
	} else if ok {
		klog.V(5).Infof("Skipping %q chart: Already synced", id)
		return nil
	}

	if ch := s.getIndex().Get(id); ch != nil {
		klog.V(5).Infof("Skipping %q chart: Already indexed", id)
		return nil
	}

	if err := s.loadChart(name, version, skipImages); err != nil {
		klog.Errorf("unable to load %q chart: %v", id, err)
		return err
	}
	return nil
}

// loadChart loads a chart in the chart index map
func (s *Syncer) loadChart(name string, version string, skipImages bool) error {
	id := fmt.Sprintf("%s-%s", name, version)
	// loadChart is a recursive function and it will be invoked again for each
	// dependency.
	//
	// It makes sense that different "tier1" charts use the same "tier2" chart
	// dependencies. This check will make the method to skip already indexed
	// charts.
	//
	// Example:
	// `wordpress` is a "tier1" chart that depends on the "tier2" charts `mariadb`
	// and `common`. `magento` is a "tier1" chart that depends on the "tier2"
	// charts `mariadb` and `elasticsearch`.
	//
	// If we run charts-syncer for `wordpress` and `magento`, this check will
	// avoid re-indexing `mariadb` twice.
	if ch := s.getIndex().Get(id); ch != nil {
		klog.V(5).Infof("Skipping %q chart: Already indexed", id)
		return nil
	}
	// In the same way, dependencies may already exist in the target chart
	// repository.
	if ok, err := s.cli.dst.Has(name, version); err != nil {
		return errors.Errorf("unable to explore target repo to check %q chart: %v", id, err)
	} else if ok {
		klog.V(5).Infof("Skipping %q chart: Already synced", id)
		return nil
	}

	tgz, err := s.cli.src.Fetch(name, version)
	if err != nil {
		return errors.Trace(err)
	}

	ch := &Chart{
		Name:       name,
		Version:    version,
		SkipImages: skipImages,
		TgzPath:    tgz,
	}

	if !s.skipDependencies {
		deps, err := chart.GetChartDependencies(tgz, name)
		if err != nil {
			return errors.Trace(err)
		}

		if len(deps) == 0 {
			klog.V(4).Infof("Indexing %q chart", id)
			return errors.Trace(s.getIndex().Add(id, ch))
		}

		var errs error
		for _, dep := range deps {
			depID := fmt.Sprintf("%s-%s", dep.Name, dep.Version)
			if err := s.loadChart(dep.Name, dep.Version, skipImages); err != nil {
				errs = multierror.Append(errs, errors.Annotatef(err, "invalid %q chart dependency", depID))
				continue
			}
			ch.Dependencies = append(ch.Dependencies, depID)
		}
		if errs != nil {
			return errors.Trace(errs)
		}
	}

	klog.V(4).Infof("Indexing %q chart", id)
	return errors.Trace(s.getIndex().Add(id, ch))
}

// topologicalSortCharts returns the indexed charts, topologically sorted.
func (s *Syncer) topologicalSortCharts() ([]*Chart, error) {
	graph := toposort.NewGraph(len(s.getIndex()))
	for name := range s.getIndex() {
		graph.AddNode(name)
	}
	for name, ch := range s.getIndex() {
		for _, dep := range ch.Dependencies {
			graph.AddEdge(dep, name)
		}
	}

	result, ok := graph.Toposort()
	if !ok {
		return nil, errors.Errorf("dependency cycle detected in charts")
	}

	charts := make([]*Chart, len(result))
	for i, id := range result {
		charts[i] = s.getIndex().Get(id)
	}
	return charts, nil
}

func shouldSkipChart(chartName string, skippedCharts []string) bool {
	for _, s := range skippedCharts {
		if s == chartName {
			return true
		}
	}
	return false
}

func shouldSkipChartVersion(chartVersion string, Versions []string) bool {
	for _, s := range Versions {
		if s == chartVersion {
			return false
		}
	}
	return true
}

func verifyChartsVersion(specifiedVersions, chartVersions []string) ([]string, bool) {
	tmpVersions := make(map[string]struct{}, len(chartVersions))
	for _, version := range chartVersions {
		tmpVersions[version] = struct{}{}
	}

	var versions []string
	for _, version := range specifiedVersions {
		if _, ok := tmpVersions[version]; !ok {
			versions = append(versions, version)
		}
	}
	return versions, len(versions) == 0
}
