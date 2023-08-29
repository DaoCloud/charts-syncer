package syncer

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"

	"github.com/avast/retry-go"
	"github.com/juju/errors"
	"github.com/mkmik/multierror"
	"github.com/vmware-tanzu/asset-relocation-tool-for-kubernetes/pkg/mover"
	"gopkg.in/yaml.v2"
	helm "helm.sh/helm/v3/pkg/action"
	helmchart "helm.sh/helm/v3/pkg/chart"
	"k8s.io/klog/v2"

	"github.com/bitnami-labs/charts-syncer/api"
	"github.com/bitnami-labs/charts-syncer/internal/chart"
	"github.com/bitnami-labs/charts-syncer/internal/utils"
	"github.com/bitnami-labs/charts-syncer/pkg/util"
)

// SyncPendingCharts syncs the charts not found in the target
//
// It uses topological sort to sync dependencies first.
func (s *Syncer) SyncPendingCharts(chs ...*api.Charts) error {
	var errs error

	// There might be problems loading all the charts due to missing dependencies,
	// invalid/wrong charts in the repository, etc. Therefore, let's warn about
	// them instead of blocking the whole sync.
	err := s.loadCharts(chs...)
	if err != nil {
		if s.verify {
			return err
		} else {
			klog.Warningf("There were some problems loading the information of the requested charts: %v", err)
			errs = multierror.Append(errs, errors.Trace(err))
		}
	}

	if s.verify {
		fmt.Println("verify success!")
		return nil
	}

	// NOTE: We are not checking `errs` in purpose. See the comment above.
	charts, err := s.topologicalSortCharts()
	if err != nil {
		return errors.Trace(err)
	}

	if len(charts) > 1 {
		klog.Infof("There are %d charts out of sync!", len(charts))
	} else if len(charts) == 1 {
		klog.Infof("There is %d chart out of sync!", len(charts))
	} else {
		klog.Info("There are no charts out of sync!")
		return nil
	}

	for _, ch := range charts {
		id := fmt.Sprintf("%s_%s", ch.Name, ch.Version)
		klog.Infof("Syncing %q chart...", id)

		klog.V(3).Infof("Processing %q chart...", id)
		outdir, err := ioutil.TempDir("", "charts-syncer")
		if err != nil {
			klog.Errorf("unable to create output directory for %q chart: %+v", id, err)
			errs = multierror.Append(errs, errors.Trace(err))
			continue
		}
		defer os.RemoveAll(outdir)

		hasDeps := len(ch.Dependencies) > 0

		workdir, err := ioutil.TempDir("", "charts-syncer")
		if err != nil {
			klog.Errorf("unable to create work directory for %q chart: %+v", id, err)
			errs = multierror.Append(errs, errors.Trace(err))
			continue
		}
		defer os.RemoveAll(workdir)

		// Some client Upload() methods needs this info
		metadata := &helmchart.Metadata{
			Name:    ch.Name,
			Version: ch.Version,
		}
		var packagedChartPath string

		// If any of the source or target objects contains an intermediate bundles path it means we are running a partial
		// sync. Either from a repo to an intermediate dir, or from an intermediate dir to a repo.
		intermediateScenario := s.source.GetIntermediateBundlesPath() != "" || s.target.GetIntermediateBundlesPath() != ""
		if s.relocateContainerImages || intermediateScenario {
			packagedChartPath, err = s.SyncWithRelok8s(ch, outdir)
			if err != nil {
				errs = multierror.Append(errs, errors.Annotatef(err, "unable to move chart %q with relok8s", id))
				continue
			}
		} else {
			packagedChartPath, err = s.SyncWithChartsSyncer(ch, id, workdir, outdir, hasDeps)
			if err != nil {
				errs = multierror.Append(errs, errors.Annotatef(err, "unable to move chart %q with charts-syncer", id))
				continue
			}
		}

		if s.dryRun {
			klog.Infof("dry-run: Uploading %q chart", id)
			continue
		}

		klog.V(3).Infof("Uploading %q chart...", id)
		err = retry.Do(
			func() error {
				if err := s.cli.dst.Upload(packagedChartPath, metadata); err != nil {
					return err
				}
				return nil
			},
			retry.Attempts(3),
			retry.OnRetry(func(n uint, err error) {
				klog.V(3).Infof("Attempt #%d failed: %s\n", n+1, err.Error())
			}),
		)
		if err != nil {
			klog.Errorf("unable to upload %q chart: %+v", id, err)
			errs = multierror.Append(errs, errors.Trace(err))
			continue
		}
	}

	return errors.Trace(errs)
}

// SyncWithRelok8s will take a local packaged chart, a container registry and a container repository and will rewrite the chart
// updating the images in values.yaml. The local chart must include an image hints file so relok8s library knows how to
// update the images
func (s *Syncer) SyncWithRelok8s(chart *Chart, outdir string) (string, error) {
	req, packagedChartPath := getRelok8sMoveRequest(s.source, s.target, chart, outdir)

	skipImages := func() bool {
		if s.skipImages {
			return s.skipImages
		}
		return chart.SkipImages
	}

	chartMover, err := mover.NewChartMover(req, mover.WithInsecure(s.insecure), mover.WithPlatform(s.platform), mover.WithSkipImages(skipImages()))
	if err != nil {
		klog.Errorf("unable to create chart mover: %+v", err)
		return "", errors.Trace(err)
	}

	if s.autoCreateRepository && s.target.GetRepo() != nil && util.CheckoutSupportAutoCreateRepository(s.target.GetRepo().Kind) {
		err = retry.Do(
			func() error {
				err = s.SyncChartRepository()
				if err != nil {
					return err
				}
				return nil
			},
			retry.Attempts(3),
			retry.OnRetry(func(n uint, err error) {
				klog.V(3).Infof("Attempt #%d failed: %s\n", n+1, err.Error())
			}),
		)
		if err != nil {
			return "", err
		}
	}

	if s.autoCreateRepository && s.target.Containers != nil && util.CheckoutSupportAutoCreateRepository(s.target.Containers.Kind) {
		err = retry.Do(
			func() error {
				err = s.SyncImagesRepository(chartMover)
				if err != nil {
					return err
				}
				return nil
			},
			retry.Attempts(3),
			retry.OnRetry(func(n uint, err error) {
				klog.V(3).Infof("Attempt #%d failed: %s\n", n+1, err.Error())
			}),
		)
		if err != nil {
			return "", err
		}
	}

	if err = chartMover.Move(); err != nil {
		klog.Errorf("unable to move chart %s:%s: %+v", chart.Name, chart.Version, err)
		return "", errors.Trace(err)
	}

	return packagedChartPath, nil
}

func (s *Syncer) SyncChartRepository() error {
	if s.target.GetRepo() == nil {
		return nil
	}

	err := s.cli.dst.CreateRepository(s.target.GetRepo().Url)
	if err != nil {
		return err
	}
	return nil
}

func (s *Syncer) SyncImagesRepository(chartMover *mover.ChartMover) error {
	if s.target.Containers == nil {
		return nil
	}

	if s.containerCLI == nil {
		return nil
	}

	changes := chartMover.GetImageChanges()
	for _, change := range changes {
		err := s.containerCLI.CreateRepository(change.RewrittenReference.Name())
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Syncer) SyncWithChartsSyncer(ch *Chart, id, workdir, outdir string, hasDeps bool) (string, error) {
	if err := utils.Untar(ch.TgzPath, workdir); err != nil {
		klog.Errorf("unable to uncompress %q chart: %+v", id, err)
		return "", errors.Trace(errors.Annotatef(err, "uncompressing %q chart", id))
	}

	chartPath := path.Join(workdir, ch.Name)
	if err := chart.ChangeReferences(chartPath, ch.Name, ch.Version, s.source, s.target); err != nil {
		klog.Errorf("unable to process %q chart: %+v", id, err)
		return "", errors.Trace(err)

	}

	// Update deps
	if hasDeps {
		klog.V(3).Infof("Building %q dependencies", id)
		if err := chart.BuildDependencies(chartPath, s.cli.dst, s.source.GetRepo(), s.target.GetRepo()); err != nil {
			klog.Errorf("unable to build %q chart dependencies: %+v", id, err)
			return "", errors.Trace(err)
		}
	}

	// Read final chart metadata
	configFilePath := fmt.Sprintf("%s/Chart.yaml", chartPath)
	chartConfig, err := ioutil.ReadFile(configFilePath)
	if err != nil {
		klog.Errorf("unable to read %q metadata: %+v", id, err)
		return "", errors.Trace(err)
	}
	metadata := &helmchart.Metadata{}
	if err = yaml.Unmarshal(chartConfig, metadata); err != nil {
		klog.Errorf("unable to decode %q metadata: %+v", id, err)
		return "", errors.Trace(err)
	}

	// Package chart again
	klog.V(3).Infof("Packaging %q", id)
	pkgCli := helm.NewPackage()
	pkgCli.Destination = outdir
	packagedChartPath, err := pkgCli.Run(chartPath, nil)
	if err != nil {
		klog.Errorf("unable to package %q chart: %+v", id, err)
		return "", errors.Trace(err)
	}

	return packagedChartPath, nil
}

func (s *Syncer) GetRenderedImages(chs ...*api.Charts) ([]string, error) {
	err := s.loadCharts(chs...)
	if err != nil {
		return nil, err
	}

	charts, err := s.topologicalSortCharts()
	if err != nil {
		return nil, errors.Trace(err)
	}
	if len(charts) < 1 {
		return []string{}, nil
	}

	images := make([]string, 0)
	for _, ch := range charts {
		outdir, err := ioutil.TempDir("", "charts-syncer")
		if err != nil {
			return nil, err
		}
		req, _ := getRelok8sMoveRequest(s.source, s.target, ch, outdir)
		chartMover, err := mover.NewChartMover(req, mover.WithInsecure(s.insecure), mover.WithPlatform(s.platform))
		if err != nil {
			return nil, errors.Trace(err)
		}
		for _, imageChange := range chartMover.GetImageChanges() {
			images = append(images, imageChange.ImageReference.Name())
		}
	}
	return images, nil
}

func getRelok8sMoveRequest(source *api.Source, target *api.Target, chart *Chart, outdir string) (*mover.ChartMoveRequest, string) {
	if target.GetIntermediateBundlesPath() != "" {
		// airgap scenario step 1: SOURCE REPO => Intermediate bundles path
		packagedChartPath := filepath.Join(outdir, fmt.Sprintf("%s-%s.bundle.tar", chart.Name, chart.Version))
		return relok8sBundleSaveReq(chart.TgzPath, packagedChartPath, source.GetContainers().GetAuth()), packagedChartPath
	} else if source.GetIntermediateBundlesPath() != "" {
		// airgap scenario step 2: Intermediate bundles path => TARGET REPO
		// Second step of intermediate process
		// Once https://github.com/vmware-tanzu/asset-relocation-tool-for-kubernetes/issues/94 is solved, we could
		// specify the name we want for the output file. Until then, we should keep using this template thing
		outputChartPath := filepath.Join(outdir, "%s-%s.relocated.tgz")
		packagedChartPath := filepath.Join(outdir, fmt.Sprintf("%s-%s.relocated.tgz", chart.Name, chart.Version))
		return relok8sBundleLoadReq(
			chart.TgzPath, outputChartPath,
			target.GetContainerRegistry(), target.GetContainerRepository(),
			target.GetContainerPrefixRegistry(), target.GetContainerPrefixRepository(), target.GetContainers().GetAuth()), packagedChartPath
	} else {
		// Direct syncing, SOURCE_REPO => TARGET_REPO
		// Once https://github.com/vmware-tanzu/asset-relocation-tool-for-kubernetes/issues/94 is solved, we could
		// specify the name we want for the output file. Until then, we should keep using this template thing
		outputChartPath := filepath.Join(outdir, "%s-%s.tgz")
		packagedChartPath := filepath.Join(outdir, fmt.Sprintf("%s-%s.tgz", chart.Name, chart.Version))
		return relok8sMoveReq(chart.TgzPath, outputChartPath, target.GetContainerRegistry(), target.GetContainerRepository(),
			target.GetContainerPrefixRegistry(), target.GetContainerPrefixRepository(), source.GetContainers().GetAuth(), target.GetContainers().GetAuth()), packagedChartPath
	}
}

func relok8sMoveReq(sourcePath, targetPath, containerRegistry, containerRepository, containerPrefixRegistry, containerPrefixRepository string, sourceAuth, targetAuth *api.Containers_ContainerAuth) *mover.ChartMoveRequest {
	req := &mover.ChartMoveRequest{
		Source: mover.Source{
			Chart: mover.ChartSpec{
				Local: &mover.LocalChart{
					Path: sourcePath,
				},
			},
			ContainersAuth: chartsSyncerToRelok8sAuth(sourceAuth),
		},
		Target: mover.Target{
			Rules: mover.RewriteRules{
				Registry:         containerRegistry,
				PrefixRegistry:   containerPrefixRegistry,
				Repository:       containerRepository,
				PrefixRepository: containerPrefixRepository,
				ForcePush:        true,
			},
			Chart: mover.ChartSpec{
				Local: &mover.LocalChart{
					Path: targetPath,
				},
			},
			ContainersAuth: chartsSyncerToRelok8sAuth(targetAuth),
		},
	}

	return req
}

func relok8sBundleSaveReq(sourcePath, targetPath string, containerSourceAuth *api.Containers_ContainerAuth) *mover.ChartMoveRequest {
	req := &mover.ChartMoveRequest{
		Source: mover.Source{
			Chart: mover.ChartSpec{
				Local: &mover.LocalChart{
					Path: sourcePath,
				},
			},
			ContainersAuth: chartsSyncerToRelok8sAuth(containerSourceAuth),
		},
		Target: mover.Target{
			Chart: mover.ChartSpec{
				IntermediateBundle: &mover.IntermediateBundle{
					Path: targetPath,
				},
			},
		},
	}
	return req
}

func relok8sBundleLoadReq(sourcePath, targetPath, containerRegistry, containerRepository, containerPrefixRegistry, containerPrefixRepository string, containerTargetAuth *api.Containers_ContainerAuth) *mover.ChartMoveRequest {
	req := &mover.ChartMoveRequest{
		Source: mover.Source{
			Chart: mover.ChartSpec{
				IntermediateBundle: &mover.IntermediateBundle{
					Path: sourcePath,
				},
			},
		},
		Target: mover.Target{
			Rules: mover.RewriteRules{
				Registry:         containerRegistry,
				PrefixRegistry:   containerPrefixRegistry,
				Repository:       containerRepository,
				PrefixRepository: containerPrefixRepository,
				ForcePush:        true,
			},
			Chart: mover.ChartSpec{
				Local: &mover.LocalChart{
					Path: targetPath,
				},
			},
			ContainersAuth: chartsSyncerToRelok8sAuth(containerTargetAuth),
		},
	}
	return req
}

// Translates charts syncer authentication settings into relok8s authentication
func chartsSyncerToRelok8sAuth(containerAuth *api.Containers_ContainerAuth) (relok8sAuth *mover.ContainersAuth) {
	if containerAuth == nil {
		return nil
	}

	return &mover.ContainersAuth{
		Credentials: &mover.OCICredentials{
			Username: containerAuth.Username, Password: containerAuth.Password, Server: containerAuth.Registry,
		},
	}
}
