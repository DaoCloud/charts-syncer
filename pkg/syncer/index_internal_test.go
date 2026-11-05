package syncer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/bitnami-labs/charts-syncer/api"
)

func removeTgzPath(i ChartIndex) {
	for _, c := range i {
		c.TgzPath = ""
	}
}

func TestLoadCharts(t *testing.T) {
	testCases := []struct {
		desc           string
		entries        []*api.Charts
		skippedEntries []string
		want           ChartIndex
		wantErr        bool
	}{
		{
			desc:    "load apache and kafka",
			entries: []*api.Charts{{Name: "apache"}, {Name: "kafka"}},
			want: ChartIndex{
				"apache-7.3.15":    &Chart{Name: "apache", Version: "7.3.15"},
				"kafka-10.3.3":     &Chart{Name: "kafka", Version: "10.3.3", Dependencies: []string{"zookeeper-5.14.3"}},
				"zookeeper-5.14.3": &Chart{Name: "zookeeper", Version: "5.14.3"},
			},
		},
		{
			desc:           "skip apache and kafka",
			entries:        []*api.Charts{{Name: "apache"}, {Name: "kafka"}, {Name: "zookeeper"}},
			skippedEntries: []string{"apache", "kafka"},
			want: ChartIndex{
				"zookeeper-5.14.3": &Chart{Name: "zookeeper", Version: "5.14.3"},
			},
		},
		{
			desc:    "missing version returns an error but loads the others",
			entries: []*api.Charts{{Name: "apache", Versions: []string{"7.3.15", "9.9.9"}}},
			want: ChartIndex{
				"apache-7.3.15": &Chart{Name: "apache", Version: "7.3.15"},
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			s := NewFake(t, WithFakeSkipCharts(tc.skippedEntries))
			if err := s.loadCharts(tc.entries...); (err != nil) != tc.wantErr {
				t.Fatalf("unexpected error loading charts: %v, wantErr: %v", err, tc.wantErr)
			}

			// Remove TgzPath values from the computed index
			removeTgzPath(s.getIndex())

			if diff := cmp.Diff(tc.want, s.getIndex()); diff != "" {
				t.Errorf("want vs got diff:\n %+v", diff)
			}
		})
	}
}

func TestLoadChartsRenderOnly(t *testing.T) {
	dst := t.TempDir()
	input, err := os.ReadFile("../../testdata/apache-7.3.15.tgz")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "apache-7.3.15.tgz"), input, 0644); err != nil {
		t.Fatal(err)
	}

	for _, renderOnly := range []bool{false, true} {
		s := NewFake(t, WithFakeSyncerDestination(dst))
		s.renderOnly = renderOnly
		if err := s.loadCharts(&api.Charts{Name: "apache", Versions: []string{"7.3.15"}}); err != nil {
			t.Fatal(err)
		}
		if got := s.getIndex().Get("apache-7.3.15") != nil; got != renderOnly {
			t.Errorf("renderOnly=%v: apache indexed = %v, want %v", renderOnly, got, renderOnly)
		}
	}
}

func TestLoadChartsVerify(t *testing.T) {
	for _, renderOnly := range []bool{false, true} {
		s := NewFake(t)
		s.verify = true
		s.renderOnly = renderOnly
		if err := s.loadCharts(&api.Charts{Name: "apache", Versions: []string{"7.3.15"}}); err != nil {
			t.Fatal(err)
		}
		if got := s.getIndex().Get("apache-7.3.15") != nil; got != renderOnly {
			t.Errorf("renderOnly=%v: apache indexed = %v, want %v", renderOnly, got, renderOnly)
		}
		if err := s.loadCharts(&api.Charts{Name: "apache", Versions: []string{"9.9.9"}}); err == nil {
			t.Errorf("renderOnly=%v: expected error for missing version", renderOnly)
		}
	}
}

func TestTopologicalSortCharts(t *testing.T) {
	testCases := []struct {
		desc  string
		index ChartIndex
		want  []*Chart
	}{
		{
			desc: "sort index to put dependencies first",
			index: ChartIndex{
				"kafka-10.3.3":     &Chart{Name: "kafka", Version: "10.3.3", Dependencies: []string{"zookeeper-5.14.3"}},
				"zookeeper-5.14.3": &Chart{Name: "zookeeper", Version: "5.14.3"},
			},
			want: []*Chart{
				{Name: "zookeeper", Version: "5.14.3"},
				{Name: "kafka", Version: "10.3.3", Dependencies: []string{"zookeeper-5.14.3"}},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			s := &Syncer{index: tc.index}

			got, err := s.topologicalSortCharts()
			if err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("want vs got diff:\n %+v", diff)
			}
		})
	}
}
