package main

import (
	"reflect"
	"testing"
)

func TestHostPlans(t *testing.T) {
	for _, tt := range []struct {
		host, target string
		want         []string
	}{{"linux", "", []string{"linux"}}, {"windows", "", []string{"windows"}}, {"darwin", "", []string{"macos"}}, {"linux", "all", []string{"linux", "windows"}}, {"windows", "all", []string{"windows"}}, {"darwin", "all", []string{"macos", "windows", "linux"}}, {"linux", "windows", []string{"windows"}}, {"darwin", "linux", []string{"linux"}}, {"darwin", "darwin", []string{"macos"}}} {
		t.Run(tt.host+"/"+tt.target, func(t *testing.T) {
			p, e := plan(tt.host, tt.target)
			if e != nil {
				t.Fatal(e)
			}
			var got []string
			for _, b := range p {
				got = append(got, b.target)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v want %v", got, tt.want)
			}
		})
	}
}
func TestUnsupportedTarget(t *testing.T) {
	for _, tt := range [][2]string{{"linux", "macos"}, {"windows", "linux"}, {"windows", "macos"}, {"linux", "unknown"}} {
		if _, e := plan(tt[0], tt[1]); e == nil {
			t.Fatalf("accepted %v", tt)
		}
	}
}
