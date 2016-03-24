package db

import (
	"reflect"
	"testing"

	"github.com/k0kubun/pp"
	"github.com/kotakanbe/go-cve-dictionary/models"
)

func TestParseJvnCpe(t *testing.T) {
	var testdata = []struct {
		cpeName string
		cpe     models.Cpe
	}{
		{
			"cpe:/a:mysql:mysql",
			models.Cpe{
				CpeName:  "cpe:/a:mysql:mysql",
				Part:     "a",
				Vendor:   "mysql",
				Product:  "mysql",
				Version:  "",
				Update:   "",
				Edition:  "",
				Language: "",
			},
		},
		{
			"cpe:/o:microsoft:windows_7:::x32",
			models.Cpe{
				CpeName:  "cpe:/o:microsoft:windows_7:::x32",
				Part:     "o",
				Vendor:   "microsoft",
				Product:  "windows_7",
				Version:  "",
				Update:   "",
				Edition:  "x32",
				Language: "",
			},
		},
		{
			"cpe:/a:alvaro_herrera:pl/php",
			models.Cpe{
				CpeName:  "cpe:/a:alvaro_herrera:pl/php",
				Part:     "a",
				Vendor:   "alvaro_herrera",
				Product:  "pl/php",
				Version:  "",
				Update:   "",
				Edition:  "",
				Language: "",
			},
		},
	}

	for _, tt := range testdata {
		cpe, err := parseCpe(tt.cpeName)
		if err != nil {
			t.Errorf("scenario: error not occured. data: %s, err: %s ", tt.cpeName, err)
		}
		if !reflect.DeepEqual(tt.cpe, cpe) {
			t.Errorf("scenario: expected %v, actual %v",
				pp.Sprintf("%v", tt.cpe),
				pp.Sprintf("%v", cpe),
			)
		}
	}

	var testerr = []struct {
		cpeName string
	}{
		{"cpe:a:mysql"},
	}

	for _, tt := range testerr {
		_, err := parseCpe(tt.cpeName)
		if err == nil {
			t.Errorf("scenario: error not occured. data: %s ", tt.cpeName)
		}
	}
}
