package utils

import (
	"encoding/json"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"golang.org/x/xerrors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

var (
	VulnStatuses = map[string]string{
		"not_affected":        "This software package is not affected by this vulnerability on this platform.",
		"affected":            "This software package is affected by the vulnerability on this platform, but no patch has been released yet.",
		"fixed":               "A patch has been released for this software package.",
		"under_investigation": "It is currently unknown whether this software package is affected by the vulnerability on this platform, and an investigation is underway.",
		"will_not_fix":        "This software package is affected by the vulnerability on this platform, but there are currently no plans to address it (primarily for vulnerabilities with low or medium impact that do not pose significant risk to customers).",
		"fix_deferred":        "This software package is affected by the vulnerability on this platform and may be fixed in the future.",
		"end_of_life":         "This software package has been identified as containing affected components, but no analysis has been conducted to determine whether it is impacted by this vulnerability.",
	}
	ChineseSeverity = map[string]string{
		"CRITICAL": "CRITICAL",
		"HIGH":     "HIGH",
		"MEDIUM":   "MEDIUM",
		"LOW":      "LOW",
		"UNKNOWN":  "UNKNOWN",
	}
)

// FormatTime 若时间为空，则正常退出并返回空字符串
func FormatTime(t *time.Time, Chinese bool) string {
	if t == nil {
		return ""
	}
	if !Chinese {
		return t.Format("2006 年 01 月 02 日 15:04:05")
	}

	location, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		log.Fatal("failed to load location:%w", err)
	}

	return t.In(location).Format("2006 年 01 月 02 日 15:04:05")
}

// ReadJSONFromFile 从文件中读取 json 文件
func ReadJSONFromFile(filename string) (*types.Report, error) {
	// 若不是 JSON 文件，则正常返回
	if filepath.Ext(filename) != ".json" {
		log.Debugf("%s is not json file", filename)
		return nil, nil
	}

	// 读取文件
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, xerrors.Errorf("failed to read file:%w", err)
	}
	log.Debugf("success to read %s", filename)

	// 转化为json
	var report types.Report
	if err = json.Unmarshal(data, &report); err != nil {
		return nil, xerrors.Errorf("failed to unmarshal json:%w", err)
	}
	return &report, nil
}

func Sort(data map[string]int) [][]string {
	var (
		items []struct {
			Key   string
			Value int
		}
		result = make([][]string, len(data))
	)

	for k, v := range data {
		items = append(items, struct {
			Key   string
			Value int
		}{Key: k, Value: v})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Value > items[j].Value
	})

	for i, item := range items {
		result[i] = []string{item.Key, strconv.Itoa(item.Value)}
	}

	return result
}

func SetArtifactType(artifactType artifact.Type) string {
	if artifactType == artifact.TypeContainerImage {
		return "Container image"
	}
	return string(artifactType)
}

func SetResultClass(resultClass types.ResultClass) string {
	switch resultClass {
	case types.ClassOSPkg:
		return "System-level software packages"
	case types.ClassLangPkg:
		return "Application Layer Software Package"
	default:
		return string(resultClass)
	}
}
