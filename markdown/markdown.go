package markdown

import (
	"fmt"
	"github.com/aquasecurity/trivy/pkg/types"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/miao2sec/trivy-plugin-report/utils"
	"os"
	"strconv"
	"strings"
)

func Export(report *types.Report, fileName string, brief bool) (err error) {
	md := utils.NewMarkdown(utils.WithName(fileName))

	md.SetH1("1. Overview")
	md = AddArtifactInfo(report, md)
	md = AddImageConf(report.Metadata.ImageConfig, md)
	md = AddVulnOverview(report, md)

	md.SetH1("2. Scan results")
	md = AddScanResult(report, md, brief)

	return os.WriteFile(md.Name, []byte(md.Data), os.ModePerm)
}

func AddArtifactInfo(report *types.Report, md *utils.Markdown) *utils.Markdown {
	var (
		artifactType = utils.SetArtifactType(report.ArtifactType)
		scanTime     = utils.FormatTime(&report.CreatedAt, true)
		osInfo       string
	)
	if report.Metadata.OS != nil {
		osInfo = fmt.Sprintf("%s %s", report.Metadata.OS.Family, report.Metadata.OS.Name)
	} else {
		osInfo = "Linux"
	}
	md.SetH2("1.1 Product Information")
	md.SetText(fmt.Sprintf("%s %s is built on the %s operating system, designed for the %s architecture, and has identified potential security issues during %s security scans.",
		artifactType, report.ArtifactName, osInfo, report.Metadata.ImageConfig.Architecture, scanTime))
	artifactInfo := [][]string{{"Product Name", report.ArtifactName}}
	addRow(&artifactInfo, "Creation date", utils.FormatTime(&report.Metadata.ImageConfig.Created.Time, true))
	addRow(&artifactInfo, "Architecture", report.Metadata.ImageConfig.Architecture)
	addRow(&artifactInfo, "Operating System", osInfo)
	addRow(&artifactInfo, "Warehouse Label", strings.Join(report.Metadata.RepoTags, "<br/>"))
	addRow(&artifactInfo, "Mirror image ID", report.Metadata.ImageID)
	addRow(&artifactInfo, "Container", report.Metadata.ImageConfig.Container)
	addRow(&artifactInfo, "Docker Version", report.Metadata.ImageConfig.DockerVersion)
	addRow(&artifactInfo, "Scan time", scanTime)
	md.SetTable([]string{"Product Type", artifactType}, artifactInfo)
	return md
}
func AddVulnOverview(report *types.Report, md *utils.Markdown) *utils.Markdown {
	var (
		Severities = make(map[string]map[string]int)
		Vulns      = make(map[string]int)
		Pkgs       = make(map[string]int)
		FixedVulns = make(map[string]int)
		target     string
		vulnName   string
		fixedCount int
		vulnCount  int
	)
	for _, result := range report.Results {
		if result.Class != types.ClassOSPkg && result.Class != types.ClassLangPkg {
			continue
		}
		if result.Class == types.ClassOSPkg {
			target = fmt.Sprintf("System Layer Component Vulnerabilities：%s", result.Target)
		} else {
			target = fmt.Sprintf("Application Layer Component Vulnerabilities：%s", result.Target)
		}
		Severities[target] = make(map[string]int)
		for _, vuln := range result.Vulnerabilities {
			if vuln.Title == "" {
				vulnName = vuln.VulnerabilityID
			} else {
				vulnName = fmt.Sprintf("%s : %s", vuln.VulnerabilityID, vuln.Title)
			}
			Severities[target][vuln.Severity]++
			Vulns[vulnName]++
			Pkgs[vuln.PkgName]++
			vulnCount++
			if vuln.FixedVersion != "" {
				fixedCount++
				FixedVulns[vulnName]++
			}
		}
	}

	md.SetH2("1.3 Vulnerability Overview")
	md = countSeverity(md, Severities)
	md = countFixedVuln(md, FixedVulns, fixedCount, vulnCount)
	md = countPkgs(md, Pkgs)
	return countVulns(md, Vulns)
}
func AddImageConf(ImageConfig v1.ConfigFile, md *utils.Markdown) *utils.Markdown {
	var (
		histories [][]string
		confs     [][]string
	)

	for _, history := range ImageConfig.History {
		histories = append(histories, []string{history.Created.Format("2006-01-02 15:04:05"), history.CreatedBy})
	}
	for _, cmd := range ImageConfig.Config.Cmd {
		confs = append(confs, []string{"Execute command", cmd})
	}
	for _, env := range ImageConfig.Config.Env {
		confs = append(confs, []string{"Environment Variables", env})
	}
	md.SetH2("1.2 Mirror Configuration")
	md.SetText("The mirror creation history is shown below. Please manually check for any suspicious execution commands, such as downloading malicious files.")
	md.SetTable([]string{"创建时间", "历史记录"}, histories)
	md.SetText("Configuration details for the mirror are listed below. Please manually inspect for any suspicious executable commands or exposed secrets, such as malicious commands or application keys.")
	md.SetTable([]string{"Configuration Type", "Content"}, confs)
	return md
}
func AddScanResult(report *types.Report, md *utils.Markdown, brief bool) *utils.Markdown {
	for i, result := range report.Results {
		if result.Vulnerabilities == nil {
			continue
		}
		md.SetH2(fmt.Sprintf("2.%v %s", i+1, result.Target))
		md.SetTable([]string{"Scan Target", result.Target}, [][]string{
			{"Software Package Type", utils.SetResultClass(result.Class)},
			{"Target Type", string(result.Type)}})

		for j, vulnerability := range result.Vulnerabilities {
			var pkgInfo, vulnInfo [][]string
			if vulnerability.Title == "" {
				md.SetH3(fmt.Sprintf("2.%v.%v %s", i+1, j+1, vulnerability.VulnerabilityID))
			} else {
				md.SetH3(fmt.Sprintf("2.%v.%v %s:%s", i+1, j+1, vulnerability.VulnerabilityID, vulnerability.Title))
			}

			// 软件包信息
			md.SetH4(fmt.Sprintf("2.%v.%v.1 Software Package Information", i+1, j+1))
			addRow(&pkgInfo, "Software Package Name", vulnerability.PkgName)
			addRow(&pkgInfo, "Installation Version", vulnerability.InstalledVersion)
			addRow(&pkgInfo, "Software Package ID", vulnerability.PkgID)
			addRow(&pkgInfo, "Fixed Version", vulnerability.FixedVersion)
			md.SetTable([]string{"Software Package URL", vulnerability.PkgIdentifier.PURL.String()}, pkgInfo)

			// 漏洞信息
			md.SetH4(fmt.Sprintf("2.%v.%v.2 Vulnerability Information", i+1, j+1))
			addRow(&vulnInfo, "Vulnerability Title", vulnerability.Title)
			addRow(&vulnInfo, "Threat Level", utils.ChineseSeverity[vulnerability.Severity])
			addRow(&vulnInfo, "Threat Level Source", string(vulnerability.SeveritySource))
			addRow(&vulnInfo, "Supplier Vulnerability ID", strings.Join(vulnerability.VendorIDs, "<br/>"))
			addRow(&vulnInfo, "Status", utils.VulnStatuses[vulnerability.Status.String()])
			addRow(&vulnInfo, "Disclosure Date", utils.FormatTime(vulnerability.PublishedDate, true))
			addRow(&vulnInfo, "Last modified", utils.FormatTime(vulnerability.LastModifiedDate, true))
			md.SetTable([]string{"Vulnerability ID", vulnerability.VulnerabilityID}, vulnInfo)

			if !brief {
				// 漏洞描述
				md.SetH4(fmt.Sprintf("2.%v.%v.3 Vulnerability Description", i+1, j+1))
				md.SetText(vulnerability.Description)
				// 相关链接
				md.SetH4(fmt.Sprintf("2.%v.%v.4 Related Links", i+1, j+1))
				md.SetUl(append([]string{vulnerability.PrimaryURL, vulnerability.DataSource.URL}, vulnerability.References...))
			}
		}
	}
	return md
}

func countSeverity(md *utils.Markdown, SeverityCount map[string]map[string]int) *utils.Markdown {
	var (
		Severities                                [][]string
		critical, high, medium, low, unknown, all int
	)

	for target, severities := range SeverityCount {
		Severities = append(Severities, []string{
			target,
			strconv.Itoa(severities["CRITICAL"]),
			strconv.Itoa(severities["HIGH"]),
			strconv.Itoa(severities["MEDIUM"]),
			strconv.Itoa(severities["LOW"]),
			strconv.Itoa(severities["UNKNOWN"]),
			strconv.Itoa(severities["CRITICAL"] + severities["HIGH"] + severities["MEDIUM"] +
				severities["LOW"] + severities["UNKNOWN"]),
		})
		critical += severities["CRITICAL"]
		high += severities["HIGH"]
		medium += severities["MEDIUM"]
		low += severities["LOW"]
		unknown += severities["UNKNOWN"]
	}
	all = critical + high + medium + low + unknown
	Severities = append(Severities, []string{
		"漏洞总数", strconv.Itoa(critical), strconv.Itoa(high), strconv.Itoa(medium),
		strconv.Itoa(low), strconv.Itoa(unknown), strconv.Itoa(all),
	})
	md.SetText(fmt.Sprintf("A total of %v vulnerabilities were scanned, including %v critical vulnerabilities, accounting for %.2f%% of the total; and %v high-risk vulnerabilities, accounting for %.2f%% of the total.",
		all, critical, float64(critical)/float64(all)*100, high, float64(high)/float64(all)*100))
	md.SetTable([]string{"", "Extremely dangerous", "High-risk", "Moderate risk", "Low risk", "Unknown", "Total"}, Severities)
	return md
}
func countFixedVuln(md *utils.Markdown, FixedVuln map[string]int, fixedCount int, vulnCount int) *utils.Markdown {
	md.SetText(fmt.Sprintf("Among these, %v vulnerabilities are fixable, accounting for %.2f%% of the total.", fixedCount, float64(fixedCount)/float64(vulnCount)*100))
	md.SetTable([]string{"Vulnerabilities that can be fixed", "Number of vulnerabilities"}, utils.Sort(FixedVuln))
	return md
}
func countVulns(md *utils.Markdown, vulns map[string]int) *utils.Markdown {
	md.SetText(fmt.Sprintf("The full list of vulnerabilities is shown below. For detailed vulnerability information, please refer to the scan results in Part Two."))
	md.SetTable([]string{"Vulnerability Name", "Number of vulnerabilities"}, utils.Sort(vulns))
	return md
}
func countPkgs(md *utils.Markdown, pkgs map[string]int) *utils.Markdown {
	md.SetText(fmt.Sprintf("The software packages containing vulnerabilities are listed below:。"))
	md.SetTable([]string{"Software Package Name", "Number of vulnerabilities included"}, utils.Sort(pkgs))
	return md
}

func addRow(rows *[][]string, key, value string) {
	if value != "" {
		*rows = append(*rows, []string{key, value})
	}
}
