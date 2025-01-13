package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"bufio"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	toml "github.com/BurntSushi/toml" 
)

type GithubFile struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Path string `json:"path"`
}

type OSVResponse struct {
	Results []struct {
		Vulnerabilities []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
		} `json:"vulnerabilities"`
	} `json:"results"`
}

var dependencyFiles = []string{
	"package.json",
	"requirements.txt",
	"Pipfile",
	"pyproject.toml",
	"pom.xml",
	"build.gradle",
	"go.mod",
	"go.sum",
	"Cargo.toml",
	"Cargo.lock",
}

var githubToken string

func init() {
	githubToken = os.Getenv("GITHUB_TOKEN")
	if githubToken == "" {
		fmt.Println("Warning: GITHUB_TOKEN environment variable not set. API rate limits may be restricted.")
	}
}

func fetchFiles(repo, path string) ([]GithubFile, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/contents/%s", repo, path)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	if githubToken != "" {
		req.Header.Set("Authorization", "token "+githubToken)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch files: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var files []GithubFile
	err = json.Unmarshal(body, &files)
	if err != nil {
		return nil, err
	}

	time.Sleep(time.Second) 
	return files, nil
}

func processRepo(repo string) error {
	files, err := fetchFiles(repo, "")
	if err != nil {
		return fmt.Errorf("error fetching root directory: %v", err)
	}

	for _, file := range files {
		if file.Type == "dir" {
			err := processDirectory(repo, file.Path)
			if err != nil {
				fmt.Printf("Error processing directory %s: %v\n", file.Path, err)
			}
		} else if contains(dependencyFiles, file.Name) {
			err := processDependencyFile(repo, file.Path)
			if err != nil {
				fmt.Printf("Error processing file %s: %v\n", file.Path, err)
			}
		}
	}

	return nil
}

func processDirectory(repo, path string) error {
	files, err := fetchFiles(repo, path)
	if err != nil {
		return fmt.Errorf("error fetching files from directory %s: %v", path, err)
	}

	for _, file := range files {
		if file.Type == "dir" {
			err := processDirectory(repo, file.Path)
			if err != nil {
				fmt.Printf("Error processing subdirectory %s: %v\n", file.Path, err)
			}
		} else if contains(dependencyFiles, file.Name) {
			err := processDependencyFile(repo, file.Path)
			if err != nil {
				fmt.Printf("Error processing file %s: %v\n", file.Path, err)
			}
		}
	}

	return nil
}

func processDependencyFile(repo, filePath string) error {
	content, err := fetchFileContent(repo, filePath)
	if err != nil {
		return fmt.Errorf("error fetching %s: %v", filePath, err)
	}

	fileName := filepath.Base(filePath)
	packages := extractPackages(fileName, content)

	for name, version := range packages {
		ecosystem := determineEcosystem(fileName)
		fmt.Printf("Extracted package: %s (Version: %s)\n", name, version) 
		if version != "" {
			err := checkVulnerabilities(name, version, ecosystem)
			if err != nil {
				fmt.Printf("Error checking vulnerabilities for %s@%s (%s): %v\n", name, version, ecosystem, err)
			}
		}
	}

	return nil
}

func fetchFileContent(repo, filePath string) (string, error) {
	var content string
	for _, branch := range []string{"main", "master"} {
		url := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s", repo, branch, filePath)
		req, _ := http.NewRequest("GET", url, nil)
		if githubToken != "" {
			req.Header.Set("Authorization", "token "+githubToken)
		}

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			continue
		}
		defer resp.Body.Close()

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("error reading response body: %v", err)
		}
		content = string(bodyBytes)
		break
	}

	if content == "" {
		return "", fmt.Errorf("failed to fetch file content from both main and master branches")
	}

	time.Sleep(time.Second) 
	return content, nil
}

func determineEcosystem(fileName string) string {
	switch fileName {
	case "package.json":
		return "npm"
	case "requirements.txt", "Pipfile", "pyproject.toml":
		return "PyPI"
	case "go.mod":
		return "Go"
	case "go.sum":
		return "Go"
	case "Cargo.toml", "Cargo.lock":
		return "crates.io"
	case "pom.xml":
		return "Maven"
	case "build.gradle":
		return "Gradle"
	default:
		return "unknown"
	}
}

func extractPackages(fileName, content string) map[string]string {
	packages := make(map[string]string)

	switch fileName {
	case "package.json":
		var pkgData map[string]interface{}
		if json.Unmarshal([]byte(content), &pkgData) == nil {
			if deps, ok := pkgData["dependencies"].(map[string]interface{}); ok {
				for pkgName, ver := range deps {
					packages[pkgName] = normalizeVersion(ver.(string))
				}
			}
		}
	case "requirements.txt":
		re := regexp.MustCompile(`(\S+)==(\S+)`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			packages[match[1]] = match[2]
		}
	case "Pipfile":
		re := regexp.MustCompile(`\[\[source\]]|([a-zA-Z0-9-_]+)\s*=\s*"(.*)"`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) == 3 {
				packages[match[1]] = match[2]
			}
		}
	case "pyproject.toml":
		var pyprojectData struct {
			Tool struct {
				Poetry struct {
					Dependencies map[string]string `toml:"dependencies"`
				} `toml:"poetry"`
			} `toml:"tool"`
		}

		if _, err := toml.Decode(content, &pyprojectData); err == nil {
			for pkgName, ver := range pyprojectData.Tool.Poetry.Dependencies {
				packages[pkgName] = normalizeVersion(ver)
			}
		}
	case "pom.xml":
		re := regexp.MustCompile(`<dependency>\s*<groupId>(.*?)</groupId>\s*<artifactId>(.*?)</artifactId>\s*<version>(.*?)</version>`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) == 4 {
				packages[fmt.Sprintf("%s:%s", match[1], match[2])] = match[3]
			}
		}
	case "build.gradle":
		re := regexp.MustCompile(`implementation\s+"(.*?)":"(.*?)"`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) == 3 {
				packages[match[1]] = match[2]
			}
		}
	case "go.mod":
		re := regexp.MustCompile(`require\s*\(\n?((?:\s*[^\s]+\s+[^\s]+\n?)+)\)`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			lines := strings.Split(match[1], "\n")
			for _, line := range lines {
				parts := strings.Fields(line)
				if len(parts) == 2 {
					packages[parts[0]] = parts[1]
				}
			}
		}
	case "go.sum":
		re := regexp.MustCompile(`(\S+)\s+(\S+)\s+(\S+)`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) == 4 {
				packages[match[1]] = match[2]
			}
		}
	case "Cargo.toml", "Cargo.lock":
		re := regexp.MustCompile(`name\s*=\s*"(.*?)"\nversion\s*=\s*"(.*?)"`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) == 3 {
				packages[match[1]] = match[2]
			}
		}
	}

	return packages
}

func normalizeVersion(version string) string {
	version = strings.TrimSpace(version)
	version = strings.Trim(version, "^~<>=")
	return version
}

func checkVulnerabilities(pkgName, version, ecosystem string) error {
	url := "https://api.osv.dev/v1/query"
	reqBody := map[string]interface{}{
		"package": map[string]string{
			"name":      pkgName,
			"ecosystem": ecosystem,
		},
		"version": version,
	}

	reqBytes, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(reqBytes))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OSV query failed: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var osvResp OSVResponse
	err = json.Unmarshal(body, &osvResp)
	if err != nil {
		return err
	}

	if len(osvResp.Results) > 0 && len(osvResp.Results[0].Vulnerabilities) > 0 {
		for _, vuln := range osvResp.Results[0].Vulnerabilities {
			fmt.Printf("Vulnerability found: %s (Severity: %s)\n", vuln.ID, vuln.Severity)
		}
	} else {
		fmt.Printf("No vulnerabilities found for package %s (%s) (Version: %s).\n", pkgName, ecosystem, version) 
	}

	time.Sleep(time.Second) 
	return nil
}

func contains(list []string, element string) bool {
	for _, item := range list {
		if item == element {
			return true
		}
	}
	return false
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the GitHub repository (owner/repo): ")
	repo, _ := reader.ReadString('\n')

	
	repo = strings.TrimSpace(repo)

	err := processRepo(repo)
	if err != nil {
		fmt.Printf("Error processing repo: %v\n", err)
	} else {
		fmt.Println("Repository processing complete.")
	}
}
