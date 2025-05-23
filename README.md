# **RepoVulnScan**
Analyze dependencies and Identify vulnerabilities using OSV APItest

---

### Description:

- The **RepoVulnScan** is a Go-based tool that scans a GitHub repository to identify vulnerable dependencies in popular package manager files. It fetches the contents of dependency files and analyzes the listed dependencies using the OSV (Open Source Vulnerabilities) API.
- The tool supports various ecosystems like `npm`, `PyPI`, `Go`, `Maven`, `Gradle`, `crates.io` and more.
- This tool is especially useful for developers and security professionals to assess the security posture of their software projects by quickly identifying potential vulnerabilities in their project's dependencies.

---

![repovuln](https://github.com/user-attachments/assets/35dd5683-62bd-4f70-b866-f9150f596965)

---

### **Features:**  
1. **Supports Multiple Dependency Files:**  
   - Handles dependency files such as `package.json`, `requirements.txt`, `go.mod`, `pyproject.toml`, and more.
2. **Automatic Ecosystem Detection:**  
   - Determines the ecosystem of a dependency file (e.g., `npm`, `PyPI`, `Go`, etc.).
3. **Vulnerability Detection:**
   - Queries the OSV API to fetch details about known vulnerabilities for specific package versions.
4. **Recursive Scanning:**  
   - Traverses directories in a repository to locate and analyze all relevant files.
5. **GitHub Integration:**  
   - Fetches repository files using the GitHub API, supporting both `main` and `master` branches.
6. **Human-Readable Outputs:**  
   - Displays the scanned results, highlighting packages with detected vulnerabilities.

---
## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/vettrivel007/RepoVulnScan.git
   ```
2. Navigate to the project directory:
   ```bash
   cd RepoVulnScan
   ```
3. Initialize the Go module (if not already initialized):

   If you haven't initialized the Go module yet, run:

   ```bash
   go mod init github.com/vettri007/RepoVulnScan
   ```
   
4. Install dependencies and tidy up the module:

   Run the following command to download and clean up any necessary dependencies:

   ```bash
   go mod tidy
   ```
   This will add any missing dependencies and remove any unused ones.
   
5. Build the tool:
   ```bash
   go build -o RepoVulnScan
   ```
---
### **Usage:**  
1. Set up the GitHub Token (optional but recommended for higher API rate limits):  
   ```bash
   export GITHUB_TOKEN=<your_github_token>
   ```
2. Build the Go program:  
   ```bash
   go build -o RepoVulnScan
   ```
3. Run the tool:  
   ```bash
   ./RepoVulnScan
   ```
4. Enter the repository name in the format `owner/repo` (e.g., `ossf/malicious-packages`).

---


## Supported Dependency Files
- `package.json` (npm)
- `requirements.txt` (PyPI)
- `Pipfile` (PyPI)
- `pyproject.toml` (PyPI)
- `go.mod` (Go)
- `go.sum` (Go)
- `pom.xml` (Maven)
- `build.gradle` (Gradle)
- `Cargo.toml` (crates.io)
- `Cargo.lock` (crates.io)
  
---

### **Requirements:**  
- Go version 1.16 or higher.  
- Stabe Internet connectivity to access the GitHub API and OSV API.

---

### **Limitations:**  
- Supports only public repositories or private repositories with a valid GitHub token.  
- Requires properly formatted dependency files to extract package information accurately.  


---

## API References
- **GitHub API**: Used to fetch repository files.
- **OSV API**: Used to check for vulnerabilities in packages.

---

## Disclaimer
```
This tool is provided "as is" and is not guaranteed to detect all vulnerabilities. While it helps identify potential security risks by scanning known package vulnerabilities, it may not catch every issue, especially new or unreported vulnerabilities.

Use this tool at your own discretion. The authors are not responsible for any damages or security issues arising from the use of this tool. Always supplement it with other security measures and manual reviews.
```
Let me know if you'd like further customization! or you'd like to contact me on Linkedln or Gmail

Here my Linkedln -> www.linkedin.com/in/vettrivel2006 

Here my Mail ID -> uvettrivel007@gmail.com 

---
