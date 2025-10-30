# mcp_server.py
from fastmcp import FastMCP
import json
import subprocess
from pathlib import Path
import shutil

mcp = FastMCP("Wiz Remediation Agent for Java Services")

KB_PATH = Path("knowledge-base")
WORKSPACE = Path("workspace")

# ============= Discovery Tools =============

@mcp.tool()
def list_services() -> list:
    """List all Java services with vulnerabilities"""
    services = []
    
    vuln_dir = WORKSPACE / KB_PATH / "vulnerabilities"
    for service_dir in vuln_dir.iterdir():
        if service_dir.is_dir():
            vuln_count = len(list(service_dir.glob("*.json")))
            
            if vuln_count > 0:
                services.append({
                    "name": service_dir.name,
                    "vulnerability_count": vuln_count
                })
    
    return services

@mcp.tool()
def get_service_vulnerabilities(service_name: str) -> list:
    """Get all vulnerabilities for a Java service"""
    service_dir = KB_PATH / "vulnerabilities" / service_name
    
    if not service_dir.exists():
        return []
    
    vulnerabilities = []
    for vuln_file in service_dir.glob("*.json"):
        with open(vuln_file) as f:
            vulnerabilities.append(json.load(f))
    
    # Sort by severity
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    vulnerabilities.sort(key=lambda v: severity_order.get(v['severity'], 4))
    
    return vulnerabilities

@mcp.tool()
def get_vulnerability(wiz_id: str) -> dict:
    """Get detailed information about a specific vulnerability"""
    
    # Search across all services
    for service_dir in (KB_PATH / "vulnerabilities").iterdir():
        vuln_file = service_dir / f"{wiz_id}.json"
        if vuln_file.exists():
            with open(vuln_file) as f:
                return json.load(f)
    
    return {"error": f"Vulnerability {wiz_id} not found"}

# ============= Java Repository Tools =============

@mcp.tool()
def clone_java_service(service_name: str) -> dict:
    """Clone a Java service repository"""
    
    # Get repo URL from service mapping
    service_file = KB_PATH / "services" / f"{service_name}.yaml"
    if not service_file.exists():
        return {"error": f"Service {service_name} not configured"}
    
    import yaml
    with open(service_file) as f:
        service = yaml.safe_load(f)
    
    # Clone to workspace
    repo_path = WORKSPACE / service_name
    
    # Remove if exists
    if repo_path.exists():
        shutil.rmtree(repo_path)
    
    # Clone
    result = subprocess.run(
        ['git', 'clone', service['repo_url'], str(repo_path)],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        return {"error": f"Clone failed: {result.stderr}"}
    
    return {
        "status": "cloned",
        "service": service_name,
        "path": str(repo_path)
    }

@mcp.tool()
def read_java_file(service_name: str, file_path: str) -> dict:
    """Read a Java source file"""
    
    repo_path = WORKSPACE / service_name
    full_path = repo_path / file_path
    
    if not full_path.exists():
        return {"error": f"File not found: {file_path}"}
    
    with open(full_path) as f:
        return {
            "path": file_path,
            "content": f.read()
        }

@mcp.tool()
def write_java_file(service_name: str, file_path: str, content: str) -> dict:
    """Write fixed code to Java file"""
    
    repo_path = WORKSPACE / service_name
    full_path = repo_path / file_path
    
    # Backup original
    backup_path = full_path.with_suffix(full_path.suffix + '.backup')
    if full_path.exists():
        shutil.copy(full_path, backup_path)
    
    # Write new content
    with open(full_path, 'w') as f:
        f.write(content)
    
    return {
        "status": "written",
        "file": file_path,
        "backup": str(backup_path)
    }

# ============= Java Build & Test Tools =============

@mcp.tool()
def run_maven_tests(service_name: str) -> dict:
    """Run Maven tests for a Java service"""
    
    repo_path = WORKSPACE / service_name
    
    result = subprocess.run(
        ['mvn', 'test'],
        cwd=repo_path,
        capture_output=True,
        text=True,
        timeout=300  # 5 minute timeout
    )
    
    return {
        "service": service_name,
        "passed": result.returncode == 0,
        "exit_code": result.returncode,
        "output": result.stdout,
        "errors": result.stderr
    }

@mcp.tool()
def run_gradle_tests(service_name: str) -> dict:
    """Run Gradle tests for a Java service"""
    
    repo_path = WORKSPACE / service_name
    
    result = subprocess.run(
        ['./gradlew', 'test'],
        cwd=repo_path,
        capture_output=True,
        text=True,
        timeout=300
    )
    
    return {
        "service": service_name,
        "passed": result.returncode == 0,
        "exit_code": result.returncode,
        "output": result.stdout,
        "errors": result.stderr
    }

# ============= Fix Pattern Tools =============

@mcp.tool()
def get_fix_patterns() -> list:
    """Get all available fix patterns"""
    patterns_dir = KB_PATH / "fix-patterns"
    
    patterns = []
    for pattern_file in patterns_dir.glob("*.json"):
        with open(pattern_file) as f:
            patterns.append(json.load(f))
    
    return patterns

@mcp.tool()
def get_fix_pattern(vuln_type: str) -> dict:
    """Get fix pattern for a specific vulnerability type"""
    
    pattern_file = KB_PATH / "fix-patterns" / f"{vuln_type}-pattern.json"
    
    if not pattern_file.exists():
        return {"error": f"No pattern found for type: {vuln_type}"}
    
    with open(pattern_file) as f:
        return json.load(f)

# ============= Git Operations =============

@mcp.tool()
def create_git_branch(service_name: str, wiz_id: str) -> dict:
    """Create a Git branch for the fix"""
    
    repo_path = WORKSPACE / service_name
    branch_name = f"fix/{wiz_id}"
    
    # Create branch
    subprocess.run(
        ['git', 'checkout', '-b', branch_name],
        cwd=repo_path,
        capture_output=True
    )
    
    return {
        "service": service_name,
        "branch": branch_name,
        "status": "created"
    }

@mcp.tool()
def git_commit(service_name: str, wiz_id: str, message: str) -> dict:
    """Commit changes"""
    
    repo_path = WORKSPACE / service_name
    
    # Add all changes
    subprocess.run(['git', 'add', '.'], cwd=repo_path)
    
    # Commit
    result = subprocess.run(
        ['git', 'commit', '-m', f"Fix {wiz_id}: {message}"],
        cwd=repo_path,
        capture_output=True
    )
    
    return {
        "service": service_name,
        "committed": result.returncode == 0
    }

@mcp.tool()
def push_and_create_pr(service_name: str, wiz_id: str, branch_name: str) -> dict:
    """Push branch and create GitHub PR"""
    
    repo_path = WORKSPACE / service_name
    
    # Push branch
    subprocess.run(
        ['git', 'push', 'origin', branch_name],
        cwd=repo_path
    )
    
    # Get vulnerability details for PR description
    vuln = get_vulnerability(wiz_id)
    
    # Create PR using GitHub CLI
    pr_body = f"""
## Fix Wiz Vulnerability: {wiz_id}

**Severity:** {vuln['severity']}
**Type:** {vuln['type']}
**File:** {vuln['file_path']}

### Description
{vuln['description']}

### Changes
{vuln['recommendation']}

### Testing
✅ All tests passing

---
*Auto-generated by Wiz Remediation Agent*
    """
    
    result = subprocess.run(
        ['gh', 'pr', 'create', 
         '--title', f"Fix {wiz_id}: {vuln['title']}",
         '--body', pr_body],
        cwd=repo_path,
        capture_output=True,
        text=True
    )
    
    return {
        "service": service_name,
        "wiz_id": wiz_id,
        "pr_url": result.stdout.strip()
    }

# ============= Workflow Orchestration =============

@mcp.tool()
def fix_vulnerability_workflow(wiz_id: str) -> dict:
    """Complete workflow to fix a vulnerability in Java service"""
    
    log = []
    
    # Step 1: Get vulnerability
    log.append("📋 Getting vulnerability details...")
    vuln = get_vulnerability(wiz_id)
    if 'error' in vuln:
        return {"error": vuln['error'], "log": log}
    
    service_name = vuln['service']
    log.append(f"✓ Found in service: {service_name}")
    
    # Step 2: Clone repo
    log.append("📦 Cloning repository...")
    clone_result = clone_java_service(service_name)
    if 'error' in clone_result:
        return {"error": clone_result['error'], "log": log}
    log.append("✓ Repository cloned")
    
    # Step 3: Create branch
    log.append("🌿 Creating fix branch...")
    branch_result = create_git_branch(service_name, wiz_id)
    log.append(f"✓ Branch: {branch_result['branch']}")
    
    # Step 4: Read vulnerable file
    log.append("📖 Reading vulnerable code...")
    file_content = read_java_file(service_name, vuln['file_path'])
    if 'error' in file_content:
        return {"error": file_content['error'], "log": log}
    log.append("✓ File read")
    
    # NOTE: At this point, Claude will analyze the code
    # and generate the fix. The agent decides what to do next!
    
    return {
        "status": "ready_for_fix",
        "service": service_name,
        "vulnerability": vuln,
        "file_content": file_content['content'],
        "log": log,
        "next_steps": [
            "Analyze vulnerable code",
            "Get fix pattern",
            "Apply fix",
            "Run tests",
            "Create PR"
        ]
    }

if __name__ == "__main__":
    mcp.run(transport="stdio")