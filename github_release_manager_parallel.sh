#!/usr/bin/env bash
# GitHub Release Manager - PARALLEL VERSION
# Dramatically improved performance with concurrent downloads and progress tracking

set -Eeuo pipefail

# -------------------- Configuration --------------------
MAX_PARALLEL_DOWNLOADS=${MAX_PARALLEL_DOWNLOADS:-4}
DOWNLOAD_TIMEOUT=${DOWNLOAD_TIMEOUT:-300}  # 5 minutes per download
RETRY_ATTEMPTS=${RETRY_ATTEMPTS:-3}
PROGRESS_FILE="/tmp/kaliforge2_download_progress.json"

# Initialize progress tracking
init_progress_tracking() {
    echo "{\"downloads\": {}, \"summary\": {\"total\": 0, \"completed\": 0, \"failed\": 0, \"in_progress\": 0}}" > "$PROGRESS_FILE"
}

# Update progress for a specific download
update_download_progress() {
    local download_id="$1"
    local status="$2"      # starting, downloading, completed, failed
    local progress="$3"    # 0-100 for downloading, or size info
    local message="$4"     # Optional message
    
    # Use Python for JSON manipulation (more reliable than jq)
    python3 -c "
import json
import sys

try:
    with open('$PROGRESS_FILE', 'r') as f:
        data = json.load(f)
    
    data['downloads']['$download_id'] = {
        'status': '$status',
        'progress': '$progress',
        'message': '$message',
        'timestamp': '$(date -Iseconds)'
    }
    
    # Update summary
    downloads = data['downloads']
    data['summary'] = {
        'total': len(downloads),
        'completed': len([d for d in downloads.values() if d['status'] == 'completed']),
        'failed': len([d for d in downloads.values() if d['status'] == 'failed']),
        'in_progress': len([d for d in downloads.values() if d['status'] in ['starting', 'downloading']])
    }
    
    with open('$PROGRESS_FILE', 'w') as f:
        json.dump(data, f, indent=2)
        
except Exception as e:
    print(f'Progress update failed: {e}', file=sys.stderr)
"
}

# Enhanced download function with progress tracking and retries
download_github_release_enhanced() {
    local repo="$1"
    local pattern="$2"
    local dest_dir="$3"
    local filename="${4:-}"
    local download_id="${5:-${repo//\//_}_${pattern}}"
    local github_token="${GITHUB_TOKEN:-}"
    
    echo "[+] Starting enhanced download: $repo ($download_id)"
    update_download_progress "$download_id" "starting" "0" "Initializing download for $repo"
    
    # Build API URL and headers
    local api_url="https://api.github.com/repos/$repo/releases/latest"
    local curl_headers=()
    
    if [[ -n "$github_token" ]]; then
        curl_headers+=("-H" "Authorization: Bearer $github_token")
    fi
    
    local attempt=1
    while [[ $attempt -le $RETRY_ATTEMPTS ]]; do
        echo "[+] Attempt $attempt/$RETRY_ATTEMPTS for $repo"
        
        # Get release info with timeout
        local release_data
        update_download_progress "$download_id" "downloading" "10" "Fetching release info (attempt $attempt)"
        
        if ! release_data=$(timeout 30 curl -s "${curl_headers[@]}" "$api_url" 2>/dev/null); then
            echo "[!] Failed to fetch release data for $repo (attempt $attempt)" >&2
            if [[ $attempt -eq $RETRY_ATTEMPTS ]]; then
                update_download_progress "$download_id" "failed" "0" "Failed to fetch release info after $RETRY_ATTEMPTS attempts"
                return 1
            fi
            ((attempt++))
            sleep $((attempt * 2))  # Exponential backoff
            continue
        fi
        
        # Extract download URL
        local download_url
        update_download_progress "$download_id" "downloading" "20" "Parsing release data"
        
        download_url=$(echo "$release_data" | python3 -c "
import json, sys, re
try:
    data = json.load(sys.stdin)
    pattern = '$pattern'
    for asset in data.get('assets', []):
        if re.search(pattern, asset['name'], re.IGNORECASE):
            print(asset['browser_download_url'])
            sys.exit(0)
    sys.exit(1)
except:
    sys.exit(1)
" 2>/dev/null)
        
        if [[ -z "$download_url" || "$download_url" == "null" ]]; then
            echo "[!] No matching asset found for pattern '$pattern' in $repo" >&2
            update_download_progress "$download_id" "failed" "0" "No matching asset found for pattern: $pattern"
            return 1
        fi
        
        # Determine filename
        local asset_name
        asset_name=$(basename "$download_url")
        local final_filename="${filename:-$asset_name}"
        local full_path="$dest_dir/$final_filename"
        
        # Create destination directory
        mkdir -p "$dest_dir"
        
        # Download with progress tracking
        echo "[+] Downloading $asset_name -> $full_path (attempt $attempt)"
        update_download_progress "$download_id" "downloading" "30" "Downloading $asset_name"
        
        # Use curl with progress bar and timeout
        if timeout "$DOWNLOAD_TIMEOUT" curl -L \
            --progress-bar \
            --retry 2 \
            --retry-delay 2 \
            --connect-timeout 30 \
            --max-time "$DOWNLOAD_TIMEOUT" \
            -o "$full_path" \
            "$download_url" 2>/dev/null; then
            
            update_download_progress "$download_id" "downloading" "80" "Processing downloaded file"
            
            # Handle compressed files
            if [[ "$asset_name" =~ \.(gz|zip|tar\.gz|tgz)$ ]]; then
                echo "[+] Extracting $asset_name"
                update_download_progress "$download_id" "downloading" "90" "Extracting $asset_name"
                
                case "$asset_name" in
                    *.tar.gz|*.tgz)
                        if tar -xzf "$full_path" -C "$dest_dir" 2>/dev/null; then
                            rm "$full_path"
                        else
                            echo "[!] Warning: Failed to extract $asset_name" >&2
                        fi
                        ;;
                    *.gz)
                        if gunzip "$full_path" 2>/dev/null; then
                            local extracted_name="${final_filename%.gz}"
                            if [[ "$extracted_name" != "$final_filename" && -f "$dest_dir/${final_filename%.gz}" ]]; then
                                mv "$dest_dir/${final_filename%.gz}" "$dest_dir/$extracted_name" 2>/dev/null || true
                            fi
                        else
                            echo "[!] Warning: Failed to extract $asset_name" >&2
                        fi
                        ;;
                    *.zip)
                        if command -v unzip >/dev/null && unzip -q "$full_path" -d "$dest_dir" 2>/dev/null; then
                            rm "$full_path"
                        else
                            echo "[!] Warning: Failed to extract $asset_name (unzip not available or failed)" >&2
                        fi
                        ;;
                esac
            fi
            
            # Make executable if it's a binary
            local final_file="$dest_dir/$final_filename"
            if [[ "$asset_name" =~ \.gz$ ]]; then
                final_file="$dest_dir/${final_filename%.gz}"
            fi
            
            if [[ -f "$final_file" ]] && file "$final_file" 2>/dev/null | grep -q "executable"; then
                chmod +x "$final_file"
            fi
            
            update_download_progress "$download_id" "completed" "100" "Successfully downloaded and installed: $final_filename"
            echo "[✓] Successfully downloaded and installed: $final_filename"
            return 0
            
        else
            echo "[!] Failed to download $download_url (attempt $attempt)" >&2
            if [[ $attempt -eq $RETRY_ATTEMPTS ]]; then
                update_download_progress "$download_id" "failed" "0" "Download failed after $RETRY_ATTEMPTS attempts"
                return 1
            fi
            ((attempt++))
            sleep $((attempt * 2))  # Exponential backoff
        fi
    done
    
    return 1
}

# Parallel download orchestrator
download_tools_parallel() {
    local category="$1"
    local tools_dir="$2"
    
    echo "[+] Starting parallel downloads for category: $category"
    init_progress_tracking
    
    # Define download jobs based on category
    local -a download_jobs=()
    
    case "$category" in
        "pivoting")
            download_jobs=(
                "jpillora/chisel|linux_amd64\.gz$|$tools_dir/Pivoting/Linux|chisel_x64|chisel_linux_x64"
                "jpillora/chisel|linux_386\.gz$|$tools_dir/Pivoting/Linux|chisel_x86|chisel_linux_x86"
                "jpillora/chisel|windows_amd64\.gz$|$tools_dir/Pivoting/Windows|chisel_x64.exe|chisel_windows_x64"
                "jpillora/chisel|windows_386\.gz$|$tools_dir/Pivoting/Windows|chisel_x86.exe|chisel_windows_x86"
            )
            ;;
        "privesc")
            download_jobs=(
                "carlospolop/PEASS-ng|linpeas\.sh$|$tools_dir/PrivEsc/Linux|linpeas.sh|linpeas"
                "carlospolop/PEASS-ng|winPEASx64\.exe$|$tools_dir/PrivEsc/Windows|winPEASx64.exe|winpeas_x64"
                "carlospolop/PEASS-ng|winPEASx86\.exe$|$tools_dir/PrivEsc/Windows|winPEASx86.exe|winpeas_x86"
                "DominicBreuker/pspy|pspy64$|$tools_dir/PrivEsc/Linux|pspy64|pspy64"
                "DominicBreuker/pspy|pspy32$|$tools_dir/PrivEsc/Linux|pspy32|pspy32"
                "itm4n/PrintSpoofer|PrintSpoofer64\.exe$|$tools_dir/PrivEsc/Windows/PrintSpoofer|PrintSpoofer64.exe|printspoofer64"
                "itm4n/PrintSpoofer|PrintSpoofer32\.exe$|$tools_dir/PrivEsc/Windows/PrintSpoofer|PrintSpoofer32.exe|printspoofer32"
                "BeichenDream/GodPotato|GodPotato-NET4\.exe$|$tools_dir/PrivEsc/Windows/GodPotato|GodPotato-NET4.exe|godpotato"
            )
            ;;
        "ad")
            download_jobs=(
                "BloodHoundAD/SharpHound|SharpHound.*\.exe$|$tools_dir/ActiveDirectory/SharpHound|SharpHound.exe|sharphound"
                "BloodHoundAD/BloodHound|BloodHound-linux-x64.*\.zip$|$tools_dir/ActiveDirectory|BloodHound.zip|bloodhound"
            )
            ;;
        "c2")
            download_jobs=(
                "BishopFox/sliver|sliver-server_linux$|$tools_dir/C2/Sliver|sliver-server|sliver_server_linux"
                "BishopFox/sliver|sliver-client_linux$|$tools_dir/C2/Sliver|sliver-client|sliver_client_linux"
                "BishopFox/sliver|sliver-server_windows\.exe$|$tools_dir/C2/Sliver|sliver-server.exe|sliver_server_windows"
                "BishopFox/sliver|sliver-client_windows\.exe$|$tools_dir/C2/Sliver|sliver-client.exe|sliver_client_windows"
            )
            ;;
    esac
    
    if [[ ${#download_jobs[@]} -eq 0 ]]; then
        echo "[!] No download jobs defined for category: $category"
        return 0
    fi
    
    echo "[+] Queuing ${#download_jobs[@]} downloads for parallel execution"
    
    # Create temporary script directory
    local temp_dir="/tmp/kaliforge2_parallel_$$"
    mkdir -p "$temp_dir"
    
    # Create individual download scripts
    local -a pids=()
    local job_count=0
    
    for job in "${download_jobs[@]}"; do
        IFS='|' read -r repo pattern dest_dir filename download_id <<< "$job"
        
        # Create individual download script
        local script_file="$temp_dir/download_${job_count}.sh"
        cat > "$script_file" << EOF
#!/bin/bash
set -euo pipefail

# Source the main functions
source "\$(dirname "\$0")/../github_release_manager_parallel.sh"

# Execute the download
download_github_release_enhanced "$repo" "$pattern" "$dest_dir" "$filename" "$download_id"
exit_code=\$?

# Log completion
if [[ \$exit_code -eq 0 ]]; then
    echo "[✓] Completed: $download_id"
else
    echo "[✗] Failed: $download_id"
fi

exit \$exit_code
EOF
        chmod +x "$script_file"
        
        # Start background download (with process limit)
        if [[ ${#pids[@]} -ge $MAX_PARALLEL_DOWNLOADS ]]; then
            # Wait for one process to complete
            wait "${pids[0]}" 2>/dev/null || true
            pids=("${pids[@]:1}")  # Remove first element
        fi
        
        # Start new download
        echo "[+] Starting download $((job_count + 1))/${#download_jobs[@]}: $download_id"
        "$script_file" &
        pids+=($!)
        
        ((job_count++))
        sleep 0.2  # Small delay to prevent overwhelming the system
    done
    
    # Wait for all remaining downloads to complete
    echo "[+] Waiting for ${#pids[@]} remaining downloads to complete..."
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || echo "[!] Download process $pid failed or was killed"
    done
    
    # Clean up
    rm -rf "$temp_dir"
    
    # Final progress summary
    local summary
    if [[ -f "$PROGRESS_FILE" ]]; then
        summary=$(python3 -c "
import json
try:
    with open('$PROGRESS_FILE', 'r') as f:
        data = json.load(f)
    s = data['summary']
    print(f\"Downloads completed: {s['completed']}/{s['total']} (Failed: {s['failed']})\")
except:
    print('Summary unavailable')
")
        echo "[+] $summary"
    fi
    
    echo "[✓] Parallel download orchestration complete for category: $category"
}

# Git repository cloning with parallel support  
clone_repositories_parallel() {
    local category="$1"
    local tools_dir="$2"
    
    local -a clone_jobs=()
    
    case "$category" in
        "recon")
            clone_jobs=(
                "https://github.com/techgaun/github-dorks|$tools_dir/Recon/github-dorks"
            )
            ;;
        "ad")
            clone_jobs=(
                "https://github.com/dirkjanm/PKINITtools|$tools_dir/ActiveDirectory/PKINITtools"
                "https://github.com/Greenwolf/ntlm_theft|$tools_dir/ActiveDirectory/ntlm_theft"
            )
            ;;
        "shells")
            clone_jobs=(
                "https://github.com/brightio/penelope|$tools_dir/Shells/penelope"
                "https://github.com/samratashok/nishang|$tools_dir/Shells/nishang"
                "https://github.com/t3l3machus/hoaxshell|$tools_dir/Shells/hoaxshell"
            )
            ;;
    esac
    
    if [[ ${#clone_jobs[@]} -eq 0 ]]; then
        return 0
    fi
    
    echo "[+] Cloning ${#clone_jobs[@]} repositories in parallel"
    local -a pids=()
    
    for job in "${clone_jobs[@]}"; do
        IFS='|' read -r repo_url dest_path <<< "$job"
        
        # Start background clone (limit concurrent clones)
        if [[ ${#pids[@]} -ge 3 ]]; then  # Max 3 concurrent clones
            wait "${pids[0]}" 2>/dev/null || true
            pids=("${pids[@]:1}")
        fi
        
        (
            echo "[+] Cloning $(basename "$repo_url") to $dest_path"
            git clone --depth 1 "$repo_url" "$dest_path" 2>/dev/null || {
                echo "[!] Failed to clone $repo_url" >&2
                exit 1
            }
            echo "[✓] Cloned $(basename "$repo_url")"
        ) &
        pids+=($!)
    done
    
    # Wait for all clones to complete
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    
    echo "[✓] Repository cloning complete"
}

# Enhanced main installation function with parallel processing
install_github_tools_parallel() {
    local tools_dir="$1"
    local category="$2"
    
    echo "[+] Installing GitHub tools for category: $category (PARALLEL MODE)"
    
    case "$category" in
        "pivoting"|"privesc"|"ad"|"c2")
            download_tools_parallel "$category" "$tools_dir"
            ;;
        "recon"|"shells")
            clone_repositories_parallel "$category" "$tools_dir"
            ;;
        *)
            echo "[!] Unknown category: $category"
            return 1
            ;;
    esac
    
    echo "[✓] GitHub tools installation complete for: $category"
}

# Progress monitoring function (can be called from other scripts)
get_download_progress() {
    if [[ -f "$PROGRESS_FILE" ]]; then
        cat "$PROGRESS_FILE"
    else
        echo "{\"error\": \"No progress data available\"}"
    fi
}

# Clean up progress file
cleanup_progress() {
    rm -f "$PROGRESS_FILE"
}

# -------------------- Usage Example --------------------
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "GitHub Release Manager - PARALLEL VERSION"
    echo "==========================================="
    
    if [[ $# -lt 2 ]]; then
        echo "Usage: $0 <tools_directory> <category>"
        echo "Categories: pivoting, privesc, ad, c2, recon, shells"
        exit 1
    fi
    
    TOOLS_DIR="$1"
    CATEGORY="$2"
    
    echo "Tools directory: $TOOLS_DIR"
    echo "Category: $CATEGORY"
    echo "Max parallel downloads: $MAX_PARALLEL_DOWNLOADS"
    echo
    
    # Create basic directory structure
    mkdir -p "$TOOLS_DIR"/{Pivoting/{Linux,Windows},PrivEsc/{Linux,Windows},ActiveDirectory,Recon,Shells,C2}
    
    # Run parallel installation
    time install_github_tools_parallel "$TOOLS_DIR" "$CATEGORY"
    
    echo
    echo "[+] Installation complete! Check progress with:"
    echo "    get_download_progress | jq"
fi