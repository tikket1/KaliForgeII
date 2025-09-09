#!/usr/bin/env bash
# GitHub Release Manager - Enhanced tool for downloading GitHub releases
# Used by SecureForge (enhanced kali_bootstrapper.sh)

set -Eeuo pipefail

# -------------------- GitHub Release Functions --------------------

download_github_release() {
    local repo="$1"           # Format: "owner/repo"
    local pattern="$2"        # Regex pattern to match asset name
    local dest_dir="$3"       # Destination directory
    local filename="${4:-}"   # Optional: custom filename
    local github_token="${GITHUB_TOKEN:-}"
    
    echo "[+] Downloading latest release from $repo matching '$pattern'"
    
    # Build API URL and headers
    local api_url="https://api.github.com/repos/$repo/releases/latest"
    local curl_headers=()
    
    if [[ -n "$github_token" ]]; then
        curl_headers+=("-H" "Authorization: Bearer $github_token")
    fi
    
    # Get release info
    local release_data
    if ! release_data=$(curl -s "${curl_headers[@]}" "$api_url"); then
        echo "[!] Failed to fetch release data for $repo" >&2
        return 1
    fi
    
    # Extract download URL
    local download_url
    download_url=$(echo "$release_data" | jq -r --arg pattern "$pattern" '
        .assets[] | 
        select(.name | test($pattern; "i")) | 
        .browser_download_url' | head -n1)
    
    if [[ -z "$download_url" || "$download_url" == "null" ]]; then
        echo "[!] No matching asset found for pattern '$pattern' in $repo" >&2
        return 1
    fi
    
    # Determine filename
    local asset_name
    asset_name=$(basename "$download_url")
    local final_filename="${filename:-$asset_name}"
    local full_path="$dest_dir/$final_filename"
    
    # Create destination directory
    mkdir -p "$dest_dir"
    
    # Download file
    echo "[+] Downloading $asset_name -> $full_path"
    if curl -L -o "$full_path" "$download_url"; then
        # Handle compressed files
        if [[ "$asset_name" =~ \.(gz|zip)$ ]]; then
            echo "[+] Extracting $asset_name"
            case "$asset_name" in
                *.tar.gz|*.tgz)
                    tar -xzf "$full_path" -C "$dest_dir"
                    rm "$full_path"
                    ;;
                *.gz)
                    gunzip "$full_path"
                    # Remove .gz extension from filename
                    local extracted_name="${final_filename%.gz}"
                    if [[ "$extracted_name" != "$final_filename" ]]; then
                        mv "$dest_dir/${final_filename%.gz}" "$dest_dir/$extracted_name" 2>/dev/null || true
                    fi
                    ;;
                *.zip)
                    unzip -q "$full_path" -d "$dest_dir"
                    rm "$full_path"
                    ;;
            esac
        fi
        
        # Make executable if it's a binary
        if [[ -f "$dest_dir/$final_filename" ]] && file "$dest_dir/$final_filename" | grep -q "executable"; then
            chmod +x "$dest_dir/$final_filename"
        fi
        
        echo "[✓] Successfully downloaded and installed: $final_filename"
        return 0
    else
        echo "[!] Failed to download $download_url" >&2
        return 1
    fi
}

install_github_tools() {
    local tools_dir="$1"
    local category="$2"
    
    echo "[+] Installing GitHub tools for category: $category"
    
    case "$category" in
        "pivoting")
            # Chisel - Fast TCP/UDP tunnel
            download_github_release "jpillora/chisel" "linux_amd64\.gz$" "$tools_dir/Pivoting/Linux" "chisel_x64"
            download_github_release "jpillora/chisel" "linux_386\.gz$" "$tools_dir/Pivoting/Linux" "chisel_x86"
            download_github_release "jpillora/chisel" "windows_amd64\.gz$" "$tools_dir/Pivoting/Windows" "chisel_x64.exe"
            download_github_release "jpillora/chisel" "windows_386\.gz$" "$tools_dir/Pivoting/Windows" "chisel_x86.exe"
            ;;
        "privesc")
            # LinPEAS & WinPEAS
            download_github_release "carlospolop/PEASS-ng" "linpeas\.sh$" "$tools_dir/PrivEsc/Linux" "linpeas.sh"
            download_github_release "carlospolop/PEASS-ng" "winPEASx64\.exe$" "$tools_dir/PrivEsc/Windows" "winPEASx64.exe"
            download_github_release "carlospolop/PEASS-ng" "winPEASx86\.exe$" "$tools_dir/PrivEsc/Windows" "winPEASx86.exe"
            
            # pspy - Process monitoring for Linux
            download_github_release "DominicBreuker/pspy" "pspy64$" "$tools_dir/PrivEsc/Linux" "pspy64"
            download_github_release "DominicBreuker/pspy" "pspy32$" "$tools_dir/PrivEsc/Linux" "pspy32"
            
            # Windows privilege escalation tools
            download_github_release "itm4n/PrintSpoofer" "PrintSpoofer64\.exe$" "$tools_dir/PrivEsc/Windows/PrintSpoofer" "PrintSpoofer64.exe"
            download_github_release "itm4n/PrintSpoofer" "PrintSpoofer32\.exe$" "$tools_dir/PrivEsc/Windows/PrintSpoofer" "PrintSpoofer32.exe"
            download_github_release "BeichenDream/GodPotato" "GodPotato-NET4\.exe$" "$tools_dir/PrivEsc/Windows/GodPotato" "GodPotato-NET4.exe"
            ;;
        "recon")
            # GitHub reconnaissance tools
            git clone --depth 1 "https://github.com/techgaun/github-dorks" "$tools_dir/Recon/github-dorks" 2>/dev/null || true
            ;;
        "ad")
            # Active Directory tools
            download_github_release "BloodHoundAD/SharpHound" "SharpHound.*\.exe$" "$tools_dir/ActiveDirectory/SharpHound"
            download_github_release "BloodHoundAD/BloodHound" "BloodHound-linux-x64.*\.zip$" "$tools_dir/ActiveDirectory"
            
            # Clone AD-related repositories
            git clone --depth 1 "https://github.com/dirkjanm/PKINITtools" "$tools_dir/ActiveDirectory/PKINITtools" 2>/dev/null || true
            git clone --depth 1 "https://github.com/Greenwolf/ntlm_theft" "$tools_dir/ActiveDirectory/ntlm_theft" 2>/dev/null || true
            ;;
        "shells")
            # Shell and payload tools
            git clone --depth 1 "https://github.com/brightio/penelope" "$tools_dir/Shells/penelope" 2>/dev/null || true
            git clone --depth 1 "https://github.com/samratashok/nishang" "$tools_dir/Shells/nishang" 2>/dev/null || true
            git clone --depth 1 "https://github.com/t3l3machus/hoaxshell" "$tools_dir/Shells/hoaxshell" 2>/dev/null || true
            ;;
        "c2")
            # Command & Control frameworks
            echo "[+] Installing Sliver C2 framework..."
            
            # Sliver C2 - Modern cross-platform implant framework
            download_github_release "BishopFox/sliver" "sliver-server_linux$" "$tools_dir/C2/Sliver" "sliver-server"
            download_github_release "BishopFox/sliver" "sliver-client_linux$" "$tools_dir/C2/Sliver" "sliver-client"
            
            # Windows versions for cross-platform operations
            download_github_release "BishopFox/sliver" "sliver-server_windows\.exe$" "$tools_dir/C2/Sliver" "sliver-server.exe"
            download_github_release "BishopFox/sliver" "sliver-client_windows\.exe$" "$tools_dir/C2/Sliver" "sliver-client.exe"
            
            # Create Sliver configuration directory
            mkdir -p "$tools_dir/C2/Sliver/configs"
            
            # Download additional Sliver tools if available
            download_github_release "BishopFox/sliver" "sliver-armored_linux$" "$tools_dir/C2/Sliver" "sliver-armored" || true
            
            echo "[✓] Sliver C2 framework installation complete"
            ;;
    esac
    
    echo "[✓] GitHub tools installation complete for: $category"
}

# -------------------- Usage Example --------------------
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Example usage
    TOOLS_DIR="/home/${USER}/PentestTools"
    
    echo "GitHub Release Manager - Test Run"
    echo "Tools directory: $TOOLS_DIR"
    
    # Create basic directory structure
    mkdir -p "$TOOLS_DIR"/{Pivoting/{Linux,Windows},PrivEsc/{Linux,Windows},ActiveDirectory,Recon,Shells}
    
    # Test download
    echo "[+] Testing GitHub release download..."
    # download_github_release "jpillora/chisel" "linux_amd64\.gz$" "$TOOLS_DIR/test" "chisel_test"
    
    echo "[+] Use this script by sourcing it and calling the functions"
    echo "Example: install_github_tools '$TOOLS_DIR' 'pivoting'"
fi