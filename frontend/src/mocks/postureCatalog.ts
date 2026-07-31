// Mock posture check catalogue — covers every category/check id required by
// docs/API_CONTRACT_V2_SECURITY.md Part A4, with plausible (not random)
// content so the UI has something real to render. Statuses are fixed per
// check (not re-randomized) so a rescan feels stable rather than flickering.

import type { CheckStatus, PostureCheck, Severity } from "../api/types";

interface CheckSpec {
  id: string;
  category: string;
  title: string;
  status: CheckStatus;
  severity: Severity;
  score_weight: number;
  observed: string;
  expected: string;
  why_it_matters: string;
  evidence: { label: string; value: string }[];
  remediation_summary: string;
  commands?: { shell: string; command: string; requires_admin: boolean; reversible: boolean; risk_note?: string }[];
  docs_url?: string;
  references?: string[];
}

const PS = "powershell";

export const CATEGORY_LABELS: Record<string, string> = {
  firewall: "Firewall",
  smb: "SMB",
  remote_access: "Remote access",
  name_resolution: "Name resolution",
  network_config: "Network configuration",
  wifi: "Wi-Fi",
  tls: "TLS",
  listening_services: "Listening services",
  updates_and_defense: "Updates & defense",
  accounts: "Accounts",
};

const SPECS: CheckSpec[] = [
  // --- firewall ---
  {
    id: "firewall_profiles_enabled", category: "firewall", title: "Windows Firewall is enabled on all profiles",
    status: "pass", severity: "high", score_weight: 9,
    observed: "Domain: On, Private: On, Public: On", expected: "All profiles On",
    why_it_matters: "A disabled profile leaves that network context with no host-based filtering at all.",
    evidence: [{ label: "Domain", value: "On" }, { label: "Private", value: "On" }, { label: "Public", value: "On" }],
    remediation_summary: "No action needed.",
  },
  {
    id: "firewall_inbound_default_block", category: "firewall", title: "Inbound default action is Block",
    status: "pass", severity: "high", score_weight: 8,
    observed: "DefaultInboundAction: Block on all profiles", expected: "Block",
    why_it_matters: "An Allow default would accept any inbound connection not explicitly blocked.",
    evidence: [{ label: "Public profile default", value: "Block" }],
    remediation_summary: "No action needed.",
  },
  {
    id: "firewall_allow_rules_broad", category: "firewall", title: "Broad inbound allow rules present",
    status: "warn", severity: "medium", score_weight: 6,
    observed: "2 enabled inbound Allow rules with RemoteAddress = Any and no program restriction", expected: "Inbound allow rules scoped to specific programs, ports, or address ranges",
    why_it_matters: "A rule that allows any remote address to any local port on a matched program is nearly as permissive as no firewall at all for that program.",
    evidence: [{ label: "Rule", value: "\"Node.js Server\" — Any → 3000/tcp" }, { label: "Rule", value: "\"Dev HTTP\" — Any → 8080/tcp" }],
    remediation_summary: "Scope broad allow rules to the addresses or subnets that actually need access.",
    commands: [{ shell: PS, command: "Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Where-Object { ($_ | Get-NetFirewallAddressFilter).RemoteAddress -eq 'Any' }", requires_admin: false, reversible: true, risk_note: "Read-only listing; scoping the rules themselves requires Set-NetFirewallRule." }],
  },
  {
    id: "firewall_logging_enabled", category: "firewall", title: "Firewall dropped-packet logging is off",
    status: "fail", severity: "low", score_weight: 3,
    observed: "LogBlocked: False on all profiles", expected: "LogBlocked: True, with a bounded log size",
    why_it_matters: "Without logging, you have no local record of blocked connection attempts to review after the fact.",
    evidence: [{ label: "Public profile", value: "LogBlocked: False" }],
    remediation_summary: "Enable blocked-packet logging with a bounded file size.",
    commands: [{ shell: PS, command: "Set-NetFirewallProfile -All -LogBlocked True -LogMaxSizeKilobytes 4096", requires_admin: true, reversible: true }],
  },
  // --- smb ---
  {
    id: "smb1_disabled", category: "smb", title: "SMBv1 is disabled",
    status: "pass", severity: "critical", score_weight: 10,
    observed: "SMB1Protocol feature: Disabled", expected: "Disabled",
    why_it_matters: "SMBv1 has no protection against relay or EternalBlue-class attacks and should never be enabled.",
    evidence: [{ label: "Feature state", value: "Disabled" }],
    remediation_summary: "No action needed.",
  },
  {
    id: "smb_signing_required", category: "smb", title: "SMB signing is not required",
    status: "fail", severity: "high", score_weight: 8,
    observed: "RequireSecuritySignature = False on the SMB client and server", expected: "RequireSecuritySignature = True",
    why_it_matters: "Without required signing, an attacker on the same network can relay or tamper with SMB sessions.",
    evidence: [{ label: "Client", value: "RequireSecuritySignature: False" }, { label: "Server", value: "RequireSecuritySignature: False" }],
    remediation_summary: "Require SMB signing on both the client and the server.",
    commands: [{ shell: PS, command: "Set-SmbClientConfiguration -RequireSecuritySignature $true -Force; Set-SmbServerConfiguration -RequireSecuritySignature $true -Force", requires_admin: true, reversible: true, risk_note: "May reduce throughput slightly and can break very old SMBv1 devices." }],
    docs_url: "https://learn.microsoft.com/windows-server/storage/file-server/smb-signing",
    references: ["CIS Microsoft Windows 11 v3.0.0 2.3.9.2"],
  },
  {
    id: "smb_guest_auth_disabled", category: "smb", title: "SMB guest fallback authentication is disabled",
    status: "pass", severity: "medium", score_weight: 5,
    observed: "AllowInsecureGuestAuth: False", expected: "False",
    why_it_matters: "Guest fallback lets a share be accessed unauthenticated if credentials are rejected.",
    evidence: [{ label: "AllowInsecureGuestAuth", value: "False" }],
    remediation_summary: "No action needed.",
  },
  {
    id: "smb_shares_exposed", category: "smb", title: "Non-default SMB shares are exposed",
    status: "warn", severity: "medium", score_weight: 5,
    observed: "2 custom shares found: \"Backups\" (Everyone: Read), \"Media\" (Everyone: Full Control)", expected: "Shares scoped to specific users or groups, least privilege",
    why_it_matters: "\"Everyone: Full Control\" on a share lets any authenticated user on the network modify or delete its contents.",
    evidence: [{ label: "Share", value: "Backups — Everyone: Read" }, { label: "Share", value: "Media — Everyone: Full Control" }],
    remediation_summary: "Restrict share permissions to specific accounts and the minimum access level needed.",
    commands: [{ shell: PS, command: "Get-SmbShare | Where-Object { $_.Name -notmatch '\\$$' } | Get-SmbShareAccess", requires_admin: false, reversible: true, risk_note: "Read-only; use Revoke-SmbShareAccess / Grant-SmbShareAccess to change permissions." }],
  },
  // --- remote_access ---
  {
    id: "rdp_disabled_or_nla", category: "remote_access", title: "RDP is enabled without Network Level Authentication",
    status: "fail", severity: "high", score_weight: 8,
    observed: "fDenyTSConnections: 0 (RDP enabled), UserAuthentication: 0 (NLA off)", expected: "RDP disabled, or enabled with UserAuthentication = 1",
    why_it_matters: "Without NLA, the RDP service completes a full session negotiation before authentication, widening the pre-auth attack surface.",
    evidence: [{ label: "RDP enabled", value: "Yes" }, { label: "NLA required", value: "No" }],
    remediation_summary: "Require Network Level Authentication for RDP, or disable RDP if unused.",
    commands: [{ shell: PS, command: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1", requires_admin: true, reversible: true }],
  },
  {
    id: "winrm_exposure", category: "remote_access", title: "WinRM listener is scoped correctly",
    status: "pass", severity: "medium", score_weight: 5,
    observed: "WinRM HTTP listener bound to no explicit IP filter is present but firewall restricts it to the Private profile", expected: "WinRM not reachable from Public networks",
    why_it_matters: "An unscoped WinRM listener reachable from any network is a common lateral-movement target.",
    evidence: [{ label: "Firewall scope", value: "Private profile only" }],
    remediation_summary: "No action needed.",
  },
  {
    id: "remote_registry_disabled", category: "remote_access", title: "Remote Registry service is running",
    status: "warn", severity: "medium", score_weight: 4,
    observed: "RemoteRegistry service: Running (Manual start)", expected: "Disabled unless actively needed",
    why_it_matters: "An attacker with credentials can use Remote Registry to read or modify registry keys on this host over the network.",
    evidence: [{ label: "Service state", value: "Running" }, { label: "Start type", value: "Manual" }],
    remediation_summary: "Disable the Remote Registry service unless it's actively required for management tooling.",
    commands: [{ shell: PS, command: "Stop-Service RemoteRegistry -Force; Set-Service RemoteRegistry -StartupType Disabled", requires_admin: true, reversible: true }],
  },
  {
    id: "psremoting_scope", category: "remote_access", title: "PowerShell Remoting trusted hosts is unrestricted",
    status: "fail", severity: "medium", score_weight: 5,
    observed: "TrustedHosts: *", expected: "TrustedHosts scoped to specific known hosts, or empty",
    why_it_matters: "A wildcard TrustedHosts entry means this machine will attempt NTLM authentication to any host claiming to be in the list, which weakens credential protection.",
    evidence: [{ label: "TrustedHosts", value: "*" }],
    remediation_summary: "Scope TrustedHosts to specific hostnames or clear it if remoting isn't used.",
    commands: [{ shell: PS, command: "Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value '' -Force", requires_admin: true, reversible: true }],
  },
  // --- name_resolution ---
  {
    id: "llmnr_disabled", category: "name_resolution", title: "LLMNR is enabled",
    status: "fail", severity: "medium", score_weight: 5,
    observed: "EnableMulticast: 1 (or policy not set)", expected: "LLMNR disabled via policy",
    why_it_matters: "LLMNR responses can be spoofed by an attacker on the local network to capture NTLM credential hashes (Responder-style attacks).",
    evidence: [{ label: "LLMNR policy", value: "Not configured (enabled by default)" }],
    remediation_summary: "Disable LLMNR via Group Policy or the registry.",
    commands: [{ shell: PS, command: "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast -Value 0", requires_admin: true, reversible: true }],
  },
  {
    id: "netbios_disabled", category: "name_resolution", title: "NetBIOS over TCP/IP is enabled",
    status: "warn", severity: "low", score_weight: 3,
    observed: "NetbiosOptions: 0 (use DHCP/default, effectively enabled) on the primary adapter", expected: "Disabled on adapters that don't need it",
    why_it_matters: "NetBIOS name resolution is spoofable similarly to LLMNR and is largely unnecessary on modern networks.",
    evidence: [{ label: "Adapter", value: "Ethernet — NetbiosOptions: 0" }],
    remediation_summary: "Disable NetBIOS over TCP/IP on adapters where it isn't required.",
    commands: [{ shell: PS, command: "$adapter = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled }; $adapter.SetTcpipNetbios(2)", requires_admin: true, reversible: true }],
  },
  {
    id: "mdns_exposure", category: "name_resolution", title: "mDNS responder reachable from the LAN",
    status: "pass", severity: "low", score_weight: 2,
    observed: "No mDNS listener bound to 0.0.0.0:5353", expected: "Not broadly exposed, or informational only",
    why_it_matters: "An overly chatty mDNS responder can leak hostnames and services to anyone on the local subnet.",
    evidence: [{ label: "Port 5353", value: "Not listening" }],
    remediation_summary: "No action needed.",
  },
  {
    id: "wpad_disabled", category: "name_resolution", title: "WPAD auto-proxy discovery is enabled",
    status: "warn", severity: "medium", score_weight: 4,
    observed: "AutoDetect: True in WinHTTP and per-user IE settings", expected: "Disabled unless a legitimate WPAD server is in use",
    why_it_matters: "WPAD is a classic vector for on-path proxy injection — a rogue DHCP/DNS response can point clients at an attacker-controlled proxy.",
    evidence: [{ label: "WinHTTP AutoDetect", value: "True" }],
    remediation_summary: "Disable WPAD auto-detection unless your network intentionally relies on it.",
    commands: [{ shell: PS, command: "netsh winhttp set proxy proxy-server=\"\" bypass-list=\"\"; reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v AutoDetect /t REG_DWORD /d 0 /f", requires_admin: false, reversible: true }],
  },
  {
    id: "dns_over_https", category: "name_resolution", title: "DNS-over-HTTPS is not configured",
    status: "warn", severity: "info", score_weight: 2,
    observed: "System DNS client is using classic UDP/53", expected: "DoH configured, or acceptable if the browser handles it independently",
    why_it_matters: "Plain DNS is observable and spoofable on-path; DoH prevents both.",
    evidence: [{ label: "DoH state", value: "Off (OS resolver)" }],
    remediation_summary: "Consider enabling DNS-over-HTTPS at the OS level for system-wide coverage.",
  },
  {
    id: "dns_servers_trusted", category: "name_resolution", title: "DNS servers are the expected ISP/router resolvers",
    status: "pass", severity: "medium", score_weight: 4,
    observed: "DNS servers: 192.168.1.1", expected: "Known, trusted resolvers (router, ISP, or an explicitly chosen provider)",
    why_it_matters: "An unexpected DNS server can silently redirect lookups to malicious infrastructure.",
    evidence: [{ label: "Configured DNS", value: "192.168.1.1" }],
    remediation_summary: "No action needed.",
  },
  // --- network_config ---
  {
    id: "ipv6_state", category: "network_config", title: "IPv6 is enabled with default privacy extensions",
    status: "pass", severity: "info", score_weight: 2,
    observed: "IPv6 enabled, temporary addresses enabled", expected: "Either consistently disabled, or enabled with privacy extensions on",
    why_it_matters: "IPv6 without privacy extensions can expose a stable hardware-derived address to every site you visit.",
    evidence: [{ label: "Privacy extensions", value: "Enabled" }],
    remediation_summary: "No action needed.",
  },
  {
    id: "ip_forwarding_disabled", category: "network_config", title: "IP forwarding is disabled",
    status: "pass", severity: "high", score_weight: 7,
    observed: "IPEnableRouter: 0", expected: "0 (disabled) unless this host is an intentional router",
    why_it_matters: "IP forwarding turns this host into a router, which can be abused to pivot traffic between networks it's attached to.",
    evidence: [{ label: "IPEnableRouter", value: "0" }],
    remediation_summary: "No action needed.",
  },
  {
    id: "promiscuous_adapters", category: "network_config", title: "No adapters found in promiscuous mode outside this tool's own capture",
    status: "pass", severity: "medium", score_weight: 4,
    observed: "1 adapter in promiscuous mode: NetAudit's own capture session", expected: "No unexpected promiscuous-mode adapters",
    why_it_matters: "A promiscuous adapter that isn't yours can indicate unauthorized packet sniffing on this host.",
    evidence: [{ label: "Promiscuous adapters", value: "Ethernet (NetAudit capture)" }],
    remediation_summary: "No action needed.",
  },
  {
    id: "unused_adapters_enabled", category: "network_config", title: "Unused network adapters are still enabled",
    status: "warn", severity: "low", score_weight: 3,
    observed: "Bluetooth PAN adapter enabled with no paired devices in 90 days", expected: "Disable adapters not in active use",
    why_it_matters: "Every enabled adapter is an additional attack surface, even if idle.",
    evidence: [{ label: "Adapter", value: "Bluetooth Network Connection — enabled, idle" }],
    remediation_summary: "Disable network adapters that aren't in active use.",
    commands: [{ shell: PS, command: "Disable-NetAdapter -Name 'Bluetooth Network Connection' -Confirm:$false", requires_admin: true, reversible: true }],
  },
  {
    id: "network_profile_public", category: "network_config", title: "Active network is set to Public profile",
    status: "error", severity: "info", score_weight: 2,
    observed: "Could not read network category for the active connection — requires elevation", expected: "N/A (informational check)",
    why_it_matters: "The Public profile applies a more restrictive firewall baseline; knowing which profile is active helps interpret the firewall checks above.",
    evidence: [{ label: "Reason", value: "Access denied reading NetConnectionProfile" }],
    remediation_summary: "Re-run this scan as Administrator to determine the active network profile.",
  },
  // --- wifi ---
  {
    id: "wifi_encryption_strength", category: "wifi", title: "Connected Wi-Fi network uses WPA2/WPA3",
    status: "pass", severity: "high", score_weight: 8,
    observed: "Authentication: WPA2-Personal, Cipher: AES", expected: "WPA2 or WPA3, AES/CCMP or better",
    why_it_matters: "WEP or WPA(1)/TKIP networks can be cracked or downgraded relatively easily.",
    evidence: [{ label: "Authentication", value: "WPA2-Personal" }, { label: "Cipher", value: "AES" }],
    remediation_summary: "No action needed.",
  },
  {
    id: "wifi_open_networks_saved", category: "wifi", title: "Saved profiles include open (unencrypted) networks",
    status: "warn", severity: "medium", score_weight: 4,
    observed: "2 saved profiles with Authentication: Open (\"Airport_Free_WiFi\", \"CoffeeShop\")", expected: "No saved open-network profiles, or auto-connect disabled for them",
    why_it_matters: "Windows will auto-reconnect to saved open networks by name, which an attacker can spoof to get you onto a hostile network.",
    evidence: [{ label: "Profile", value: "Airport_Free_WiFi — Open" }, { label: "Profile", value: "CoffeeShop — Open" }],
    remediation_summary: "Remove saved open-network profiles you no longer need.",
    commands: [{ shell: PS, command: "netsh wlan delete profile name=\"Airport_Free_WiFi\"; netsh wlan delete profile name=\"CoffeeShop\"", requires_admin: false, reversible: false, risk_note: "Removes the saved profile; you'll need to reconnect manually next time." }],
  },
  {
    id: "wifi_autoconnect_open", category: "wifi", title: "Auto-connect to open hotspots is disabled",
    status: "pass", severity: "medium", score_weight: 4,
    observed: "\"Connect to suggested open hotspots\" is off", expected: "Off",
    why_it_matters: "Automatically joining unknown open networks exposes traffic to whoever operates that access point.",
    evidence: [{ label: "Auto-connect to open hotspots", value: "Off" }],
    remediation_summary: "No action needed.",
  },
  // --- tls ---
  {
    id: "tls10_11_disabled", category: "tls", title: "TLS 1.0 and 1.1 are still enabled",
    status: "fail", severity: "high", score_weight: 7,
    observed: "SCHANNEL: TLS 1.0 Client/Server Enabled, TLS 1.1 Client/Server Enabled", expected: "Disabled — TLS 1.2+ only",
    why_it_matters: "TLS 1.0/1.1 have known weaknesses (BEAST, POODLE-adjacent issues) and are deprecated by all major browsers and standards bodies.",
    evidence: [{ label: "TLS 1.0", value: "Enabled" }, { label: "TLS 1.1", value: "Enabled" }],
    remediation_summary: "Disable TLS 1.0 and 1.1 in the SCHANNEL registry keys.",
    commands: [{ shell: PS, command: "foreach ($p in 'TLS 1.0','TLS 1.1') { New-Item -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\$p\\Server\" -Force | Out-Null; Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\$p\\Server\" -Name Enabled -Value 0 }", requires_admin: true, reversible: true, risk_note: "Can break connectivity to very old internal services that only offer TLS 1.0/1.1." }],
  },
  {
    id: "ssl3_disabled", category: "tls", title: "SSL 3.0 is disabled",
    status: "pass", severity: "critical", score_weight: 9,
    observed: "SCHANNEL: SSL 3.0 Server Disabled", expected: "Disabled",
    why_it_matters: "SSL 3.0 is broken by the POODLE attack and should never be enabled.",
    evidence: [{ label: "SSL 3.0", value: "Disabled" }],
    remediation_summary: "No action needed.",
  },
  {
    id: "weak_ciphers_disabled", category: "tls", title: "RC4 cipher suite is still enabled",
    status: "fail", severity: "medium", score_weight: 5,
    observed: "TLS_RSA_WITH_RC4_128_SHA present in the enabled cipher suite order", expected: "RC4 and other weak ciphers removed from the suite order",
    why_it_matters: "RC4 has known biases that can be exploited to recover plaintext from repeated sessions.",
    evidence: [{ label: "Weak cipher found", value: "TLS_RSA_WITH_RC4_128_SHA" }],
    remediation_summary: "Remove RC4-based cipher suites from the system TLS cipher order.",
    commands: [{ shell: PS, command: "Disable-TlsCipherSuite -Name 'TLS_RSA_WITH_RC4_128_SHA'", requires_admin: true, reversible: true }],
  },
  {
    id: "certificate_store_anomalies", category: "tls", title: "No untrusted root certificates found in the local store",
    status: "pass", severity: "high", score_weight: 6,
    observed: "0 non-Microsoft, non-enterprise roots in the Trusted Root store", expected: "Only expected/enterprise roots present",
    why_it_matters: "A rogue root certificate would let its holder transparently intercept any TLS connection on this machine.",
    evidence: [{ label: "Unexpected roots", value: "0 found" }],
    remediation_summary: "No action needed.",
  },
  // --- listening_services ---
  {
    id: "listening_on_all_interfaces", category: "listening_services", title: "Services listening on 0.0.0.0 found",
    status: "warn", severity: "medium", score_weight: 5,
    observed: "node.exe listening on 0.0.0.0:3000", expected: "Development services bound to 127.0.0.1 unless intentionally shared",
    why_it_matters: "Binding to all interfaces exposes a service to the entire LAN (and any VPN) rather than just this machine.",
    evidence: [{ label: "Listener", value: "node.exe — 0.0.0.0:3000" }],
    remediation_summary: "Bind local development servers to 127.0.0.1 unless you intend to share them on the network.",
  },
  {
    id: "high_risk_ports_open", category: "listening_services", title: "No high-risk ports (Telnet, legacy RPC) are open",
    status: "pass", severity: "critical", score_weight: 8,
    observed: "Ports 23, 135 (external), 445 (external) not reachable from outside", expected: "Not reachable from the LAN/WAN",
    why_it_matters: "Telnet and legacy RPC/SMB exposure are among the most commonly exploited entry points.",
    evidence: [{ label: "Port 23", value: "Not listening" }],
    remediation_summary: "No action needed.",
  },
  {
    id: "unexpected_listeners", category: "listening_services", title: "Unrecognized listener on a high port",
    status: "fail", severity: "high", score_weight: 6,
    observed: "Unsigned binary \"svcupd.exe\" listening on 0.0.0.0:31337, not present in Program Files", expected: "All listeners map to a recognized, signed application",
    why_it_matters: "An unsigned process listening on a non-standard port from outside Program Files is a common backdoor pattern.",
    evidence: [{ label: "Process", value: "svcupd.exe (unsigned)" }, { label: "Port", value: "31337/tcp" }, { label: "Path", value: "C:\\Users\\Public\\svcupd.exe" }],
    remediation_summary: "Investigate this process before removing it — confirm it isn't a legitimate but unusually named tool.",
    commands: [{ shell: PS, command: "Get-Process | Where-Object { $_.Path -eq 'C:\\Users\\Public\\svcupd.exe' } | Select-Object Id,Path,Company,StartTime", requires_admin: false, reversible: true }],
  },
  {
    id: "upnp_disabled", category: "listening_services", title: "UPnP is enabled on the router-facing adapter",
    status: "warn", severity: "medium", score_weight: 4,
    observed: "SSDP Discovery service: Running", expected: "Disabled unless a specific application requires automatic port mapping",
    why_it_matters: "UPnP lets any application on this host open inbound ports on your router without confirmation.",
    evidence: [{ label: "SSDP Discovery", value: "Running" }],
    remediation_summary: "Disable UPnP/SSDP unless something specific relies on it, and check your router for existing UPnP-opened ports.",
    commands: [{ shell: PS, command: "Stop-Service SSDPSRV -Force; Set-Service SSDPSRV -StartupType Disabled", requires_admin: true, reversible: true }],
  },
  // --- updates_and_defense ---
  {
    id: "defender_realtime_enabled", category: "updates_and_defense", title: "Defender real-time protection is on",
    status: "pass", severity: "critical", score_weight: 9,
    observed: "RealTimeProtectionEnabled: True", expected: "True",
    why_it_matters: "Real-time protection is the primary safety net against known malware being written to disk or executed.",
    evidence: [{ label: "Real-time protection", value: "Enabled" }],
    remediation_summary: "No action needed.",
  },
  {
    id: "defender_signatures_current", category: "updates_and_defense", title: "Defender signatures are 6 days old",
    status: "warn", severity: "medium", score_weight: 4,
    observed: "AntivirusSignatureLastUpdated: 6 days ago", expected: "Updated within the last 24-48 hours",
    why_it_matters: "Stale signatures miss detections for malware families discovered after the last update.",
    evidence: [{ label: "Last updated", value: "6 days ago" }],
    remediation_summary: "Trigger a signature update.",
    commands: [{ shell: PS, command: "Update-MpSignature", requires_admin: true, reversible: true }],
  },
  {
    id: "windows_update_current", category: "updates_and_defense", title: "2 important updates are pending",
    status: "warn", severity: "high", score_weight: 6,
    observed: "2 pending updates including 1 security update, last successful install 14 days ago", expected: "No pending security updates older than 7 days",
    why_it_matters: "Unpatched vulnerabilities in shipped updates are actively exploited once the patch (and the bug it fixes) becomes public.",
    evidence: [{ label: "Pending", value: "2 updates (1 security)" }],
    remediation_summary: "Install pending Windows updates.",
    commands: [{ shell: PS, command: "Install-WindowsUpdate -AcceptAll -AutoReboot", requires_admin: true, reversible: false, risk_note: "May require a restart." }],
  },
  {
    id: "uac_enabled", category: "updates_and_defense", title: "User Account Control is at the default level",
    status: "pass", severity: "high", score_weight: 7,
    observed: "EnableLUA: 1, ConsentPromptBehaviorAdmin: 5 (default)", expected: "EnableLUA: 1",
    why_it_matters: "UAC is what forces an explicit prompt before a process gains administrative rights.",
    evidence: [{ label: "EnableLUA", value: "1" }],
    remediation_summary: "No action needed.",
  },
  {
    id: "bitlocker_status", category: "updates_and_defense", title: "System drive is not encrypted",
    status: "fail", severity: "high", score_weight: 7,
    observed: "C: — ProtectionStatus: Off", expected: "ProtectionStatus: On",
    why_it_matters: "An unencrypted drive can be read by anyone with physical access, by removing it or booting another OS.",
    evidence: [{ label: "Drive C:", value: "Protection Off" }],
    remediation_summary: "Enable BitLocker on the system drive.",
    commands: [{ shell: PS, command: "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector", requires_admin: true, reversible: true, risk_note: "Requires a TPM; back up the recovery key before enabling." }],
  },
  // --- accounts ---
  {
    id: "guest_account_disabled", category: "accounts", title: "Guest account is disabled",
    status: "pass", severity: "high", score_weight: 6,
    observed: "Guest account: Disabled", expected: "Disabled",
    why_it_matters: "An enabled Guest account is a standing, often-forgotten unauthenticated (or trivially authenticated) entry point.",
    evidence: [{ label: "Guest", value: "Disabled" }],
    remediation_summary: "No action needed.",
  },
  {
    id: "local_admin_count", category: "accounts", title: "3 accounts are in the local Administrators group",
    status: "warn", severity: "medium", score_weight: 4,
    observed: "Administrators group members: lukab, Administrator, svc-backup", expected: "Minimum necessary accounts with admin rights",
    why_it_matters: "Every additional admin account is an additional path to full compromise if its credentials leak.",
    evidence: [{ label: "Member", value: "lukab" }, { label: "Member", value: "Administrator (built-in)" }, { label: "Member", value: "svc-backup" }],
    remediation_summary: "Review whether svc-backup needs full local admin, or can run with a scoped service account instead.",
  },
  {
    id: "blank_passwords", category: "accounts", title: "No local accounts with blank passwords",
    status: "pass", severity: "critical", score_weight: 9,
    observed: "0 local accounts with an empty password", expected: "0",
    why_it_matters: "A blank password is equivalent to no authentication at all for that account.",
    evidence: [{ label: "Accounts with blank password", value: "0" }],
    remediation_summary: "No action needed.",
  },
  {
    id: "autologon_disabled", category: "accounts", title: "Automatic logon policy check",
    status: "skipped", severity: "info", score_weight: 4,
    observed: "This machine is domain-joined; AutoAdminLogon is governed by domain policy, not the local registry key this check reads.", expected: "N/A on domain-joined hosts",
    why_it_matters: "On a standalone machine, automatic logon stores a plaintext password in the registry and skips authentication on boot.",
    evidence: [{ label: "Join state", value: "Domain-joined" }],
    remediation_summary: "Check domain Group Policy for autologon settings instead of this local check.",
  },
];

export function buildPostureChecks(nowIso: string): PostureCheck[] {
  return SPECS.map((s) => ({
    id: s.id,
    category: s.category,
    title: s.title,
    status: s.status,
    severity: s.severity,
    score_weight: s.score_weight,
    observed: s.observed,
    expected: s.expected,
    why_it_matters: s.why_it_matters,
    evidence: s.evidence,
    remediation: {
      summary: s.remediation_summary,
      commands: s.commands ?? [],
      docs_url: s.docs_url,
    },
    references: s.references ?? [],
    checked_at: nowIso,
    duration_ms: 8 + Math.round((s.id.length * 37) % 60),
  }));
}

export function categoriesFromChecks(checks: PostureCheck[]): { id: string; label: string; checkIds: string[] }[] {
  const order: string[] = [];
  const byCat = new Map<string, string[]>();
  for (const c of checks) {
    if (!byCat.has(c.category)) {
      byCat.set(c.category, []);
      order.push(c.category);
    }
    byCat.get(c.category)!.push(c.id);
  }
  return order.map((id) => ({ id, label: CATEGORY_LABELS[id] ?? id, checkIds: byCat.get(id)! }));
}
