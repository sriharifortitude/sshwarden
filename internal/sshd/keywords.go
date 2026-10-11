// Package sshd reads sshd_config the way sshd does: Include, first value wins, and Match
// blocks that override the global section for the connections they match.
package sshd

// spec describes one keyword.
type spec struct {
	// Name is the spelling used in the manual.
	Name string
	// InMatch is true when the keyword may appear inside a Match block.
	InMatch bool
	// Multi is true when every occurrence counts (Port, HostKey, AllowUsers, ...) instead of the first.
	Multi bool
	// Alias names the keyword this one is another spelling of.
	Alias string
	// Removed is true for keywords sshd accepts but ignores, with a warning.
	Removed bool
}

// keywords is the sshd_config(5) keyword list of OpenSSH 9.x and 10.x, plus keywords that
// common distribution patches add, so a stock Debian or Red Hat file is not reported as broken.
var keywords = map[string]spec{}

func init() {
	inMatch := []string{
		"AcceptEnv", "AllowAgentForwarding", "AllowGroups", "AllowStreamLocalForwarding", "AllowTcpForwarding",
		"AllowUsers", "AuthenticationMethods", "AuthorizedKeysCommand", "AuthorizedKeysCommandUser",
		"AuthorizedKeysFile", "AuthorizedPrincipalsCommand", "AuthorizedPrincipalsCommandUser",
		"AuthorizedPrincipalsFile", "Banner", "CASignatureAlgorithms", "ChannelTimeout", "ChrootDirectory",
		"ClientAliveCountMax", "ClientAliveInterval", "DenyGroups", "DenyUsers", "DisableForwarding",
		"ExposeAuthInfo", "ForceCommand", "GatewayPorts", "GSSAPIAuthentication", "HostbasedAcceptedAlgorithms",
		"HostbasedAuthentication", "HostbasedUsesNameFromPacketOnly", "IgnoreRhosts", "Include", "IPQoS",
		"KbdInteractiveAuthentication", "KerberosAuthentication", "LogLevel", "LogVerbose", "MaxAuthTries",
		"MaxSessions", "PasswordAuthentication", "PermitEmptyPasswords", "PermitListen", "PermitOpen",
		"PermitRootLogin", "PermitTTY", "PermitTunnel", "PermitUserRC", "PubkeyAcceptedAlgorithms",
		"PubkeyAuthentication", "PubkeyAuthOptions", "RefuseConnection", "RekeyLimit", "RevokedKeys", "SetEnv",
		"StreamLocalBindMask", "StreamLocalBindUnlink", "TrustedUserCAKeys", "UnusedConnectionTimeout",
		"X11DisplayOffset", "X11Forwarding", "X11UseLocalhost", "Subsystem", "RDomain", "IgnoreUserKnownHosts",
	}
	globalOnly := []string{
		"AddressFamily", "Ciphers", "Compression", "FingerprintHash", "GSSAPICleanupCredentials",
		"GSSAPIStrictAcceptorCheck", "HostCertificate", "HostKey", "HostKeyAgent", "HostKeyAlgorithms",
		"KerberosGetAFSToken", "KerberosOrLocalPasswd", "KerberosTicketCleanup", "KexAlgorithms", "ListenAddress",
		"LoginGraceTime", "MACs", "Match", "MaxStartups", "ModuliFile", "PerSourceMaxStartups",
		"PerSourceNetBlockSize", "PerSourcePenalties", "PerSourcePenaltyExemptList", "PidFile", "Port",
		"PrintLastLog", "PrintMotd", "RequiredRSASize", "SecurityKeyProvider", "SshdSessionPath", "SshdAuthPath",
		"StrictModes", "SyslogFacility", "TCPKeepAlive", "UseDNS", "UsePAM", "VersionAddendum", "XAuthLocation",
		"PermitUserEnvironment",
		// Distribution patches (Debian, Ubuntu, Fedora, RHEL).
		"DebianBanner", "GSSAPIKeyExchange", "GSSAPIStoreCredentialsOnRekey", "GSSAPIKexAlgorithms",
		"GSSAPIEnablek5users", "KerberosUseKuserok",
	}
	// Keywords where every occurrence counts. Treating an uncertain keyword as multi only means
	// a repeated value is not reported as ignored, which is the safe side.
	multi := map[string]bool{
		"AcceptEnv": true, "AllowGroups": true, "AllowUsers": true, "DenyGroups": true, "DenyUsers": true,
		"HostKey": true, "HostCertificate": true, "ListenAddress": true, "Port": true, "Subsystem": true,
		"Include": true, "Match": true, "SetEnv": true, "PermitOpen": true, "PermitListen": true,
		"ChannelTimeout": true, "LogVerbose": true, "AuthorizedKeysFile": true, "AuthorizedPrincipalsFile": true,
	}
	for _, k := range inMatch {
		keywords[lower(k)] = spec{Name: k, InMatch: true, Multi: multi[k]}
	}
	for _, k := range globalOnly {
		keywords[lower(k)] = spec{Name: k, Multi: multi[k]}
	}
	for alias, target := range map[string]string{
		"ChallengeResponseAuthentication": "KbdInteractiveAuthentication",
		"PubkeyAcceptedKeyTypes":          "PubkeyAcceptedAlgorithms",
		"HostbasedAcceptedKeyTypes":       "HostbasedAcceptedAlgorithms",
		"CASignatureAlgorithm":            "CASignatureAlgorithms",
	} {
		t := keywords[lower(target)]
		keywords[lower(alias)] = spec{Name: alias, InMatch: t.InMatch, Alias: target}
	}
	for _, k := range []string{"Protocol", "UsePrivilegeSeparation", "RSAAuthentication", "RhostsRSAAuthentication",
		"KeyRegenerationInterval", "ServerKeyBits", "UseLogin", "DSAAuthentication"} {
		keywords[lower(k)] = spec{Name: k, Removed: true}
	}
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// Canonical returns the lower-case keyword a spelling stands for, following aliases.
func Canonical(word string) (string, spec, bool) {
	s, ok := keywords[lower(word)]
	if !ok {
		return "", spec{}, false
	}
	if s.Alias != "" {
		return lower(s.Alias), s, true
	}
	return lower(word), s, true
}

// DisplayName is the manual's spelling of a canonical keyword.
func DisplayName(canonical string) string {
	if s, ok := keywords[canonical]; ok {
		return s.Name
	}
	return canonical
}
