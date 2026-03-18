//go:build linux

package authdaemon

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

func writeCACertIfNotExists(path, contents string, force bool) error {
	contents = strings.TrimSpace(contents)
	if contents != "" && !strings.HasSuffix(contents, "\n") {
		contents += "\n"
	}
	existing, err := os.ReadFile(path)
	if err == nil {
		existingStr := strings.TrimSpace(string(existing))
		if existingStr != "" && !strings.HasSuffix(existingStr, "\n") {
			existingStr += "\n"
		}
		if existingStr == contents || !force {
			return nil
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	return os.WriteFile(path, []byte(contents), 0644)
}

func writePrincipals(path, username, niceID string) error {
	if path == "" || strings.TrimSpace(username) == "" {
		return nil
	}
	data := make(map[string][]string)
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &data)
	}
	list := data[username]
	seen := make(map[string]struct{}, len(list)+2)
	for _, p := range list {
		seen[p] = struct{}{}
	}
	for _, p := range []string{strings.TrimSpace(username), strings.TrimSpace(niceID)} {
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		list = append(list, p)
	}
	data[username] = list
	body, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal principals: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	return os.WriteFile(path, body, 0644)
}

func ensureUser(username string, meta ConnectionMetadata, generateRandomPassword bool) error {
	if username == "" {
		return nil
	}
	u, err := user.Lookup(username)
	if err != nil {
		if _, ok := err.(user.UnknownUserError); !ok {
			return fmt.Errorf("lookup user %s: %w", username, err)
		}
		return createUser(username, meta, generateRandomPassword)
	}
	return reconcileUser(u, meta)
}

func createUser(username string, meta ConnectionMetadata, generateRandomPassword bool) error {
	args := []string{"-s", "/bin/bash"}
	if meta.Homedir {
		args = append(args, "-m")
	} else {
		args = append(args, "-M")
	}
	args = append(args, username)
	cmd := exec.Command("useradd", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("useradd %s: %w (output: %s)", username, err, string(out))
	}
	if generateRandomPassword {
		if err := setRandomPassword(username); err != nil {
			return err
		}
	}
	if meta.Homedir {
		if u, err := user.Lookup(username); err == nil && u.HomeDir != "" {
			uid, gid := mustAtoi(u.Uid), mustAtoi(u.Gid)
			copySkelInto("/etc/skel", u.HomeDir, uid, gid)
		}
	}
	setUserGroups(username, desiredGroups(meta))
	return configureSudo(username, meta)
}

func reconcileUser(u *user.User, meta ConnectionMetadata) error {
	setUserGroups(u.Username, desiredGroups(meta))
	if meta.Homedir && u.HomeDir != "" {
		uid, gid := mustAtoi(u.Uid), mustAtoi(u.Gid)
		if st, err := os.Stat(u.HomeDir); err != nil || !st.IsDir() {
			if err := os.MkdirAll(u.HomeDir, 0755); err == nil {
				_ = os.Chown(u.HomeDir, uid, gid)
			}
		}
		copySkelInto("/etc/skel", u.HomeDir, uid, gid)
	}
	return configureSudo(u.Username, meta)
}

func configureSudo(username string, meta ConnectionMetadata) error {
	switch meta.SudoMode {
	case "full":
		return configurePasswordlessSudo(username)
	case "commands":
		if len(meta.SudoCommands) == 0 {
			removeSudoers(username)
			return nil
		}
		return configureSudoCommands(username, meta.SudoCommands)
	default:
		removeSudoers(username)
		return nil
	}
}

func desiredGroups(meta ConnectionMetadata) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, g := range meta.Groups {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if _, ok := seen[g]; ok {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	if meta.SudoMode == "full" {
		sg := sudoGroup()
		if _, ok := seen[sg]; !ok {
			out = append(out, sg)
		}
	}
	return out
}

func setUserGroups(username string, groups []string) {
	cmd := exec.Command("usermod", "-G", strings.Join(groups, ","), username)
	_, _ = cmd.CombinedOutput()
}

func setRandomPassword(username string) error {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("generate password: %w", err)
	}
	password := hex.EncodeToString(b)
	cmd := exec.Command("chpasswd")
	cmd.Stdin = strings.NewReader(username + ":" + password)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("chpasswd: %w (output: %s)", err, string(out))
	}
	return nil
}

func sudoGroup() string {
	f, err := os.Open("/etc/group")
	if err != nil {
		return "sudo"
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	hasWheel := false
	hasSudo := false
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "wheel:") {
			hasWheel = true
		}
		if strings.HasPrefix(line, "sudo:") {
			hasSudo = true
		}
	}
	if hasWheel {
		return "wheel"
	}
	if hasSudo {
		return "sudo"
	}
	return "sudo"
}

func configurePasswordlessSudo(username string) error {
	return writeSudoersFile(username, fmt.Sprintf("# Created by Pangolin auth-daemon\n%s ALL=(ALL) NOPASSWD:ALL\n", username))
}

func configureSudoCommands(username string, commands []string) error {
	var b strings.Builder
	b.WriteString("# Created by Pangolin auth-daemon (restricted commands)\n")
	valid := 0
	for _, c := range commands {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		fmt.Fprintf(&b, "%s ALL=(ALL) NOPASSWD: %s\n", username, c)
		valid++
	}
	if valid == 0 {
		return fmt.Errorf("no valid sudo commands")
	}
	return writeSudoersFile(username, b.String())
}

func writeSudoersFile(username, content string) error {
	sudoersFile := filepath.Join("/etc/sudoers.d", "90-pangolin-"+username)
	tmpFile := sudoersFile + ".tmp"
	if err := os.WriteFile(tmpFile, []byte(content), 0440); err != nil {
		return fmt.Errorf("write temp sudoers file: %w", err)
	}
	cmd := exec.Command("visudo", "-c", "-f", tmpFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("visudo validation failed: %w (output: %s)", err, string(out))
	}
	return os.Rename(tmpFile, sudoersFile)
}

func removeSudoers(username string) {
	_ = os.Remove(filepath.Join("/etc/sudoers.d", "90-pangolin-"+username))
}

func copySkelInto(srcDir, dstDir string, uid, gid int) {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		src := filepath.Join(srcDir, e.Name())
		dst := filepath.Join(dstDir, e.Name())
		if e.IsDir() {
			if err := os.MkdirAll(dst, 0755); err != nil {
				continue
			}
			_ = os.Chown(dst, uid, gid)
			copySkelInto(src, dst, uid, gid)
			continue
		}
		if _, err := os.Stat(dst); err == nil {
			continue
		}
		data, err := os.ReadFile(src)
		if err != nil {
			continue
		}
		if err := os.WriteFile(dst, data, 0644); err != nil {
			continue
		}
		_ = os.Chown(dst, uid, gid)
	}
}

func mustAtoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
