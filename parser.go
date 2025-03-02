package sshconfig

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/gobwas/glob"
	"github.com/mitchellh/go-homedir"
)

// SSHHost defines a single host entry in an ssh config
type SSHHost struct {
	Host              []string
	HostName          string
	User              string
	Port              int
	IdentityFile      string
	ProxyCommand      string
	ProxyJump         []string
	LocalForwards     []Forward
	RemoteForwards    []Forward
	DynamicForwards   []DynamicForward
	HostKeyAlgorithms []string
	Ciphers           []string
	MACs              []string

	hostMatcher      []glob.Glob
	isGlobalWildcard bool
}

// Match returns true if the host matches to SSHHost
func (h *SSHHost) Match(host string) bool {
	for _, g := range h.hostMatcher {
		if g != nil && g.Match(host) {
			return true
		}
	}
	return false
}

// Forward defines a single port forward entry
type Forward struct {
	InHost  string
	InPort  int
	OutHost string
	OutPort int
}

// NewForward returns Forward object parsed from LocalForward or RemoteForward string
func NewForward(f string) (Forward, error) {
	r := regexp.MustCompile(`((\S+):)?(\d+)\s+(\S+):(\d+)`)
	m := r.FindStringSubmatch(f)

	if len(m) < 6 {
		return Forward{}, fmt.Errorf("invalid forward: %#v", f)
	}

	InPort, err := strconv.Atoi(m[3])
	if err != nil {
		return Forward{}, err
	}

	OutPort, err := strconv.Atoi(m[5])
	if err != nil {
		return Forward{}, err
	}

	return Forward{
		InHost:  m[2],
		InPort:  InPort,
		OutHost: m[4],
		OutPort: OutPort,
	}, nil
}

// DynamicForward defines a single dynamic port forward entry
type DynamicForward struct {
	Host string
	Port int
}

// NewDynamicForward returns DForward object parsed from DynamicForward string
func NewDynamicForward(f string) (DynamicForward, error) {
	r := regexp.MustCompile(`((\S+):)?(\d+)`)
	m := r.FindStringSubmatch(f)

	if len(m) < 4 {
		return DynamicForward{}, fmt.Errorf("invalid dynamic forward: %#v", f)
	}

	InPort, err := strconv.Atoi(m[3])
	if err != nil {
		return DynamicForward{}, err
	}

	return DynamicForward{
		Host: m[2],
		Port: InPort,
	}, nil
}

// MustParse must parse the SSH config given by path, or it will panic
func MustParse(path string) []*SSHHost {
	config, err := Parse(path)
	if err != nil {
		panic(err)
	}
	return config
}

// MustParseSSHConfig must parse the SSH config given by path, or it will panic
// Deprecated: Use MustParse instead.
func MustParseSSHConfig(path string) []*SSHHost {
	return MustParse(path)
}

// ParseSSHConfig parses a SSH config given by path.
// Deprecated: Use Parse instead.
func ParseSSHConfig(path string) ([]*SSHHost, error) {
	return Parse(path)
}

// Parse parses an SSH config given by path.
func Parse(path string) ([]*SSHHost, error) {
	// read config file
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return parse(string(content), path)
}

// ParseFS parses a SSH config given by path contained in fsys.
func ParseFS(fsys fs.FS, path string) ([]*SSHHost, error) {
	// read config file
	content, err := fs.ReadFile(fsys, path)
	if err != nil {
		return nil, err
	}

	return parse(string(content), path)
}

// parses an openssh config file
func parse(input string, path string) ([]*SSHHost, error) {
	var sshConfigs []*SSHHost
	var next item
	var sshHost *SSHHost
	var onlyIncludes = !strings.Contains(input, "Host ") && strings.Contains(input, "Include ")

	lexer := lex(input)
Loop:
	for {
		token := lexer.nextItem()

		if sshHost == nil {
			if token.typ == itemEOF {
				break Loop
			}
			if token.typ != itemHost && token.typ != itemInclude {
				// File has no `Host` but has `Include`. Continue trying to parse it.
				if onlyIncludes {
					continue Loop
				}
				return nil, fmt.Errorf("%s:%d: config variable before Host variable", path, token.pos)
			}
		} else if token.typ == itemInclude {
			return nil, fmt.Errorf("include not allowed in Host block")
		}

		switch token.typ {
		case itemHost:
			if sshHost != nil {
				sshConfigs = append(sshConfigs, sshHost)
			}

			sshHost = new(SSHHost)
		case itemHostValue:
			sshHost.Host = strings.Split(token.val, " ")
			sshHost.isGlobalWildcard = len(sshHost.Host) == 1 && sshHost.Host[0] == "*"
			if !sshHost.isGlobalWildcard {
				globs, err := compileHostsToGlob(sshHost.Host)
				if err != nil {
					return nil, err
				}
				sshHost.hostMatcher = globs
			}
		case itemHostName:
			next = lexer.nextItem()
			if next.typ != itemValue {
				return nil, fmt.Errorf(next.val)
			}
			sshHost.HostName = next.val
		case itemUser:
			next = lexer.nextItem()
			if next.typ != itemValue {
				return nil, fmt.Errorf(next.val)
			}
			sshHost.User = next.val
		case itemPort:
			next = lexer.nextItem()
			if next.typ != itemValue {
				return nil, fmt.Errorf(next.val)
			}
			port, err := strconv.Atoi(next.val)
			if err != nil {
				return nil, err
			}
			sshHost.Port = port
		case itemProxyCommand:
			next = lexer.nextItem()
			if next.typ != itemValue {
				return nil, fmt.Errorf(next.val)
			}
			sshHost.ProxyCommand = next.val
		case itemProxyJumpHost:
			next = lexer.nextItem()
			if next.typ != itemValue {
				return nil, fmt.Errorf(next.val)
			}
			sshHost.ProxyJump = strings.Split(next.val, ",")
		case itemHostKeyAlgorithms:
			next = lexer.nextItem()
			if next.typ != itemValue {
				return nil, fmt.Errorf(next.val)
			}
			sshHost.HostKeyAlgorithms = strings.Split(next.val, ",")
		case itemIdentityFile:
			next = lexer.nextItem()
			if next.typ != itemValue {
				return nil, fmt.Errorf(next.val)
			}
			sshHost.IdentityFile = next.val
		case itemLocalForward:
			next = lexer.nextItem()
			f, err := NewForward(next.val)
			if err != nil {
				return nil, err
			}
			sshHost.LocalForwards = append(sshHost.LocalForwards, f)
		case itemRemoteForward:
			next = lexer.nextItem()
			f, err := NewForward(next.val)
			if err != nil {
				return nil, err
			}
			sshHost.RemoteForwards = append(sshHost.RemoteForwards, f)
		case itemDynamicForward:
			next = lexer.nextItem()
			f, err := NewDynamicForward(next.val)
			if err != nil {
				return nil, err
			}
			sshHost.DynamicForwards = append(sshHost.DynamicForwards, f)
		case itemInclude:
			next = lexer.nextItem()
			if next.typ != itemValue {
				return nil, fmt.Errorf(next.val)
			}

			includePath, err := parseIncludePath(path, next.val)
			if err != nil {
				return nil, err
			}

			files, err := filepath.Glob(includePath)
			if err != nil {
				return nil, err
			}

			if len(files) == 0 {
				return nil, fmt.Errorf("no files found for include path %s", includePath)
			}

			for _, f := range files {
				includeSshConfigs, err := Parse(f)
				if err != nil {
					return nil, err
				}

				sshConfigs = append(sshConfigs, includeSshConfigs...)
			}
		case itemCiphers:
			next = lexer.nextItem()
			if next.typ != itemValue {
				return nil, fmt.Errorf(next.val)
			}
			sshHost.Ciphers = strings.Split(next.val, ",")
		case itemMACs:
			next = lexer.nextItem()
			if next.typ != itemValue {
				return nil, fmt.Errorf(next.val)
			}
			sshHost.MACs = strings.Split(next.val, ",")
		case itemError:
			return nil, fmt.Errorf("%s at pos %d", token.val, token.pos)
		case itemEOF:
			if sshHost != nil {
				sshConfigs = append(sshConfigs, sshHost)
			}
			break Loop
		default:
			// continue onwards
		}
	}
	return mergeGlobalWildcard(sshConfigs), nil
}

func parseIncludePath(currentPath string, includePath string) (string, error) {
	if strings.HasPrefix(includePath, "~") {
		expandedPath, err := homedir.Expand(includePath)
		if err != nil {
			return "", err
		}

		return expandedPath, nil
	} else if !strings.HasPrefix(includePath, "/") {
		return filepath.Join(filepath.Dir(currentPath), includePath), nil
	}

	return includePath, nil
}

func mergeGlobalWildcard(sshConfigs []*SSHHost) []*SSHHost {
	gi := slices.IndexFunc(sshConfigs, func(host *SSHHost) bool {
		if host.isGlobalWildcard {
			return true
		}
		return false
	})
	if gi == -1 {
		return sshConfigs
	}

	global := sshConfigs[gi]
	for _, sshConfig := range sshConfigs {
		if sshConfig.User == "" {
			sshConfig.User = global.User
		}

		if sshConfig.Port == 0 {
			sshConfig.Port = global.Port
		}

		if sshConfig.IdentityFile == "" {
			sshConfig.IdentityFile = global.IdentityFile
		}

		if sshConfig.ProxyCommand == "" {
			sshConfig.ProxyCommand = global.ProxyCommand
		}

		if len(sshConfig.ProxyJump) == 0 {
			sshConfig.ProxyJump = global.ProxyJump
		}

		if len(sshConfig.HostKeyAlgorithms) == 0 {
			sshConfig.HostKeyAlgorithms = global.HostKeyAlgorithms
		}

		if len(sshConfig.Ciphers) == 0 {
			sshConfig.Ciphers = global.Ciphers
		}

		if len(sshConfig.MACs) == 0 {
			sshConfig.MACs = global.MACs
		}
	}

	return slices.Delete(sshConfigs, gi, gi+1)
}

func compileHostsToGlob(hosts []string) ([]glob.Glob, error) {
	globs := make([]glob.Glob, 0, len(hosts))
	for _, pattern := range hosts {
		compiled, err := glob.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile glob pattern: %s, error: %w", pattern, err)
		}
		globs = append(globs, compiled)
	}

	return globs, nil
}
