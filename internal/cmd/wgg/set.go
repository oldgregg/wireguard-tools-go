package wgg

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"path/filepath"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func cmdSet(args []string) error {
	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}
	defer c.Close()

	cfg := wgtypes.Config{}
	cp := configParser{Cfg: &cfg}

	dev, args := args[0], args[1:]
	for len(args) > 0 {
		if args, err = parseOneConfigValue(args, cp); err != nil {
			return err
		}
	}

	if err := c.ConfigureDevice(dev, cfg); err != nil {
		return fmt.Errorf("error configuring device %s: %w", dev, err)
	}
	return nil
}

func parseOneConfigValue(args []string, cp configParser) ([]string, error) {
	errInvalid := fmt.Errorf("invalid argument: %s", args[0])

	cpMap := map[string]func(string) error{
		"fwmark":      cp.ParseFirewallMark,
		"listen-port": cp.ParseListenPort,
		"private-key": cp.ParsePrivateKeyFromFile,
	}

	if args[0] == "peer" {
		if len(args) < 2 {
			return nil, errInvalid
		}

		pc := wgtypes.PeerConfig{}
		pcp := peerConfigParser{Cfg: &pc}

		if err := pcp.ParsePublicKey(args[1]); err != nil {
			return nil, fmt.Errorf("error parsing peer key: %w", err)
		}

		args = args[2:]
		var done bool
		var err error
		for !done && len(args) > 0 {
			if args, done, err = parseOnePeerConfigValue(args, pcp); err != nil {
				return nil, err
			}
		}

		cp.Cfg.Peers = append(cp.Cfg.Peers, pc)
	} else {
		parseFunc, ok := cpMap[args[0]]
		if !ok || len(args) < 2 {
			return nil, errInvalid
		}
		if err := parseFunc(args[1]); err != nil {
			return nil, fmt.Errorf("error parsing %s: %w", args[0], err)
		}
		args = args[2:]
	}

	return args, nil
}

func parseOnePeerConfigValue(args []string, pcp peerConfigParser) ([]string, bool, error) {
	done := false
	errInvalid := fmt.Errorf("invalid argument: %s", args[0])

	pcpMap := map[string]func(string) error{
		"allowed-ips":          pcp.ParseAllowedIPs,
		"endpoint":             pcp.ParseEndpoint,
		"persistent-keepalive": pcp.ParsePersistentKeepalive,
		"preshared-key":        pcp.ParsePresharedKeyFromFile,
	}

	switch args[0] {
	case "remove":
		pcp.Cfg.Remove = true
		args = args[1:]

	case "peer":
		done = true

	default:
		parseFunc, ok := pcpMap[args[0]]
		if !ok || len(args) < 2 {
			return nil, false, errInvalid
		}
		if err := parseFunc(args[1]); err != nil {
			return nil, false, fmt.Errorf("error parsing %s: %w", args[0], err)
		}
		args = args[2:]
	}

	return args, done, nil
}

func cmdPkcs11Key(args []string) error {
	
	c, err := net.Dial(
		"unix",
		filepath.Join("/var/run/wireguard-fips", fmt.Sprintf("%s.sock", args[0])),
	)
	if err != nil {
		return err
	}

	if _, err := io.WriteString(c, fmt.Sprintf("set=1\npkcs11_key=%s\n\n", args[1])); err != nil {
		return err
	}

	buf := bufio.NewReader(c)
	line, _, err := buf.ReadLine()
	if err != nil {
		return err
	}
	if string(line) != "errno=0" {
		return fmt.Errorf("received error: %s", string(line))
	}

	return nil
}