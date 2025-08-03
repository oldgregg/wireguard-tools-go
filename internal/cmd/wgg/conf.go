package wgg

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/go-ini/ini"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var iniLoadOptions = ini.LoadOptions{
	AllowNonUniqueSections: true,
}

func init() {
	ini.PrettyFormat = false
	ini.PrettyEqual = true
}

func cmdShowConf(args []string) error {
	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}
	defer c.Close()

	name := args[0]
	d, err := c.Device(name)
	if err != nil {
		return fmt.Errorf("error getting device %s: %w", name, err)
	}

	conf := ini.Empty(iniLoadOptions)

	// Ignore errors
	sec, _ := conf.NewSection("Interface")
	if d.ListenPort != 0 {
		sec.NewKey("ListenPort", strconv.Itoa(d.ListenPort))
	}
	if d.FirewallMark != 0 {
		sec.NewKey("FwMark", fmt.Sprintf("0x%x", d.FirewallMark))
	}
	if !keyIsZero(d.PrivateKey[:]) {
		sec.NewKey("PrivateKey", d.PrivateKey.String())
	}

	for _, p := range d.Peers {
		sec, _ = conf.NewSection("Peer")
		sec.NewKey("PublicKey", p.PublicKey.String())
		if !keyIsZero(p.PresharedKey[:]) {
			sec.NewKey("PresharedKey", p.PresharedKey.String())
		}

		ips := make([]string, 0, len(p.AllowedIPs))
		for _, ip := range p.AllowedIPs {
			ips = append(ips, ip.String())
		}
		if len(ips) > 0 {
			sec.NewKey("AllowedIPs", strings.Join(ips, ", "))
		}

		if p.Endpoint != nil {
			sec.NewKey("Endpoint", p.Endpoint.String())
		}
		if p.PersistentKeepaliveInterval != 0 {
			val := fmt.Sprintf("%.0f", p.PersistentKeepaliveInterval.Seconds())
			sec.NewKey("PersistentKeepalive", val)
		}
	}

	if _, err := conf.WriteTo(os.Stdout); err != nil {
		return fmt.Errorf("error writing config to stdout: %w", err)
	}
	return nil
}

func cmdSetConf(args []string) error {
	// Reset all existing attributes, if any
	zero := 0
	return setConf(args, wgtypes.Config{
		PrivateKey:   &wgtypes.PrivKey{},
		ListenPort:   &zero,
		FirewallMark: &zero,
		ReplacePeers: true,
	})
}

func cmdAddConf(args []string) error {
	// Keep existing attributes
	return setConf(args, wgtypes.Config{})
}

func cmdSyncConf(args []string) error {
	name := args[0]
	configFile := args[1]

	cfg := wgtypes.Config{}
	cp := configParser{Cfg: &cfg}
	if err := parseINI(configFile, cp); err != nil {
		return err
	}

	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}
	defer c.Close()

	dev, err := c.Device(name)
	if err != nil {
		return fmt.Errorf("error getting device %s: %w", name, err)
	}

	// Remove peers that are present on the device but not in loaded config.
	// Original algorithm:
	// https://git.zx2c4.com/wireguard-tools/tree/src/setconf.c?id=b4f6b4f229d291daf7c35c6f1e7f4841cc6d69bc#n30
	peers := make(map[wgtypes.PubKey]bool)
	for _, p := range dev.Peers {
		peers[p.PublicKey] = false
	}
	for _, p := range cfg.Peers {
		peers[p.PublicKey] = true
	}
	for key, fromCfg := range peers {
		if !fromCfg {
			cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{
				PublicKey: key,
				Remove:    true,
			})
		}
	}

	if err := c.ConfigureDevice(name, cfg); err != nil {
		return fmt.Errorf("error configuring device %s: %w", name, err)
	}
	return nil
}

func setConf(args []string, cfg wgtypes.Config) error {
	name := args[0]
	configFile := args[1]

	cp := configParser{Cfg: &cfg}
	if err := parseINI(configFile, cp); err != nil {
		return err
	}

	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}
	defer c.Close()

	if err := c.ConfigureDevice(name, cfg); err != nil {
		return fmt.Errorf("error configuring device %s: %w", name, err)
	}
	return nil
}

func parseINI(file string, cp configParser) error {
	conf, err := ini.LoadSources(iniLoadOptions, file)
	if err != nil {
		return fmt.Errorf("error loading config: %w", err)
	}

	parseError := func(field, reason string) error {
		return fmt.Errorf("error parsing %s: %s", field, reason)
	}

	secs, err := conf.SectionsByName("Interface")
	if err != nil {
		return parseError("Interface", err.Error())
	}
	if len(secs) != 1 {
		return parseError("Interface", "more than one Interface section")
	}

	cpMap := map[string]func(string) error{
		"FwMark":     cp.ParseFirewallMark,
		"ListenPort": cp.ParseListenPort,
		"PrivateKey": cp.ParsePrivateKey,
	}
	for _, k := range secs[0].Keys() {
		parseFunc, ok := cpMap[k.Name()]
		if !ok {
			return parseError(k.Name(), "unknown field")
		}
		if err := parseFunc(k.String()); err != nil {
			return parseError(k.Name(), err.Error())
		}
	}
	if cp.Cfg.PrivateKey == nil {
		return parseError("PrivateKey", "required field")
	}

	secs, err = conf.SectionsByName("Peer")
	if err != nil {
		return parseError("Peer", err.Error())
	}

	for _, sec := range secs {
		pc := wgtypes.PeerConfig{}
		pcp := peerConfigParser{Cfg: &pc}
		pcpMap := map[string]func(string) error{
			"AllowedIPs":          pcp.ParseAllowedIPs,
			"Endpoint":            pcp.ParseEndpoint,
			"PersistentKeepalive": pcp.ParsePersistentKeepalive,
			"PresharedKey":        pcp.ParsePresharedKey,
			"PublicKey":           pcp.ParsePublicKey,
		}
		for _, k := range sec.Keys() {
			parseFunc, ok := pcpMap[k.Name()]
			if !ok {
				return parseError(k.Name(), "unknown field")
			}
			if err := parseFunc(k.String()); err != nil {
				return parseError(k.Name(), err.Error())
			}
		}
		if keyIsZero(pc.PublicKey[:]) {
			return parseError("PublicKey", "required field")
		}
		cp.Cfg.Peers = append(cp.Cfg.Peers, pc)
	}

	return nil
}
