package wgg

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type configParser struct {
	Cfg *wgtypes.Config
}

func (cp configParser) ParsePrivateKey(s string) error {
	key, err := wgtypes.ParsePrivateKey(s)
	if err != nil {
		return err
	}
	cp.Cfg.PrivateKey = &key
	return nil
}

func (cp configParser) ParsePrivateKeyFromFile(file string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		// An empty file clears the key.
		cp.Cfg.PrivateKey = &wgtypes.PrivKey{}
		return nil
	}
	return cp.ParsePrivateKey(strings.TrimSpace(string(data)))
}

func (cp configParser) ParseListenPort(s string) error {
	port, err := strconv.Atoi(s)
	if err != nil {
		return err
	}
	cp.Cfg.ListenPort = &port
	return nil
}

func (cp configParser) ParseFirewallMark(s string) error {
	fwmark := 0
	// "off" is equivalent to 0
	if s != "off" {
		i64, err := strconv.ParseInt(s, 0, 0)
		if err != nil {
			return err
		}
		fwmark = int(i64)
	}
	cp.Cfg.FirewallMark = &fwmark
	return nil
}

type peerConfigParser struct {
	Cfg *wgtypes.PeerConfig
}

func (pcp peerConfigParser) ParsePublicKey(s string) error {
	var err error
	pcp.Cfg.PublicKey, err = wgtypes.ParsePubKey(s)
	return err
}

func (pcp peerConfigParser) ParseAllowedIPs(s string) error {
	pcp.Cfg.ReplaceAllowedIPs = true
	if s == "" {
		return nil
	}

	for _, ipmask := range strings.Split(s, ",") {
		ipmask = strings.TrimSpace(ipmask)

		// Add all-ones mask if no mask is specified.
		if !strings.Contains(ipmask, "/") {
			if strings.Contains(ipmask, ":") {
				// IPv6
				ipmask += "/128"
			} else {
				// IPv4
				ipmask += "/32"
			}
		}

		ip, net, err := net.ParseCIDR(ipmask)
		if err != nil {
			return fmt.Errorf("error parsing CIDR: %w", err)
		}
		if !ip.Equal(net.IP) {
			return fmt.Errorf("AllowedIP has nonzero host part: %s", ipmask)
		}

		pcp.Cfg.AllowedIPs = append(pcp.Cfg.AllowedIPs, *net)
	}
	return nil
}

func (pcp peerConfigParser) ParsePresharedKey(s string) error {
	key, err := wgtypes.ParsePSK(s)
	if err != nil {
		return err
	}
	pcp.Cfg.PresharedKey = &key
	return nil
}

func (pcp peerConfigParser) ParsePresharedKeyFromFile(file string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		// An empty file clears the key.
		pcp.Cfg.PresharedKey = &wgtypes.PSK{}
		return nil
	}
	return pcp.ParsePresharedKey(strings.TrimSpace(string(data)))
}

func (pcp peerConfigParser) ParseEndpoint(s string) error {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		return err
	}
	pcp.Cfg.Endpoint = net.UDPAddrFromAddrPort(addr)
	return nil
}

func (pcp peerConfigParser) ParsePersistentKeepalive(s string) error {
	var pk time.Duration
	// "off" is equivalent to 0
	if s != "off" {
		i, err := strconv.Atoi(s)
		if err != nil {
			return err
		}
		pk = time.Duration(i) * time.Second
	}
	pcp.Cfg.PersistentKeepaliveInterval = &pk
	return nil
}
