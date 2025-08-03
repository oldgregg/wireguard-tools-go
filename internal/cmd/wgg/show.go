package wgg

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func cmdShowAll(args []string) error {
	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}
	defer c.Close()

	ds, err := c.Devices()
	if err != nil {
		return fmt.Errorf("error getting devices: %w", err)
	}

	if len(args) == 1 {
		for _, d := range ds {
			if err := printAttr(d, args[0], true); err != nil {
				return err
			}
		}
		return nil
	}

	for i, d := range ds {
		if i != 0 {
			fmt.Println("")
		}
		prettyPrint(d)
	}
	return nil
}

func cmdShowInterfaces(args []string) error {
	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}
	defer c.Close()

	ds, err := c.Devices()
	if err != nil {
		return fmt.Errorf("error getting devices: %w", err)
	}

	for _, d := range ds {
		fmt.Println(d.Name)
	}
	return nil
}

func cmdShowOne(args []string) error {
	if len(args) == 0 {
		return cmdShowAll(args)
	}

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

	if len(args) == 2 {
		return printAttr(d, args[1], false)
	}

	prettyPrint(d)
	return nil
}

func prettyPrint(d *wgtypes.Device) {
	s := fmt.Sprintf("interface: %s\n", d.Name)
	if !keyIsZero(d.PrivateKey[:]) {
		s += fmt.Sprintf("  public key: %s\n", d.PublicKey)
		s += "  private key: (hidden)\n"
	}
	if d.ListenPort != 0 {
		s += fmt.Sprintf("  listening port: %d\n", d.ListenPort)
	}
	if d.FirewallMark != 0 {
		s += fmt.Sprintf("  fwmark: 0x%x\n", d.FirewallMark)
	}
	fmt.Print(s)

	for _, p := range d.Peers {
		s := fmt.Sprintf("\npeer: %s\n", p.PublicKey)
		if !keyIsZero(p.PresharedKey[:]) {
			s += "  preshared key: (hidden)\n"
		}
		if p.Endpoint != nil {
			s += fmt.Sprintf("  endpoint: %s\n", p.Endpoint)
		}

		allowedIPs := make([]string, 0, len(p.AllowedIPs))
		for _, ip := range p.AllowedIPs {
			allowedIPs = append(allowedIPs, ip.String())
		}
		if len(allowedIPs) > 0 {
			s += fmt.Sprintf("  allowed ips: %s\n", strings.Join(allowedIPs, ", "))
		} else {
			s += "  allowed ips: (none)\n"
		}

		if !p.LastHandshakeTime.IsZero() {
			// TODO match wg output format
			ago := time.Since(p.LastHandshakeTime).Truncate(time.Second)
			s += fmt.Sprintf("  latest handshake: %s ago\n", ago)
		}
		if p.ReceiveBytes != 0 || p.TransmitBytes != 0 {
			// TODO match wg output format
			rx := fmt.Sprintf("%d B", p.ReceiveBytes)
			tx := fmt.Sprintf("%d B", p.TransmitBytes)
			s += fmt.Sprintf("  transfer: %s received, %s sent\n", rx, tx)
		}
		if p.PersistentKeepaliveInterval != 0 {
			// TODO match wg output format
			d := p.PersistentKeepaliveInterval.Truncate(time.Second)
			s += fmt.Sprintf("  persistent keepalive: every %s\n", d)
		}

		fmt.Print(s)
	}
}

func printAttr(d *wgtypes.Device, attr string, withIface bool) error {
	prefix := ""
	if withIface {
		prefix = d.Name + "\t"
	}

	switch attr {
	case "public-key":
		fmt.Printf("%s%s\n", prefix, maybeKey(d.PublicKey[:]))
	case "private-key":
		fmt.Printf("%s%s\n", prefix, maybeKey(d.PrivateKey[:]))
	case "listen-port":
		fmt.Printf("%s%d\n", prefix, d.ListenPort)
	case "fwmark":
		if d.FirewallMark == 0 {
			fmt.Printf("%soff\n", prefix)
		} else {
			fmt.Printf("%s0x%x\n", prefix, d.FirewallMark)
		}
	case "peers":
		for _, p := range d.Peers {
			fmt.Printf("%s%s\n", prefix, p.PublicKey)
		}
	case "preshared-keys":
		for _, p := range d.Peers {
			fmt.Printf("%s%s\t%s\n", prefix, p.PublicKey, maybeKey(p.PresharedKey[:]))
		}
	case "endpoints":
		for _, p := range d.Peers {
			if p.Endpoint == nil {
				fmt.Printf("%s%s\t(none)\n", prefix, p.PublicKey)
			} else {
				fmt.Printf("%s%s\t%s\n", prefix, p.PublicKey, p.Endpoint)
			}
		}
	case "allowed-ips":
		for _, p := range d.Peers {
			fmt.Printf("%s%s\t", prefix, p.PublicKey)
			if len(p.AllowedIPs) == 0 {
				fmt.Println("(none)")
				continue
			}
			ips := make([]any, 0, len(p.AllowedIPs))
			for _, ip := range p.AllowedIPs {
				ips = append(ips, ip.String())
			}
			fmt.Println(ips...)
		}
	case "latest-handshakes":
		for _, p := range d.Peers {
			if p.LastHandshakeTime.IsZero() {
				fmt.Printf("%s%s\t0\n", prefix, p.PublicKey)
			} else {
				fmt.Printf("%s%s\t%d\n", prefix, p.PublicKey, p.LastHandshakeTime.Unix())
			}
		}
	case "persistent-keepalive":
		for _, p := range d.Peers {
			if p.PersistentKeepaliveInterval == 0 {
				fmt.Printf("%s%s\toff\n", prefix, p.PublicKey)
			} else {
				fmt.Printf("%s%s\t%.0f\n", prefix, p.PublicKey, p.PersistentKeepaliveInterval.Seconds())
			}
		}
	case "transfer":
		for _, p := range d.Peers {
			fmt.Printf("%s%s\t%d\t%d\n", prefix, p.PublicKey, p.ReceiveBytes, p.TransmitBytes)
		}
	// TODO implement
	//case "dump":
	default:
		return fmt.Errorf("invalid parameter: %s", attr)
	}
	return nil
}

func maybeKey(key []byte) string {
	if keyIsZero(key) {
		return "(none)"
	}
	return base64.StdEncoding.EncodeToString(key)
}
