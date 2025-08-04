package wgg

import (
	"math"
)

type errUsage string

func (e errUsage) Error() string {
	return "Usage: " + string(e)
}

const (
	usage     = "wg <cmd> [args]"
	usageShow = "wg show { <interface> | all | interfaces } [public-key | private-key | listen-port | fwmark | peers | preshared-keys | endpoints | allowed-ips | latest-handshakes | transfer | persistent-keepalive | dump]"
	usageSet  = "wg set <interface> [listen-port <port>] [fwmark <mark>] [private-key <file path>] [peer <base64 public key> [remove] [preshared-key <file path>] [endpoint <ip>:<port>] [persistent-keepalive <interval seconds>] [allowed-ips <ip1>/<cidr1>[,<ip2>/<cidr2>]...] ]..."
)

type command struct {
	Func        func([]string) error
	Usage       errUsage
	MinNArgs    int
	MaxNArgs    int
	Subcommands map[string]*command
}

var commandRoot = &command{
	Func:  cmdShowAll,
	Usage: usage,
	Subcommands: map[string]*command{
		"show": {
			Func:     cmdShowOne,
			Usage:    usageShow,
			MaxNArgs: 2,
			Subcommands: map[string]*command{
				"all": {
					Func:     cmdShowAll,
					Usage:    usageShow,
					MaxNArgs: 1,
				},
				"interfaces": {
					Func:  cmdShowInterfaces,
					Usage: usageShow,
				},
			},
		},
		"showconf": {
			Func:     cmdShowConf,
			Usage:    "wg showconf <interface>",
			MinNArgs: 1,
			MaxNArgs: 1,
		},
		"set": {
			Func:     cmdSet,
			Usage:    usageSet,
			MinNArgs: 2,
			MaxNArgs: math.MaxInt,
		},
		"setconf": {
			Func:     cmdSetConf,
			Usage:    "wg setconf <interface> <configuration filename>",
			MinNArgs: 2,
			MaxNArgs: 2,
		},
		"addconf": {
			Func:     cmdAddConf,
			Usage:    "wg addconf <interface> <configuration filename>",
			MinNArgs: 2,
			MaxNArgs: 2,
		},
		"syncconf": {
			Func:     cmdSyncConf,
			Usage:    "wg syncconf <interface> <configuration filename>",
			MinNArgs: 2,
			MaxNArgs: 2,
		},
		"genkey": {
			Func:  cmdGenKey,
			Usage: "wg genkey",
		},
		"genpsk": {
			Func:  cmdGenPSK,
			Usage: "wg genpsk",
		},
		"pubkey": {
			Func:  cmdGenPubKeyFromStdin,
			Usage: "wg pubkey",
		},

		"pkcs11key": {
			Func:  cmdPkcs11Key,
			Usage: "wg pkcs11key <interface> <pkcs11 uri>",
			MinNArgs: 2,
			MaxNArgs: 2,
		},
	},
}

func Main(args []string) error {
	cmd := commandRoot
	for len(args) > 0 {
		if args[0] == "--help" {
			return cmd.Usage
		}

		var match *command
		for k, v := range cmd.Subcommands {
			if k == args[0] {
				match = v
				break
			}
		}
		if match != nil {
			cmd = match
			args = args[1:]
			continue
		}

		break
	}

	if len(args) < cmd.MinNArgs || len(args) > cmd.MaxNArgs {
		return cmd.Usage
	}

	return cmd.Func(args)
}
