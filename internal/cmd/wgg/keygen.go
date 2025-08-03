package wgg

import (
	"bufio"
	"fmt"
	"os"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func cmdGenPSK(args []string) error {
	k, err := wgtypes.GeneratePresharedKey()
	if err != nil {
		return fmt.Errorf("error generating key: %w", err)
	}
	fmt.Println(k)
	return nil
}

func cmdGenKey(args []string) error {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("error generating key: %w", err)
	}
	fmt.Println(k)
	return nil
}

func cmdGenPubKeyFromStdin(args []string) error {
	sc := bufio.NewScanner(os.Stdin)
	sc.Scan()
	if err := sc.Err(); err != nil {
		return fmt.Errorf("error reading from stdin: %w", err)
	}
	k, err := wgtypes.ParsePrivateKey(sc.Text())
	if err != nil {
		return fmt.Errorf("error parsing input key: %w", err)
	}
	fmt.Println(k.PublicKey())
	return nil
}
