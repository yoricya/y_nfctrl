package main

import (
	"fmt"
	"os"
	"y_nfctrl/internal/knockerModule"
)

func main() {
	cfg, err := loadConfig()

	// Load cfg
	if err != nil {
		fmt.Println("Config not found")

		cfg = &Config{}
		fmt.Print("Enter Server Address (e.g. 1.2.3.4:1234): ")
		fmt.Scanln(&cfg.Addr)

		fmt.Print("Enter Secret Key: ")
		fmt.Scanln(&cfg.Key)

		if err := saveConfig(*cfg); err != nil {
			fmt.Println("Failed to save config:", err)
			fmt.Println("Press any key to exit")
			WaitUserAndExit(1)
		}

		fmt.Println("Config saved to:", getConfigPath())
	}

	// Read OpCode
	var code = 12
	fmt.Printf("Using server: %s\n", cfg.Addr)
	fmt.Print("OpCode values:\n    0 - Disallow your IP\n    12 - Allow your IP\n    9 - Exit (Relaunch) server side NfCtrl app\n    -1 - Reset client config")
	fmt.Print("Enter OpCode (Default 12): ")

	fmt.Scanln(&code)

	if code == -2 {
		fmt.Println("Config file path:", getConfigPath())
		WaitUserAndExit(0)
	}

	if code == -1 {
		err := os.Remove(getConfigPath())
		if err != nil {
			fmt.Println("Failed to remove config:", err)
			WaitUserAndExit(1)
		}

		fmt.Println("Client config reset successfully")
		WaitUserAndExit(0)
	}

	client := knockerModule.New(cfg.Addr, cfg.Key, nil, nil)
	err = client.KnockKnock(byte(code))

	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("Knock sent successfully!")
	}

	WaitUserAndExit(0)
}

func WaitUserAndExit(code int) {
	fmt.Println("\nPress any key to exit")
	fmt.Scanln()
	os.Exit(code)
}
