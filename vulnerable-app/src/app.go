package main

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

func main() {
	// 1. Hardcoded Secret (AI placeholder key)
	const apiKey = "sk-live-1234567890abcdef"
	fmt.Println("API Key loaded successfully")

	// 2. Swallowed Error (discarding http.Get error using blank identifier)
	resp, _ := http.Get("https://api.example.com")
	if resp != nil {
		defer resp.Body.Close()
	}

	// 3. Command Injection via Sprintf / operator +
	userInput := "127.0.0.1; rm -rf /"
	cmd := exec.Command("ping", "-c", "3", userInput) // Ok
	
	// Vulnerable Command Injection (Sprintf)
	badCmd := exec.Command("sh", "-c", fmt.Sprintf("ping -c 3 %s", userInput))
	badCmd.Run()

	// Vulnerable Command Injection (Operator +)
	badCmd2 := exec.Command("ping " + userInput)
	badCmd2.Run()

	// 4. SQL Injection via string formatting and operator +
	db, _ := sql.Open("sqlite3", "app.db")
	
	// Vulnerable SQL Injection (Sprintf)
	row := db.QueryRow(fmt.Sprintf("SELECT * FROM users WHERE id = %s", userInput))
	
	// Vulnerable SQL Injection (Operator +)
	rows, _ := db.Query("SELECT * FROM users WHERE name = '" + userInput + "'")
	if rows != nil {
		rows.Close()
	}

	// 5. Insecure TLS (InsecureSkipVerify: true)
	// We'll show an ignore comment here to demonstrate aegis-ignore feature!
	// aegis-ignore: ai-go-insecure-tls
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	client.Get("https://example.com")
	
	// This one is not ignored, so it will be reported:
	tr2 := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	tr2.MaxIdleConns = 10
}
