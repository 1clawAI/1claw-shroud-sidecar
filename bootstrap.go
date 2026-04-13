package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type BootstrapConfig struct {
	MasterAPIKey string
	BaseURL      string
	VaultName    string
	AgentName    string
	PolicyPath   string
	ShroudEnable bool
	StateFile    string
}

type ProvisionState struct {
	VaultID     string `json:"vault_id"`
	AgentID     string `json:"agent_id"`
	AgentAPIKey string `json:"agent_api_key"`
	VaultName   string `json:"vault_name"`
	AgentName   string `json:"agent_name"`
	CreatedAt   string `json:"created_at"`
}

func loadBootstrapConfig() *BootstrapConfig {
	masterKey := os.Getenv("ONECLAW_MASTER_API_KEY")
	if masterKey == "" {
		return nil
	}

	stateFile := os.Getenv("ONECLAW_STATE_FILE")
	if stateFile == "" {
		home, _ := os.UserHomeDir()
		if home == "" {
			home = "/tmp"
		}
		stateFile = filepath.Join(home, ".1claw", "shroud-sidecar-state.json")
	}

	return &BootstrapConfig{
		MasterAPIKey: masterKey,
		BaseURL:      strings.TrimRight(envOr("ONECLAW_BASE_URL", "https://api.1claw.xyz"), "/"),
		VaultName:    envOr("ONECLAW_VAULT_NAME", "shroud-sidecar"),
		AgentName:    envOr("ONECLAW_AGENT_NAME", "shroud-sidecar-agent"),
		PolicyPath:   envOr("ONECLAW_POLICY_PATH", "**"),
		ShroudEnable: true,
		StateFile:    stateFile,
	}
}

func loadStateFile(path string) (*ProvisionState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state ProvisionState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	if state.AgentID == "" || state.AgentAPIKey == "" {
		return nil, fmt.Errorf("state file missing required fields")
	}
	return &state, nil
}

func saveStateFile(path string, state *ProvisionState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func bootstrap(cfg *BootstrapConfig) (*ProvisionState, error) {
	if state, err := loadStateFile(cfg.StateFile); err == nil {
		fmt.Printf("[bootstrap] Loaded existing state from %s (agent %s)\n", cfg.StateFile, state.AgentID[:8]+"...")
		return state, nil
	}

	client := &http.Client{Timeout: 30 * time.Second}

	fmt.Println("[bootstrap] Authenticating with master API key...")
	jwt, err := apiKeyAuth(client, cfg.BaseURL, cfg.MasterAPIKey)
	if err != nil {
		return nil, fmt.Errorf("auth failed: %w", err)
	}
	fmt.Println("[bootstrap] Authenticated")

	fmt.Printf("[bootstrap] Resolving vault '%s'...\n", cfg.VaultName)
	vaultID, err := resolveOrCreateVault(client, cfg.BaseURL, jwt, cfg.VaultName)
	if err != nil {
		return nil, fmt.Errorf("vault creation failed: %w", err)
	}
	fmt.Printf("[bootstrap] Vault: %s\n", vaultID)

	fmt.Printf("[bootstrap] Creating agent '%s' (shroud_enabled: true)...\n", cfg.AgentName)
	agentID, agentKey, err := createAgent(client, cfg.BaseURL, jwt, cfg.AgentName, vaultID, cfg.ShroudEnable)
	if err != nil {
		return nil, fmt.Errorf("agent creation failed: %w", err)
	}
	fmt.Printf("[bootstrap] Agent: %s (key: %s...)\n", agentID, agentKey[:12])

	fmt.Printf("[bootstrap] Creating access policy (path: %s)...\n", cfg.PolicyPath)
	if err := createPolicy(client, cfg.BaseURL, jwt, vaultID, agentID, cfg.PolicyPath); err != nil {
		return nil, fmt.Errorf("policy creation failed: %w", err)
	}
	fmt.Println("[bootstrap] Policy created")

	state := &ProvisionState{
		VaultID:     vaultID,
		AgentID:     agentID,
		AgentAPIKey: agentKey,
		VaultName:   cfg.VaultName,
		AgentName:   cfg.AgentName,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	}

	if err := saveStateFile(cfg.StateFile, state); err != nil {
		fmt.Printf("[bootstrap] WARNING: Could not save state to %s: %v\n", cfg.StateFile, err)
	} else {
		fmt.Printf("[bootstrap] State saved to %s\n", cfg.StateFile)
	}

	return state, nil
}

func teardown(cfg *BootstrapConfig) error {
	state, err := loadStateFile(cfg.StateFile)
	if err != nil {
		fmt.Printf("[teardown] No state file at %s — nothing to clean up\n", cfg.StateFile)
		return nil
	}

	client := &http.Client{Timeout: 30 * time.Second}

	fmt.Println("[teardown] Authenticating...")
	jwt, err := apiKeyAuth(client, cfg.BaseURL, cfg.MasterAPIKey)
	if err != nil {
		return fmt.Errorf("auth failed: %w", err)
	}

	fmt.Printf("[teardown] Deleting agent %s...\n", state.AgentID)
	if err := deleteResource(client, cfg.BaseURL, jwt, "/v1/agents/"+state.AgentID); err != nil {
		fmt.Printf("[teardown] WARNING: Agent delete failed: %v\n", err)
	} else {
		fmt.Println("[teardown] Agent deleted")
	}

	destroyVault := os.Getenv("ONECLAW_AUTO_DESTROY_VAULT") == "true"
	if destroyVault {
		fmt.Printf("[teardown] Deleting vault %s...\n", state.VaultID)
		if err := deleteResource(client, cfg.BaseURL, jwt, "/v1/vaults/"+state.VaultID); err != nil {
			fmt.Printf("[teardown] WARNING: Vault delete failed: %v\n", err)
		} else {
			fmt.Println("[teardown] Vault deleted")
		}
	} else {
		fmt.Printf("[teardown] Vault %s retained (set ONECLAW_AUTO_DESTROY_VAULT=true to delete)\n", state.VaultID)
	}

	os.Remove(cfg.StateFile)
	fmt.Println("[teardown] Cleanup complete")
	return nil
}

// --- API helpers ---

func apiKeyAuth(client *http.Client, baseURL, apiKey string) (string, error) {
	body, _ := json.Marshal(map[string]string{"api_key": apiKey})
	resp, err := client.Post(baseURL+"/v1/auth/api-key-token", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(data))
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return "", err
	}
	return result.AccessToken, nil
}

func resolveOrCreateVault(client *http.Client, baseURL, jwt, name string) (string, error) {
	body, _ := json.Marshal(map[string]string{
		"name":        name,
		"description": "Auto-provisioned by shroud-sidecar",
	})

	req, _ := http.NewRequest("POST", baseURL+"/v1/vaults", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)

	if resp.StatusCode/100 == 2 {
		var result struct {
			ID string `json:"id"`
		}
		json.Unmarshal(data, &result)
		return result.ID, nil
	}

	fmt.Printf("[bootstrap] Vault create returned %d — searching for existing '%s'\n", resp.StatusCode, name)

	req, _ = http.NewRequest("GET", baseURL+"/v1/vaults", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)

	resp, err = client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ = io.ReadAll(resp.Body)

	var list struct {
		Vaults []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"vaults"`
	}
	json.Unmarshal(data, &list)

	for _, v := range list.Vaults {
		if v.Name == name {
			return v.ID, nil
		}
	}
	return "", fmt.Errorf("no vault named '%s' found and create failed", name)
}

func createAgent(client *http.Client, baseURL, jwt, name, vaultID string, shroud bool) (string, string, error) {
	payload := map[string]interface{}{
		"name":            name,
		"vault_ids":       []string{vaultID},
		"shroud_enabled":  shroud,
		"description":     "Auto-provisioned by shroud-sidecar",
	}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", baseURL+"/v1/agents", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)

	if resp.StatusCode/100 != 2 {
		return "", "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(data))
	}

	var result struct {
		Agent struct {
			ID string `json:"id"`
		} `json:"agent"`
		APIKey string `json:"api_key"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return "", "", err
	}
	if result.APIKey == "" {
		return "", "", fmt.Errorf("agent created but no API key returned")
	}
	return result.Agent.ID, result.APIKey, nil
}

func createPolicy(client *http.Client, baseURL, jwt, vaultID, agentID, pathPattern string) error {
	payload := map[string]interface{}{
		"secret_path_pattern": pathPattern,
		"principal_type":      "agent",
		"principal_id":        agentID,
		"permissions":         []string{"read", "write"},
	}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", baseURL+"/v1/vaults/"+vaultID+"/policies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(data))
	}
	return nil
}

func deleteResource(client *http.Client, baseURL, jwt, path string) error {
	req, _ := http.NewRequest("DELETE", baseURL+path, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(data))
	}
	return nil
}
