package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// CommandKeyStore delegates the narrow native-key write boundary to a separately
// permissioned helper. Credentials travel only over stdin, never argv or logs.
type CommandKeyStore struct{ helperPath string }

func NewCommandKeyStore(helperPath string) *CommandKeyStore {
	return &CommandKeyStore{helperPath: helperPath}
}

type keyStoreRequest struct {
	Operation  string         `json:"operation"`
	Record     ManagedRecord  `json:"record"`
	Credential string         `json:"credential"`
	Fields     map[string]any `json:"fields,omitempty"`
}

type keyStoreResponse struct {
	OK   bool      `json:"ok"`
	Kind string    `json:"kind"`
	Key  NativeKey `json:"key"`
}

type keyStoreBuffer struct{ bytes.Buffer }

func (b *keyStoreBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 65536 {
		return 0, io.ErrShortBuffer
	}
	return b.Buffer.Write(p)
}

func (s *CommandKeyStore) execute(ctx context.Context, request keyStoreRequest) (keyStoreResponse, error) {
	var response keyStoreResponse
	if !filepath.IsAbs(s.helperPath) {
		return response, managerError(503, "独立 Key 存储尚未配置")
	}
	data, err := json.Marshal(request)
	if err != nil || len(data) > 16384 {
		return response, managerError(400, "独立 Key 参数无效")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/python3", "-I", s.helperPath)
	command.Env = []string{"LANG=C.UTF-8", "TZ=Asia/Shanghai", "PYTHONDONTWRITEBYTECODE=1"}
	for _, variable := range []string{"KEY_MANAGEMENT_PG_DSN", "KEY_MANAGEMENT_REDIS_HOST",
		"KEY_MANAGEMENT_REDIS_PORT", "KEY_MANAGEMENT_REDIS_USERNAME",
		"KEY_MANAGEMENT_REDIS_PASSWORD", "KEY_MANAGEMENT_REDIS_DB"} {
		if value, exists := os.LookupEnv(variable); exists {
			command.Env = append(command.Env, variable+"="+value)
		}
	}
	command.Stdin = bytes.NewReader(data)
	var output keyStoreBuffer
	command.Stdout, command.Stderr = &output, io.Discard
	runErr := command.Run()
	if json.Unmarshal(output.Bytes(), &response) != nil || !response.OK || runErr != nil {
		if response.Kind == "conflict" {
			return keyStoreResponse{}, managerError(409, "独立用户或 Key 身份发生变化，已停止写入")
		}
		return keyStoreResponse{}, managerError(503, "独立 Key 存储或认证缓存暂时不可用，请重试原操作")
	}
	return response, nil
}

func (s *CommandKeyStore) Check(ctx context.Context) error {
	_, err := s.execute(ctx, keyStoreRequest{Operation: "check"})
	return err
}

func (s *CommandKeyStore) Create(ctx context.Context, record ManagedRecord, credential string) (NativeKey, error) {
	response, err := s.execute(ctx, keyStoreRequest{Operation: "create", Record: record, Credential: credential})
	if err != nil {
		return NativeKey{}, err
	}
	if response.Key.ID <= 0 || response.Key.UserID != record.UserID || response.Key.Key != credential ||
		(record.KeyID > 0 && response.Key.ID != record.KeyID) {
		return NativeKey{}, managerError(503, "独立 Key 创建结果未确认，请重试原批次")
	}
	return response.Key, nil
}

func (s *CommandKeyStore) Update(ctx context.Context, record ManagedRecord, credential string, fields map[string]any) error {
	_, err := s.execute(ctx, keyStoreRequest{Operation: "update", Record: record, Credential: credential, Fields: fields})
	return err
}
