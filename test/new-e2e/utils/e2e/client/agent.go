// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package client

import (
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DataDog/test-infra-definitions/datadog/agent"
	"github.com/cenkalti/backoff"
)

var _ clientService[agent.ClientData] = (*Agent)(nil)

// A client Agent that is connected to an agent.Installer defined in test-infra-definition.
type Agent struct {
	*UpResultDeserializer[agent.ClientData]
	*vmClient
}

// Create a new instance of Agent
func NewAgent(installer *agent.Installer) *Agent {
	agentInstance := &Agent{}
	agentInstance.UpResultDeserializer = NewUpResultDeserializer[agent.ClientData](installer, agentInstance)
	return agentInstance
}

//lint:ignore U1000 Ignore unused function as this function is call using reflection
func (agent *Agent) initService(t *testing.T, data *agent.ClientData) error {
	var err error
	agent.vmClient, err = newVMClient(t, "", &data.Connection)
	return err
}

func (agent *Agent) Version() string {
	return agent.vmClient.Execute("datadog-agent version")
}

func (agent *Agent) Config() string {
	return agent.vmClient.Execute("sudo datadog-agent config")
}

type Status struct {
	Content string
}

func newStatus(s string) *Status {
	return &Status{Content: s}
}

// isReady true if status contains a valid version
func (s *Status) isReady() (bool, error) {
	return regexp.MatchString("={15}\nAgent \\(v7\\.\\d{2}\\..*\n={15}", s.Content)
}

func (agent *Agent) Status() *Status {
	return newStatus(agent.vmClient.Execute("sudo datadog-agent status"))
}

// IsReady runs status command and returns true if the agent is ready
// Use this to wait for agent to be ready before running any command
func (a *Agent) IsReady() (bool, error) {
	return a.Status().isReady()
}

// WaitForReady blocks up for one minute waiting for agent to be ready
// Retries every 100 ms up to one minute
// Returns error on failure
func (a *Agent) WaitForReady() error {
	return a.WaitForReadyTimeout(1 * time.Minute)
}

// WaitForReady blocks up for timeout waiting for agent to be ready
// Retries every 100 ms up to timeout
// Returns error on failure
func (a *Agent) WaitForReadyTimeout(timeout time.Duration) error {
	interval := 100 * time.Millisecond
	maxRetries := timeout.Milliseconds() / interval.Milliseconds()
	err := backoff.Retry(func() error {
		isReady, err := a.IsReady()
		if err != nil {
			return err
		}
		if !isReady {
			return errors.New("agent not ready")
		}
		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(interval), uint64(maxRetries)))
	return err
}
