package process

import (
	"fmt"
	"time"

	"context"
	"github.com/moby/moby/client"
)

type docker struct {
	client        *client.Client
	containerName string
}

// NewDocker create a new docker process that manages a container
func NewDocker(containerName string) (Process, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, err
	}

	return docker{
		client:        cli,
		containerName: fmt.Sprintf("/%s", containerName),
	}, nil
}

func (proc docker) Start() error {
	containerID, err := proc.resolveContainerName()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	_, err = proc.client.ContainerStart(ctx, containerID, client.ContainerStartOptions{})
	return err
}

func (proc docker) Stop() error {
	containerID, err := proc.resolveContainerName()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	_, err = proc.client.ContainerStop(ctx, containerID, client.ContainerStopOptions{})
	return err
}

func (proc docker) IsRunning() (bool, error) {
	containerID, err := proc.resolveContainerName()
	if err != nil {
		return false, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	info, err := proc.client.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{})
	if err != nil {
		return false, err
	}

	return info.Container.State.Running, nil
}

func (proc docker) resolveContainerName() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	containers, err := proc.client.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return "", err
	}

	for _, container := range containers.Items {
		for _, name := range container.Names {
			if name != proc.containerName {
				continue
			}
			return container.ID, nil
		}
	}

	return "", fmt.Errorf("container with name \"%s\" not found", proc.containerName)
}
