package mongocontroller

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/phayes/freeport"
)

// Params are Parameters for creating a MongoDB controller.
type Params struct {
	// ExecutablePath is the path of the mongodb executable.
	ExecutablePath string
	// RootTempDir is where temporary files should be placed.
	RootTempDir string
	// UseWiredTiger determines whether the wired tiger storage engine should be used. By default
	// it is not used.
	UseWiredTiger bool
}

// Controller is a Minio controller.
type Controller struct {
	port    int
	tempDir string
	cmd     *exec.Cmd
}

// New creates a new controller.
func New(p Params) (*Controller, error) {
	//TODO check executable path is valid and is executable
	tdir := filepath.Join(p.RootTempDir, "MongoController-"+uuid.New().String())
	ddir := filepath.Join(tdir, "data")
	err := os.MkdirAll(ddir, 0700)
	if err != nil {
		return nil, err
	}
	outfile, err := os.Create(filepath.Join(tdir, "output.txt"))
	if err != nil {
		return nil, err
	}
	port, err := freeport.GetFreePort()
	if err != nil {
		return nil, err
	}
	cmdargs := []string{
		"--port", strconv.Itoa(port),
		"--dbpath", ddir,
		"--nojournal",
	}
	if p.UseWiredTiger {
		cmdargs = append(cmdargs, "--storageEngine", "wiredTiger")
	}
	cmd := exec.Command(p.ExecutablePath, cmdargs...)
	cmd.Stdout = outfile
	cmd.Stderr = outfile
	err = cmd.Start()
	if err != nil {
		return nil, err
	}
	time.Sleep(500 * time.Millisecond) // wait for server to start

	return &Controller{port, tdir, cmd}, nil
}

// GetPort returns the port on which MongoDB is listening.
func (c *Controller) GetPort() int {
	return c.port
}

// Destroy destroys the controller. If deleteTempDir is true, all files created by the controller
// will be removed.
func (c *Controller) Destroy(deleteTempDir bool) error {
	err := c.cmd.Process.Kill()
	if err != nil {
		return err
	}
	c.cmd.Wait()
	if err != nil {
		return err
	}
	if deleteTempDir {
		os.RemoveAll(c.tempDir)
	}
	return nil
}
