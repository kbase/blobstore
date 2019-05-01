package miniocontroller

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/google/uuid"
	"github.com/phayes/freeport"
)

// Params are Parameters for creating a Minio controller.
type Params struct {
	// ExecutablePath is the path of the minio executable.
	ExecutablePath string
	// AccessKey is the access key to set for the Minio server.
	AccessKey string
	// SecretKey is the secret key to set for the Minio server.
	SecretKey string
	// RootTempDir is where temporary files should be placed.
	RootTempDir string
}

// Controller is a Minio controller.
type Controller struct {
	port      int
	tempDir   string
	accessKey string
	secretKey string
	cmd       *exec.Cmd
}

// New creates a new controller.
func New(p Params) (*Controller, error) {
	//TODO check executable path is valid and is executable
	tdir := filepath.Join(p.RootTempDir, "MinioController-"+uuid.New().String())
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
	cmd := exec.Command(
		p.ExecutablePath,
		"server",
		"--address", "localhost:"+strconv.Itoa(port),
		ddir)
	cmd.Env = append(
		os.Environ(),
		"MINIO_ACCESS_KEY="+p.AccessKey,
		"MINIO_SECRET_KEY="+p.SecretKey)
	cmd.Stdout = outfile
	cmd.Stderr = outfile
	err = cmd.Start()
	if err != nil {
		return nil, err
	}
	// at 100ms, sometimes s3.S3.CreateBucket() hangs forever.
	// at 200, sometimes gets connection refused.
	time.Sleep(500 * time.Millisecond) // wait for server to start

	return &Controller{port, tdir, p.AccessKey, p.SecretKey, cmd}, nil
}

// GetPort returns the port on which Minio is listening.
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

// CreateS3Client creates a Amazon S3 client pointed at the minio instance.
//
// region sets the region to use - e.g. "us-west-1".
func (c *Controller) CreateS3Client(region string) *s3.S3 {
	trueref := true
	endpoint := "localhost:" + strconv.Itoa(c.port)

	sess := session.Must(session.NewSession())
	creds := credentials.NewStaticCredentials(c.accessKey, c.secretKey, "")
	return s3.New(sess, &aws.Config{
		Credentials:      creds,
		Endpoint:         &endpoint,
		Region:           &region,
		DisableSSL:       &trueref,
		S3ForcePathStyle: &trueref}) // minio pukes otherwise
}

//TODO destroy all buckets
