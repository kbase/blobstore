package service

import (
	"context"
	"net/http"
	"crypto/tls"

	"github.com/aws/aws-sdk-go/service/s3"

	"github.com/aws/aws-sdk-go/aws"

	"github.com/aws/aws-sdk-go/aws/credentials"

	"github.com/aws/aws-sdk-go/aws/session"

	"github.com/kbase/blobstore/core"
	"github.com/kbase/blobstore/filestore"

	"github.com/kbase/blobstore/nodestore"

	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/kbase/blobstore/auth"
	authcache "github.com/kbase/blobstore/auth/cache"
	"github.com/kbase/blobstore/config"
	"github.com/minio/minio-go"

	"go.mongodb.org/mongo-driver/mongo"
)

// Most of the error conditions are a real pain to test.

// Dependencies contain the built dependencies of the blobstore service.
type Dependencies struct {
	AuthCache *authcache.Cache
	BlobStore *core.BlobStore
}

// ConstructDependencies builds the blobstore dependencies from a configuration.
func constructDependencies(cfg *config.Config) (*Dependencies, error) {
	d := Dependencies{}
	auth, err := buildAuth(cfg)
	if err != nil {
		return nil, err
	}
	d.AuthCache = auth
	ns, err := buildNodeStore(cfg)
	if err != nil {
		return nil, err
	}
	fs, err := buildFileStore(cfg)
	if err != nil {
		return nil, err
	}
	d.BlobStore = core.New(fs, ns)
	return &d, nil
}

func buildFileStore(cfg *config.Config) (filestore.FileStore, error) {
	trueref := true

	sess := session.Must(session.NewSession())
	creds := credentials.NewStaticCredentials(cfg.S3AccessKey, cfg.S3AccessSecret, "")

	// need a custom transport to support not verifying SSL cert
	customTransport := &http.Transport{
	    TLSClientConfig: &tls.Config{InsecureSkipVerify: &cfg.S3DisableSSLVerify},
        }

	awscli := s3.New(sess, &aws.Config{
		Credentials:      creds,
		Endpoint:         &cfg.S3Host,
		Region:           &cfg.S3Region,
		DisableSSL:       &cfg.S3DisableSSL,
		S3ForcePathStyle: &trueref}) // minio pukes otherwise

	minioClient, err := minio.NewWithRegion(
		cfg.S3Host, cfg.S3AccessKey, cfg.S3AccessSecret, !cfg.S3DisableSSL, cfg.S3Region)
        minioClient.SetCustomTransport(customTransport)
	
	if err != nil {
		return nil, err
	}
	return filestore.NewS3FileStore(awscli, minioClient, cfg.S3Bucket)
}

func buildNodeStore(cfg *config.Config) (nodestore.NodeStore, error) {
	copts := options.ClientOptions{Hosts: []string{cfg.MongoHost}}
	if cfg.MongoUser != "" {
		creds := options.Credential{
			Username:   cfg.MongoUser,
			Password:   cfg.MongoPwd,
			AuthSource: cfg.MongoDatabase}
		copts.SetAuth(creds)
	}
	err := copts.Validate()
	if err != nil {
		return nil, err
	}
	client, err := mongo.Connect(context.Background(), &copts)
	if err != nil {
		return nil, err
	}
	db := client.Database(cfg.MongoDatabase)
	return nodestore.NewMongoNodeStore(db)
}

func buildAuth(cfg *config.Config) (*authcache.Cache, error) {
	roles := []func(*auth.KBaseProvider) error{}
	for _, r := range *cfg.AuthAdminRoles {
		roles = append(roles, auth.AdminRole(r))
	}
	prov, err := auth.NewKBaseProvider(*cfg.AuthURL, roles...)
	if err != nil {
		return nil, err
	}
	return authcache.NewCache(prov), nil
}
