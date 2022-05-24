package solver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const globalTimeout = 5 * time.Second

type CustomDNSProviderSolver struct {
	client *kubernetes.Clientset
	logger *zap.Logger
}

func New(logger *zap.Logger) *CustomDNSProviderSolver {
	return &CustomDNSProviderSolver{logger: logger}
}

type customDNSProviderConfig struct {
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.
	KeyPrefix string `json:"keyPrefix"`
	Etcd      struct {
		User struct {
			Ref corev1.SecretKeySelector `json:"secretKeyRef"`
		} `json:"user"`
		Password struct {
			Ref corev1.SecretKeySelector `json:"secretKeyRef"`
		} `json:"password"`
		Endpoints []string `json:"endpoints"`
	} `json:"etcd"`
}

func (c *CustomDNSProviderSolver) Name() string {
	return "etcd"
}

// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *CustomDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	c.logger.Debug("enter solver Present", zap.String("type", "lifecycle"))
	defer c.logger.Debug("exit solver Present", zap.String("type", "lifecycle"))

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return fmt.Errorf("failed to parse solver config: %w", err)
	}

	cli, err := c.getETCDClientForSolver(cfg, ch)
	if err != nil {
		return fmt.Errorf("failed to initialze etcd client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), globalTimeout)
	defer cancel()

	entryKey := etcdKey(ch, cfg)
	entryValue := etcdEntry(ch, cfg)

	c.logger.Debug("creating key", zap.String("key", entryKey), zap.String("value", entryValue))

	result, err := cli.Put(ctx, entryKey, entryValue)
	if err != nil {
		return fmt.Errorf("error writing challenge to etcd database: %w", err)
	}

	if result.PrevKv == nil {
		return nil
	}

	oldValue := string(result.PrevKv.Value)

	if oldValue != entryValue {
		c.logger.Warn("overwrote old entry, this is not supposed to happen", zap.String("old", oldValue), zap.String("new", entryValue))
	}

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *CustomDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	c.logger.Debug("enter solver CleanUp", zap.String("type", "lifecycle"))
	defer c.logger.Debug("exit solver CleanUp", zap.String("type", "lifecycle"))

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return fmt.Errorf("failed to parse solver config: %w", err)
	}

	cli, err := c.getETCDClientForSolver(cfg, ch)
	if err != nil {
		return fmt.Errorf("failed to initialze etcd client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), globalTimeout)
	defer cancel()

	entryKey := etcdKey(ch, cfg)

	c.logger.Debug("removing key", zap.String("key", entryKey))
	result, err := cli.Delete(ctx, entryKey)
	if err != nil {
		c.logger.Error("failed to cleanup record", zap.Error(err), zap.String("fqdn", ch.ResolvedFQDN), zap.String("key", ch.Key))
		return fmt.Errorf("failed to remove key: %w", err)
	}

	if result.Deleted > 1 {
		c.logger.Warn("cleanup deletion affected more than one key", zap.Int64("deletedKeyCount", result.Deleted), zap.String("key", entryKey))
	} else if result.Deleted <= 0 {
		c.logger.Warn("tried cleaning up key that did not exist", zap.Int64("deletedKeyCount", result.Deleted), zap.String("key", entryKey))
	}

	return nil
}

func (c *CustomDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	c.logger.Debug("enter solver Initialize", zap.String("type", "lifecycle"))
	defer c.logger.Debug("exit solver Initialize", zap.String("type", "lifecycle"))

	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl
	return nil
}

func etcdKey(ch *v1alpha1.ChallengeRequest, cfg customDNSProviderConfig) string {
	fqdn := ch.ResolvedFQDN

	key := cfg.KeyPrefix
	components := strings.Split(fqdn, ".")

	for i := len(components) - 2; i >= 0; i-- {
		key += fmt.Sprintf("/%v", components[i])
	}

	return fmt.Sprintf("%v/%v", key, ch.Key)
}

type skyDnsEntry struct {
	Text  string `json:"text"`
	Group string `json:"group"`
	Ttl   int    `json:"ttl"`
}

func etcdEntry(ch *v1alpha1.ChallengeRequest, cfg customDNSProviderConfig) string {
	entry := skyDnsEntry{
		Text:  ch.Key,
		Group: ch.ResolvedFQDN,
		Ttl:   60,
	}

	text, err := json.Marshal(entry)
	if err != nil {
		panic(err)
	}

	return string(text)
}

var errNoSuchKey = errors.New("no such key")

func (c *CustomDNSProviderSolver) getValueFromSecret(ref corev1.SecretKeySelector, ns string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), globalTimeout)
	defer cancel()

	secret, err := c.client.CoreV1().Secrets(ns).Get(ctx, ref.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get secret `%v`: %w", ref.Name, err)
	}

	value, ok := secret.Data[ref.Key]
	if !ok {
		return "", fmt.Errorf("failed to get value for key `%v` in secret `%v`: %w", ref.Key, ref.Name, errNoSuchKey)
	}

	return string(value), nil
}

func (c *CustomDNSProviderSolver) getETCDClientForSolver(cfg customDNSProviderConfig, ch *v1alpha1.ChallengeRequest) (*clientv3.Client, error) {
	namespace := ch.ResourceNamespace

	username, err := c.getValueFromSecret(cfg.Etcd.User.Ref, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve ETCD username: %w", err)
	}

	password, err := c.getValueFromSecret(cfg.Etcd.Password.Ref, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve ETCD password: %w", err)
	}

	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   cfg.Etcd.Endpoints,
		DialTimeout: globalTimeout,
		Username:    username,
		Password:    password,
		Logger:      c.logger,
	})
	if err != nil {
		return nil, err
	}

	return cli, nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (customDNSProviderConfig, error) {
	cfg := customDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}
