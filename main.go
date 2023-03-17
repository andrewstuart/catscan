package main

import (
	"context"
	"crypto/x509"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"astuart.co/catscan/pkg/scan"
	"astuart.co/catscan/pkg/validate"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/sirupsen/logrus"
)

var ctx, cancel = context.WithCancel(context.Background())

func init() {
	go func() {
		ch := make(chan os.Signal, 2)
		signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
		i := 0
		for range ch {
			i++
			if i > 1 {
				os.Exit(1)
			}
			cancel()
		}
	}()

}

func main() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("Authentication failure: %+v", err)
	}
	d := scan.MultiScanner{
		Scanners: []scan.Scanner{
			&scan.AzureDNSScanner{
				Creds:        cred,
				Subscription: "8cc6e0ed-1c1e-4d57-9fa5-16dfc3852bb1",
			}, &scan.AzureDNSScanner{
				Creds:        cred,
				Subscription: "0c0c4cf4-12e5-4d96-862a-655e121e073b",
				// },
				// &scan.KubeSecretScanner{
				// 	KubeConfig: &rest.Config{
				// 		Host: "http://localhost:8001",
				// 		// BearerToken: os.Getenv("TOKEN"),
				// 		// Host:        os.Getenv("SERVER"),
				// 	},
				// 	Extra: []func(corev1.Secret) ([]*x509.Certificate, error){},
				// 	// }, &scan.AXFRScanner{
				// 	// 	DNSServer:   "192.168.16.5:53",
				// 	// 	Domain:      "astuart.co",
				// 	// 	Ports:       []int16{443},
				// 	// 	Concurrency: 30,
			}},
		Concurrency: 2,
	}

	c, err := d.Scan(ctx)
	if err != nil {
		logrus.Fatal(err)
	}

	certs, errs := make(chan *x509.Certificate), make(chan error)

	go func() {
		defer close(certs)
		defer close(errs)
		tkr := time.NewTicker(time.Minute)
		c.Read(ctx, certs, errs)
		for {
			select {
			case <-ctx.Done():
				return
			case <-tkr.C:
				c.Read(ctx, certs, errs)
			}
		}
	}()

	v := validate.MultiValidator{
		validate.MinKeyStrength(2048),
		validate.ValidAt(time.Now().AddDate(0, 0, 30)),
	}

	for {
		select {
		case c, ok := <-certs:
			if !ok {
				logrus.Info("certs closed")
				return
			}
			err := v.Validate(c)
			if err != nil {
				logrus.WithField("certNames", c.DNSNames).WithError(err).Error("invalid cert encountered")
			}
		case <-ctx.Done():
			logrus.Info("shutdown signaled")
			return
		case err, ok := <-errs:
			if !ok {
				logrus.Info("errs closed")
				return
			}
			logrus.WithError(err).Error("encounted error scanning")
		}
	}
}
