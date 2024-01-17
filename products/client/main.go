package main

import (
	"context"
	"fmt"

	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"

	pb "github.com/david993/product/products"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func loadPrivateKey(file, password string) ([]byte, error) {
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("failed to decode PEM block in private key file")
	}

	decrypted, err := x509.DecryptPEMBlock(block, []byte(password))
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

func loadCertificate(file string) ([]byte, error) {
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func main() {
	clientCert, err := tls.LoadX509KeyPair("cert/client-cert.pem", "cert/client-key.pem")
	if err != nil {
		fmt.Println("Error loading client certificate:", err)
	}

	caCertificate, _ := loadCertificate("cert/ca-cert.pem")

	caPool := x509.NewCertPool()
	if ok := caPool.AppendCertsFromPEM(caCertificate); !ok {
		log.Fatalf("failed to append ca certs")
	}

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
	})

	conn, err := grpc.Dial("0.0.0.0:50051", grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("failed to dial server: %s", err)
	}

	c := pb.NewProductServiceClient(conn)
	rList, err := c.All(context.Background(), &pb.Empty{})
	if err != nil {
		panic(err)
	}
	fmt.Println(rList.Products)

}
