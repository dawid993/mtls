package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"io/ioutil"

	"crypto/x509"
	"log"

	pb "github.com/david993/product/products"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func loadCertificate(file string) ([]byte, error) {
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	return b, nil
}

type server struct {
	pb.UnimplementedProductServiceServer
}

func (s *server) All(context.Context, *pb.Empty) (*pb.ProductList, error) {
	return &pb.ProductList{Products: []*pb.Product{
		{Name: "Product 1", Description: "Description 1", Price: 100.0},
	}}, nil
}

// Unary interceptor function to handle panics and errors
func unaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Println("Recovered from panic in unary interceptor:", err)
		}
	}()

	// Calls the handler
	resp, err := handler(ctx, req)

	// Now we can handle errors and print detailed error messages
	if err != nil {
		fmt.Printf("Error occurred during request: %v\n", err)
	}

	return resp, err
}

func main() {
	serverCert, err := tls.LoadX509KeyPair("cert/server-cert.pem", "cert/server-key.pem")
	if err != nil {
		fmt.Println("Error loading server certificate:", err)
	}

	caCertificate, _ := loadCertificate("cert/ca-cert.pem")
	caPool := x509.NewCertPool()
	if ok := caPool.AppendCertsFromPEM(caCertificate); !ok {
		log.Fatalf("failed to append ca certs")
	}

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert,
		RootCAs:      caPool,
	})

	// Create a unary interceptor
	var serverOpts []grpc.ServerOption
	serverOpts = append(serverOpts, grpc.Creds(creds), grpc.UnaryInterceptor(unaryInterceptor))

	s := grpc.NewServer(serverOpts...)
	lis, err := net.Listen("tcp", "localhost:50051")
	if err != nil {
		panic(err)
	}

	pb.RegisterProductServiceServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		panic(err)
	}

	fmt.Println("Server started at port 50051")
}
