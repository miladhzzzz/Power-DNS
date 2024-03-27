# Power-DNS Documentation

This documentation provides an overview of the Power-DNS project, which enables DNS resolution over HTTPS for users in regions with restricted access to DNS-over-HTTPS services. The project includes features such as DNS caching, custom DNS record management via API, integration with Kubernetes (k8s) CoreDNS, packet flow monitoring with eBPF (Extended Berkeley Packet Filter), dynamic routing methods, failover mechanisms, and metrics and monitoring capabilities.

## Table of Contents

1. [Introduction](#introduction)
2. [Features](#features)
3. [Usage](#usage)
4. [Implementation Details](#implementation-details)
5. [Running in Different Environments](#running-in-different-environments)
6. [Contributing](#contributing)
7. [License](#license)

## Introduction

The Power-DNS project aims to provide a solution for DNS resolution over HTTPS, particularly for users in regions where access to DNS-over-HTTPS services is restricted. By setting up a dedicated server with a DNS relay API, users can query DNS records via HTTP GET requests and receive responses in JSON format. The project also supports local DNS caching, custom DNS record management via API endpoints, integration with Kubernetes (k8s) CoreDNS for resolving local names to services, packet flow monitoring with eBPF, dynamic routing methods, failover mechanisms, and metrics and monitoring capabilities.

## Features

- DNS resolution over HTTPS (DoH) using a dedicated server with a DNS relay API.
- Support for querying DNS records via HTTP GET requests and receiving responses in JSON format.
- Local DNS caching on the client and server sides to ensure fast responses and reduce the load on upstream DNS servers.
- Custom DNS record management via API endpoints for adding, deleting, and showing DNS records in the hosts file of the server.
- Integration with Kubernetes (k8s) CoreDNS to resolve local names to services within Kubernetes clusters.
- Packet flow monitoring with eBPF for network traffic analysis and debugging.
- Dynamic routing methods for DNS traffic using eBPF, allowing for flexible and efficient routing based on various criteria.
- Failover mechanisms including cache, switching to plain DNS requests, and using the server hosts file to resolve the name.
- Metrics and monitoring capabilities for performance analysis and troubleshooting using eBPF.

## Usage

To use the Power-DNS server, follow these steps:

1. Clone the repository:

   ```bash
   git clone <repository-url>

2. Build the project:

````shell
cd power-dns
go build
Start the DNS server:
````

````sh

./power-dns
````

- The DNS server will start listening for DNS queries on port 53 or port 8000 for API queries.

- Use HTTP GET requests to query DNS records via the API endpoints (e.g., /dns/Query/example.com).

Note: The same codebase can be used for both the DNS relay server and the client. When running locally, you can choose to run the server component to provide DNS relay services or run the client component to query DNS records from the relay server.

## Implementation Details

### Project Structure

The project consists of the following main components:

- power-dns: The main executable file for running the DNS server.
- dns: Package containing the DNS server implementation.
- cache: Package containing the cache implementation for caching DNS responses.
- api: Package containing API endpoints for custom DNS record management.
- k8s: Package for integrating with Kubernetes (k8s) CoreDNS.
- ebpf: Package for packet flow monitoring and metrics collection with eBPF.

### Dependencies

The project relies on the following external dependencies:

- github.com/miekg/dns: Package for DNS message handling and server implementation.
- github.com/pkg/errors: Package for error handling and wrapping errors.

### DNS Tunnel Over HTTPS (DoH) Logic

The DNS server handles incoming DNS queries and forwards them to the relay server via HTTP GET requests. It supports local DNS caching on both the client and server sides to optimize performance.

### API Endpoints

The project exposes API endpoints for managing custom DNS records, including adding, deleting, and showing DNS records in the hosts file of the server.

### Kubernetes (k8s) Integration

Integration with Kubernetes (k8s) CoreDNS enables the resolution of local names to services within Kubernetes clusters.

### Packet Flow Monitoring and Metrics with eBPF

The project utilizes eBPF for packet flow monitoring and metrics collection, allowing for network traffic analysis, performance monitoring, and troubleshooting.

### Dynamic Routing Methods

The DNS server employs dynamic routing methods using eBPF, allowing for flexible and efficient routing of DNS traffic based on various criteria such as source, destination, and protocol.

### Failover Mechanisms

The project includes failover mechanisms such as cache, switching to plain DNS requests, and using the server hosts file to resolve the name, ensuring reliability and availability of DNS resolution services.

## Running in Different Environments

The project provides scripts and documentation for running the DNS relay server on different environments, including Kubernetes and various cloud providers. Additionally, you can run the entire system, including both the server/relay and client components, in a Docker container for easy deployment and management.

## Contributing

Contributions to the Power-DNS project are welcome! Feel free to submit bug reports, feature requests, or pull requests via the project repository on GitHub.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
