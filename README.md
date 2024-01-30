# Power-DNS

Power-DNS is a customizable DNS server written in Go that provides features such as Kubernetes name resolution, DNS over vless for circumventing censorship, and an API for managing DNS records on your local system.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [File Structure](#file-structure)
- [Getting Started](#getting-started)
- [Docker Usage](#docker-usage)
- [API Endpoints](#api-endpoints)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Overview

Power-DNS is a powerful DNS server designed for flexibility and extensibility. It leverages Go for its core logic, Gin for API functionality, and miekg/dns for DNS handling. The project is structured to allow easy customization and extension based on your specific requirements.

## Features

- **Kubernetes Name Resolution:** Provides seamless integration with Kubernetes for resolving names of services.

- **DNS over vless:** Circumvent censorship by forwarding DNS queries over vless to a public DNS-over-HTTPS (DoH) server.

- **API for DNS Management:** An API built with Gin allows you to interact with the DNS server, enabling the addition, removal, and retrieval of DNS records.

## File Structure

