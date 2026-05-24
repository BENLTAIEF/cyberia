# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This repository contains three distinct Python services for extracting cybersecurity data from various sources:

1. **certeuapi** - Extracts CERT-EU Security Advisories from 2020 onwards
2. **epssapijson** - Downloads EPSS (Exploit Prediction Scoring System) data from empiricalsecurity.com
3. **nvdapijson** - Extracts CVE data from the NVD (National Vulnerability Database) API

Each service is designed to run in Docker containers and extracts data from external APIs into JSONL or JSON files.

## Development Setup

To work with this codebase:

1. No special setup required - the code is ready to run
2. Each service has its own requirements.txt file
3. Services are designed to run in Docker containers with appropriate volume mounts

## Key Files and Structure

- `certeuapi/` - CERT-EU advisory extraction service
  - `main.py` - Main extraction logic
  - `ReadMe.md` - Docker build and run instructions
  - `requirements.txt` - Dependencies

- `epssapijson/` - EPSS data extraction service  
  - `main.py` - Main download logic
  - `ReadMe.md` - Docker build and run instructions
  - `dockerfile` - Docker build configuration
  - `requirements.txt` - Dependencies

- `nvdapijson/` - NVD CVE data extraction service
  - `main.py` - Main extraction logic
  - `ReadMe.md` - Docker build and run instructions
  - `dockerfile` - Docker build configuration
  - `requirements.txt` - Dependencies

## How to Run

Each service is designed to be run in Docker containers:

1. Build the Docker image: `docker build -t <service-name>:latest .`
2. Run the container with appropriate volume mounts and environment variables:
   - For certeuapi: `docker run --rm -v <local-path>:/data <service-name>:latest`
   - For epssapijson: `docker run --rm -v <local-path>:/data <service-name>:latest`
   - For nvdapijson: `docker run --rm -e NVD_API_KEY="<your-key>" -v <local-path>:/data <service-name>:latest`

## Key Components

- HTTP session management with retries for robust API access
- Data parsing and normalization for consistent output formats
- Error handling and logging for reliable operation
- Support for various data formats (JSON, JSONL, CSV)
- Volume mounting for data persistence

## Common Development Tasks

- Modify extraction logic in main.py files
- Update requirements.txt for new dependencies
- Adjust Dockerfile configurations
- Modify environment variable handling
- Update README.md with new usage instructions