# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust workspace implementing a multi-party computation (MPC) system for Solana transactions. The project consists of four main components:

- **backend**: REST API server (Actix Web) handling user authentication and Solana operations
- **indexer**: Yellowstone gRPC client for monitoring Solana blockchain events
- **mpc**: Multi-party computation server for threshold signatures and key aggregation
- **store**: Database abstraction layer using SQLx with PostgreSQL

## Development Commands

### Building and Running
```bash
# Build entire workspace
cargo build

# Build specific crate
cargo build -p backend
cargo build -p indexer  
cargo build -p mpc
cargo build -p store

# Run services (each runs on localhost:8080 by default)
cargo run -p backend    # User API and Solana operations
cargo run -p indexer    # Blockchain monitoring
cargo run -p mpc        # MPC threshold signature service

# Check code
cargo check
cargo clippy

# Run tests
cargo test
```

## Architecture

### Backend Service (`backend/`)
- Actix Web REST API server
- Routes: user management (`/signup`, `/signin`, `/user/{id}`) and Solana operations (`/quote`, `/swap`, `/sol-balance/{pubkey}`, `/token-balance/{pubkey}/{mint}`)
- Currently has stub implementations for most endpoints

### MPC Service (`mpc/`)
- Threshold signature scheme implementation
- Key endpoints: `/generate`, `/send-single`, `/aggregate-keys`, `/agg-send-step1`, `/agg-send-step2`, `/aggregate-signatures-broadcast`
- Handles multi-party key generation and signature aggregation

### Indexer Service (`indexer/`)
- Uses Yellowstone gRPC protocol to monitor Solana blockchain
- Implements health checking for gRPC connections
- Currently minimal implementation with basic client setup

### Store Library (`store/`)
- Database abstraction using SQLx with PostgreSQL
- Provides `Store` struct wrapping `PgPool`
- User management functionality (stub implementation)

## Key Dependencies

- **actix-web**: Web framework for backend and MPC services
- **sqlx**: Async PostgreSQL driver with compile-time query checking
- **yellowstone-grpc-proto**: Solana blockchain streaming via gRPC
- **tonic**: gRPC framework for indexer service
- **tokio**: Async runtime
- **serde**: Serialization for API request/response handling

## Notes

- Both backend and MPC services default to port 8080 - you'll need to configure different ports for concurrent operation
- Most endpoint implementations are currently stubs returning placeholder responses
- Database schema and migrations are not yet implemented in the store crate
- The indexer service has basic structure but minimal blockchain event handling logic