#!/bin/bash

# Script to run 3 MPC servers with different ports and database URLs
# Each server runs in the background

echo "Starting 3 MPC servers..."

# Server 1
echo "Starting MPC Server 1 on port 8081..."

PORT=8081 DATABASE_URL="postgresql://postgres:7MrMtsYOK8I9oVra@db.zumtokblncqhbngytlgj.supabase.co:5432/postgres" cargo run &
SERVER1_PID=$!

# Server 2
echo "Starting MPC Server 2 on port 8082..."
PORT=8082 DATABASE_URL="postgresql://postgres:LxKCBOwa4bHaWKvY@db.hytgsmmyifvosssexccr.supabase.co:5432/postgres" cargo run &
SERVER2_PID=$!

# Server 3
echo "Starting MPC Server 3 on port 8083..."
PORT=8083 DATABASE_URL="postgresql://postgres:iKSeInzEFMDOPAsj@db.brdstnxopdfetthmhycn.supabase.co:5432/postgres" cargo run &
SERVER3_PID=$!

echo "All servers started!"
echo "Server 1 PID: $SERVER1_PID (Port: 8081)"
echo "Server 2 PID: $SERVER2_PID (Port: 8082)"
echo "Server 3 PID: $SERVER3_PID (Port: 8083)"
echo ""
echo "Servers are running in the background."
echo "To stop all servers, run: kill $SERVER1_PID $SERVER2_PID $SERVER3_PID"
echo "Or use Ctrl+C to stop this script and all servers"

# Wait for user input to stop servers
read -p "Press Enter to stop all servers..."

echo "Stopping all servers..."
kill $SERVER1_PID $SERVER2_PID $SERVER3_PID 2>/dev/null
echo "All servers stopped."
