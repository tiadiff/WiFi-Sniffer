#!/bin/bash
echo "------------------------------------------------"
echo "Stopping NetSniff Server (Port 5001)..."
echo "------------------------------------------------"

pid=$(sudo lsof -t -i:5001)

if [ -z "$pid" ]; then
    echo "No server found running on port 5001."
else
    echo "Found process $pid. Killing it..."
    sudo kill -9 $pid
    echo "Server stopped successfully."
fi

# Keep window open
read -p "Press any key to exit..."
