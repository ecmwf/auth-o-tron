#!/bin/bash
set -e

echo "Stopping MongoDB test instance..."
docker stop authotron-mongo-test
docker rm authotron-mongo-test
echo "MongoDB stopped and removed."