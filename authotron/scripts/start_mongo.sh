#!/bin/bash
set -e

echo "Starting MongoDB test instance..."

if docker ps -a --format '{{.Names}}' | grep -q "^authotron-mongo-test$"; then
  echo "Container exists, starting it..."
  docker start authotron-mongo-test
else
  echo "Creating new container..."
  docker run -d \
    --name authotron-mongo-test \
    -p 27017:27017 \
    -e MONGO_INITDB_DATABASE=authotron \
    mongo:7
fi

echo "Waiting for MongoDB to be ready..."
sleep 3

echo "MongoDB is running at mongodb://localhost:27017"
echo "Database: authotron"
echo ""
echo "To stop: ./scripts/stop-mongo.sh"
echo "To view logs: docker logs authotron-mongo-test"
