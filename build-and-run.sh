# Create a new builder using docker-container driver
docker buildx create --name builder --driver docker-container --use

# Inspect to confirm
docker buildx inspect --bootstrap

# Build for multiple platforms
docker buildx build \
    --platform linux/arm64,linux/amd64 \
    -f Dockerfile \
    -t agent-sentinel:v1 \
    .
