docker buildx create —name builder
docker buildx use builder
docker buildx build --platform linux/arm64,linux/amd64 -f Dockerfile -t agent-sentinel:v1 .
