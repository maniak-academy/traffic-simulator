# traffic-simulator


docker buildx build --platform linux/amd64,linux/arm64 --push -t sebbycorp/traffic-simulator:latest .

docker run -p 8501:8501 sebbycorp/traffic-simulator:latest
