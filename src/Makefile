build-slim-local-images:
	@docker build -f DockerFiles/wolfi-base-Dockerfile -t YOUR-DOCKERHUB-USERNAME/sentinelprobe-base .
	# @docker build -f DockerFiles/main/cli-Dockerfile -t YOUR-DOCKERHUB-USERNAME/sentinelprobe .

build-local-image:
	@docker build -f DockerFiles/wolfi-base-Dockerfile -t YOUR-DOCKERHUB-USERNAME/sentinelprobe-base . --no-cache --progress=plain

scan-vulns:
	@trivy image YOUR-DOCKERHUB-USERNAME/sentinelprobe-base --scanners vuln

local: build-local-image scan-vulns
