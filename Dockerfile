FROM python:3.12-slim
LABEL org.opencontainers.image.title="sniffdog" \
      org.opencontainers.image.description="Static malware detection for PyPI and npm packages"
RUN useradd --create-home --uid 10001 sniffdog
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . && rm -rf /root/.cache
USER sniffdog
WORKDIR /work
ENTRYPOINT ["sniffdog"]
CMD ["--help"]
