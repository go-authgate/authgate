FROM alpine:3.21

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

LABEL maintainer="AuthGate Team" \
  org.label-schema.name="AuthGate" \
  org.label-schema.vendor="AuthGate" \
  org.label-schema.schema-version="1.0" \
  org.label-schema.version="${VERSION}"

LABEL org.opencontainers.image.source=https://github.com/your-org/authgate
LABEL org.opencontainers.image.description="OAuth 2.0 Device Authorization Grant server for CLI tools and browserless devices"
LABEL org.opencontainers.image.licenses=MIT
LABEL org.opencontainers.image.version="${VERSION}"

RUN apk add --no-cache ca-certificates wget && \
  rm -rf /var/cache/apk/* && \
  adduser -D -u 1000 authgate && \
  mkdir -p /app/data && \
  chown -R authgate:authgate /app

# Copy the binary (templates and static files are embedded)
COPY release/${TARGETOS}/${TARGETARCH}/authgate /bin/authgate

USER authgate

WORKDIR /app

# Expose default port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Volume for database
VOLUME ["/app/data"]

# Set default environment
ENV DATABASE_PATH=/app/data/oauth.db

CMD ["/bin/authgate", "server"]
