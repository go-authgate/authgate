FROM alpine:3.21

ARG TARGETOS
ARG TARGETARCH

LABEL maintainer="AuthGate Team" \
  org.label-schema.name="AuthGate" \
  org.label-schema.vendor="AuthGate" \
  org.label-schema.schema-version="1.0"

LABEL org.opencontainers.image.source=https://github.com/your-org/authgate
LABEL org.opencontainers.image.description="OAuth 2.0 Device Authorization Grant server for CLI tools and browserless devices"
LABEL org.opencontainers.image.licenses=MIT

RUN apk add --no-cache ca-certificates && \
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

# Volume for database
VOLUME ["/app/data"]

# Set default environment
ENV DATABASE_PATH=/app/data/oauth.db

CMD ["/bin/authgate"]
