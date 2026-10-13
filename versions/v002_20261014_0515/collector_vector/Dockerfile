FROM timberio/vector:0.38.0-alpine

COPY vector.yaml /etc/vector/vector.yaml

EXPOSE 8686

CMD ["--config", "/etc/vector/vector.yaml"]
