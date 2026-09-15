FROM python:3.12-slim

WORKDIR /srv
COPY server.py .
COPY index.html .

EXPOSE 80
CMD ["python", "server.py"]
