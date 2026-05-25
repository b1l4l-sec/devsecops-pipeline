# Use slim image to reduce attack surface
FROM python:3.12-slim

# Security: don't run as root
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

# Set working directory
WORKDIR /app

# Copy and install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app source
COPY app.py .

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 5000

# Health check built into container
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"

# Run the app
CMD ["python", "app.py"]
