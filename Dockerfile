# Use official Python runtime as a parent image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set work directory
WORKDIR /app

# Install system dependencies (needed for yara-python compilation)
RUN apt-get update && apt-get install -y \
    gcc \
    libyara-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies clearly
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Manually install yara-python since we have build tools now
RUN pip install yara-python

# Copy application code
COPY . /app

# Create a volume for persistent data
VOLUME /root/.malware-analyzer

# Expose port
EXPOSE 8000

# Run the application
CMD ["python", "malware_analyzer.py"]
