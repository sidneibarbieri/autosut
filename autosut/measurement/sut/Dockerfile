FROM python:3.11-slim

LABEL description="STICKS SUT Measurement Pipeline"

WORKDIR /pipeline

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy pipeline scripts
COPY scripts/ scripts/

# Default: run the measurement pipeline
ENTRYPOINT ["python3", "scripts/sut_measurement_pipeline.py"]
