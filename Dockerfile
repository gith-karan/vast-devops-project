# Use Python 3.12 slim image
FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set work directory
WORKDIR /app

# Install system dependencies for PostgreSQL (not MySQL)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        libmagic1 \
        libmagic-dev \
        file \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . /app/

# Create staticfiles directory
RUN mkdir -p /app/staticfiles

# Expose port
EXPOSE $PORT

# Create Railway startup script (no waiting for external DB)
RUN echo '#!/bin/bash\n\
echo "Starting Railway deployment..."\n\
\n\
echo "Running migrations..."\n\
python manage.py migrate --settings=vast_project.railway_settings\n\
\n\
echo "Collecting static files..."\n\
python manage.py collectstatic --noinput --settings=vast_project.railway_settings\n\
\n\
echo "Starting Django server on Railway..."\n\
python manage.py runserver 0.0.0.0:$PORT --settings=vast_project.railway_settings' > /app/railway-start.sh

RUN chmod +x /app/railway-start.sh

# Run the application
CMD ["/app/railway-start.sh"]
