# Use Python 3.12 slim image
FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set work directory
WORKDIR /app

# Install system dependencies for PostgreSQL and other requirements
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        libmagic1 \
        libmagic-dev \
        file \
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . /app/

# Create staticfiles directory
RUN mkdir -p /app/staticfiles

# Collect static files for production
RUN python manage.py collectstatic --noinput --settings=vast_project.render_settings || echo "collectstatic will run on first deployment"

# Expose the port
EXPOSE $PORT

# Create startup script
RUN echo '#!/bin/bash\npython manage.py migrate --settings=vast_project.render_settings\ngunicorn vast_project.wsgi:application --bind 0.0.0.0:$PORT --settings=vast_project.render_settings' > /app/start.sh
RUN chmod +x /app/start.sh

# Run the application
CMD ["/app/start.sh"]
