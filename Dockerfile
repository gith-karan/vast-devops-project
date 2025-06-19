# Use Python 3.12 slim image
FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set work directory
WORKDIR /app

# Install system dependencies for PostgreSQL (NOT MySQL)
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

# Collect static files
RUN python manage.py collectstatic --noinput --settings=vast_project.render_settings || echo "Static collection will run on deployment"

# Expose port
EXPOSE $PORT

# Create and set startup script
RUN echo '#!/bin/bash\n\
python manage.py migrate --settings=vast_project.render_settings\n\
python manage.py collectstatic --noinput --settings=vast_project.render_settings\n\
gunicorn vast_project.wsgi:application --bind 0.0.0.0:$PORT --settings=vast_project.render_settings' > /app/start.sh

RUN chmod +x /app/start.sh

# Run the application
CMD ["/app/start.sh"]
