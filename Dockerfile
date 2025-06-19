# Use official Python runtime as base image
FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set work directory
WORKDIR /app

# Install system dependencies (including libmagic for python-magic)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        default-libmysqlclient-dev \
        build-essential \
        pkg-config \
        netcat-openbsd \
        libmagic1 \
        libmagic-dev \
        file \
        wait-for-it \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . /app/

# Create staticfiles directory
RUN mkdir -p /app/staticfiles

# Create wait script
RUN echo '#!/bin/bash\n\
echo "Waiting for MySQL to be ready..."\n\
while ! nc -z db 3306; do\n\
  echo "MySQL is unavailable - sleeping"\n\
  sleep 2\n\
done\n\
echo "MySQL is up - executing command"\n\
\n\
echo "Running migrations..."\n\
python manage.py migrate --settings=vast_project.settings_prod\n\
\n\
echo "Collecting static files..."\n\
python manage.py collectstatic --noinput --settings=vast_project.settings_prod --clear\n\
\n\
echo "Starting Django server..."\n\
python manage.py runserver 0.0.0.0:8000 --settings=vast_project.settings_prod' > /app/wait-and-start.sh

RUN chmod +x /app/wait-and-start.sh

# Expose port
EXPOSE 8000

# Run the wait script instead of direct Django
CMD ["/app/wait-and-start.sh"]
