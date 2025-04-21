FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install paramiko for SSH functionality
RUN pip install paramiko

# Copy application files
COPY ip_setup.py /app/
COPY start.py /app/
COPY setup.html /app/
COPY ODU_CHarts.html /app/
COPY SIT_SERVER_SPACE.py /app/
COPY cell_selection_handler.py /app/

# Create an empty active sessions file
RUN echo "{}" > /app/global_active_sessions.json

# Expose the port the server runs on
EXPOSE 8080

# Set environment variable for Python to run in unbuffered mode
ENV PYTHONUNBUFFERED=1

# Run the setup server
CMD ["python", "ip_setup.py"]
