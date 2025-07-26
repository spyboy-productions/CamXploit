# Use the official Python image as a base image
FROM python:3.12-slim

# Set the working directory in the container
WORKDIR /app

# Install FFmpeg
RUN apt-get update && apt-get install -y ffmpeg

# Copy the requirements file to the working directory
COPY requirements.txt .

# Install uv and the Python dependencies
RUN pip install uv
RUN uv pip install --system -r requirements.txt
RUN uv pip install --system Flask

# Copy the rest of the application code to the working directory
COPY . .

# Expose the port that the Flask application will run on
EXPOSE 5000

# Set the command to run the application
CMD ["python3", "server.py"]
