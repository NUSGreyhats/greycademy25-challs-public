# Use an official lightweight Python image
FROM python:3.9-slim  

# Set the working directory
WORKDIR /app  

# Copy project files into the container
COPY ./app /app  

# Install dependencies
RUN pip install -r requirements.txt

# Command to run the app
CMD ["python", "server.py"]