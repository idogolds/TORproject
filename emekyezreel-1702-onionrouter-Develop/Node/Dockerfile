FROM microsoft/server-core-windows:latest-ltsc2  # Or any Windows based Python image

# Set the working directory
WORKDIR \\app

# Copy only the necessary program files
COPY node.py \\app\
COPY encryptions.py \\app\
COPY errors.py \\app\
COPY aeslib.dll \\app\
COPY config.ini \\app\
COPY requirements.txt \\app\

# Install needed packages using PowerShell
RUN powershell -ExecutionPolicy Bypass -Command "pip install --no-cache-dir -r requirements.txt"

EXPOSE 7007
EXPOSE 9999

CMD ["python", "node.py"]
