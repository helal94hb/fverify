FROM python:3.12-slim

# Install uv
RUN pip install uv

# Set working directory
WORKDIR /app

# Copy the dependency files first for caching
COPY pyproject.toml uv.lock ./

# Install dependencies using uv
RUN uv sync --frozen

# Copy the application source code
COPY app /app/app

# Set environment variables for production (can be overridden at runtime)
# ENV FV_DATABASE_URL="sqlite+aiosqlite:///./face-verify.db"
# ENV FV_AT_REST_KEY="YOUR_PRODUCTION_FERNET_KEY"
# ENV FV_SEAL_PRIVATE_KEY_PEM="YOUR_PRODUCTION_PRIVATE_KEY"
# ENV FV_OTP_EXPORT_KEY="YOUR_PRODUCTION_AES_KEY"

# Expose the application port
EXPOSE 8400

# Run the FastAPI app using the virtual environment created by uv
CMD ["uv", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8400"]
