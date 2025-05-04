import logging
import os
from datetime import date
import re
from typing import Any
from urllib.parse import urlparse
import httpx
from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader

from models import MsgPayload, RequestPayload, ResponsePayload

# Create a logs directory if it doesn't exist
if not os.path.exists("logs"):
    os.makedirs("logs")

# Get today's date in YYYY-MM-DD format
today = date.today().strftime("%Y-%m-%d")

# Configure logging
log_file_path = os.path.join("logs", f"{today}.log")
logging.basicConfig(
    filename=log_file_path,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

app = FastAPI()

# CORS configuration
origins = [
    "http://localhost",
    "http://localhost:8080",
    "https://yourdomain.com",  # Add your frontend domain
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)


# Define the API key header
API_KEY_NAME = "X-API-Key"
API_KEY = "abcdef-token-123"  # Replace with your actual API key
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

messages_list: dict[int, MsgPayload] = {}


# Dependency to verify the API key
async def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key != API_KEY:
        logging.warning("Invalid API key attempt")
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return True


@app.get("/", dependencies=[Depends(verify_api_key)])
def root() -> dict[str, str]:
    logging.info("Root endpoint accessed")
    return {"message": "It's alive!"}


# POST endpoint to forward the payload to another API
@app.post("/getStructuredDataQuery", response_model=ResponsePayload,dependencies=[Depends(verify_api_key)])
async def get_structured_data_query(payload: RequestPayload) -> Any:
    external_api_url = payload.requestBody.apiBaseUrl

    # Prepare headers for the external API
    external_api_headers = {
        "apiKey": payload.header.apiKey,
        "x-tokey-key": payload.header.x_tokey_key,
        "accept": payload.header.accept,
        "Content-Type": "application/json",
    }

    # Prepare the body for the external API
    # Forward the entire payload or just the requestBody.payload, depending on the external API's needs
    external_payload = payload.requestBody.payload

    # Log the request details
    logging.info(f"Sending request to {external_api_url} with payload: {external_payload}")
    
    # Validate the apiBaseUrl format
    try:
        # Check if the URL is well-formed
        parsed_url = urlparse(external_api_url)
        if not all([parsed_url.scheme, parsed_url.netloc]) or parsed_url.scheme not in ["http", "https"]:
            logging.error(f"Invalid apiBaseUrl: {external_api_url}")
            return ResponsePayload(
                statusCode=400,
                data={},
                success=False,
                message="Invalid apiBaseUrl: Must be a valid HTTP/HTTPS URL"
            )
        
        # Optional: Additional validation (e.g., URL pattern)
        url_pattern = re.compile(r'^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$')
        if not url_pattern.match(external_api_url):
            logging.error(f"Invalid apiBaseUrl format: {external_api_url}")
            return ResponsePayload(
                statusCode=400,
                data={},
                success=False,
                message="Invalid apiBaseUrl: Malformed URL"
            )

    except ValueError as e:
        logging.error(f"Invalid apiBaseUrl: {external_api_url}, error: {str(e)}")
        return ResponsePayload(
            statusCode=400,
            data={},
            success=False,
            message=f"Invalid apiBaseUrl: {str(e)}"
        )

    try:
        # Make the request to the external API using httpx
        async with httpx.AsyncClient() as client:
            response = await client.post(
                external_api_url,
                headers=external_api_headers,
                json=external_payload,
            )
        # Log the response details
        logging.info(f"Received response: status={response.status_code}, headers={response.headers}, body={response.text}")

        # Check if the response is JSON
        content_type = response.headers.get("content-type", "").lower()
        if "application/json" not in content_type:
            error_message = f"Non-JSON response from external API: Content-Type={content_type}"
            # Handle text/html specifically (likely an error page for invalid route)
            if "text/html" in content_type:
                # Check for common error indicators in the HTML body
                response_body = response.text.lower()
                if "404" in response_body or "not found" in response_body:
                    logging.error(f"Invalid route detected: {external_api_url}, body={response.text}")
                    error_message = f"Invalid route for {external_api_url}: Likely a 404 Not Found error"
                else:
                    logging.error(f"HTML error page received: {external_api_url}, body={response.text}")
                    error_message = f"Invalid response for {external_api_url}: HTML error page received"
            else:
                logging.error(f"Unexpected content type: Content-Type={content_type}, body={response.text}")
            return ResponsePayload(
                statusCode=response.status_code,
                data={},
                success=False,
                message=error_message
            )
        
        # Attempt to parse the response as JSON
        try:
            external_response = response.json()
        except ValueError as e:
            logging.error(f"Failed to parse response as JSON: {response.text}")
            return ResponsePayload(
                statusCode=response.status_code,
                data={},
                success=False,
                message=f"Invalid JSON response from external API: {str(e)}"
            )
        
        # Ensure the parsed response is a dictionary
        if not isinstance(external_response, dict):
            logging.error(f"Response is not a dictionary: type={type(external_response).__name__}, value={external_response}")
            return ResponsePayload(
                statusCode=response.status_code,
                data={},
                success=False,
                message=f"External API response is not a dictionary: {type(external_response).__name__}"
            )

        # Handle successful (200) and non-200 responses
        if response.status_code == 200:
            logging.info("External API call successful")
            return ResponsePayload(
                statusCode=response.status_code,
                data=external_response,
                success=True,
                message="External API call successful"
            )
        elif response.status_code == 404:
            logging.error(f"Route not found: {external_api_url}, body={response.text}")
            return ResponsePayload(
                statusCode=response.status_code,
                data=external_response,
                success=False,
                message=f"Route not found for {external_api_url}"
            )
        else:
            logging.error(f"External API error: status={response.status_code}, body={response.text}")
            return ResponsePayload(
                statusCode=response.status_code,
                data=external_response,
                success=False,
                message=f"External API error: {response.text}"
            )

    except httpx.RequestError as e:
        # Handle network or request errors (e.g., unreachable endpoint, DNS failure)
        logging.error(f"Failed to call external API: {str(e)}")
        return ResponsePayload(
            statusCode=500,
            data={},
            success=False,
            message=f"Failed to call external API: {str(e)}"
        )
    except Exception as e:
        # Catch any other unexpected exceptions
        logging.exception(f"Unexpected error: {str(e)}")
        return ResponsePayload(
            statusCode=500,
            data={},
            success=False,
            message="Internal server error"
        )