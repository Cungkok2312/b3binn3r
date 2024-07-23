from flask import Flask, request, jsonify
from functools import wraps
import re

app = Flask(__name__)

class SecurityMiddleware:
    """
    A class to implement security measures to protect a web application from common attacks.

    Attributes:
    - app: Flask
        The Flask application instance to which the middleware is applied.
    """

    def __init__(self, app: Flask):
        """
        Initializes the SecurityMiddleware with the provided Flask application.

        Parameters:
        - app: Flask
            The Flask application instance.
        """
        self.app = app
        self.app.before_request(self.validate_request)

    def validate_request(self):
        """
        Validates incoming requests to protect against common attacks such as SQL injection and XSS.
        
        Raises:
        - ValueError:
            Raises an error if the request contains potentially harmful input.
        """
        # Check for SQL injection patterns
        sql_injection_patterns = re.compile(r"(SELECT|INSERT|UPDATE|DELETE|DROP|;|--|#)", re.IGNORECASE)
        if sql_injection_patterns.search(request.data.decode('utf-8')):
            raise ValueError("Potential SQL injection detected.")

        # Check for XSS patterns
        xss_patterns = re.compile(r"<[^>]+>")
        if xss_patterns.search(request.data.decode('utf-8')):
            raise ValueError("Potential XSS attack detected.")

def create_app():
    """
    Creates and configures the Flask application with security middleware.

    Returns:
    - Flask:
        The configured Flask application instance.
    """
    security_middleware = SecurityMiddleware(app)
    return app

@app.route('/submit', methods=['POST'])
def submit_data():
    """
    Endpoint to submit data to the server.

    Returns:
    - JSON:
        A JSON response indicating success or failure.
    """
    return jsonify({"message": "Data submitted successfully!"}), 200

# Unit tests for the SecurityMiddleware class.

import unittest

class TestSecurityMiddleware(unittest.TestCase):

    def setUp(self):
        """
        Sets up the test client and the security middleware for testing.
        """
        self.app = create_app()
        self.client = self.app.test_client()

    def test_valid_submission(self):
        """
        Tests a valid submission to the /submit endpoint.
        """
        response = self.client.post('/submit', data='{"name": "John Doe"}', content_type='application/json')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {"message": "Data submitted successfully!"})

    def test_sql_injection(self):
        """
        Tests submission with SQL injection attempt.
        """
        response = self.client.post('/submit', data='{"name": "John Doe; DROP TABLE users;"}', content_type='application/json')
        self.assertEqual(response.status_code, 500)  # Expecting a server error due to validation

    def test_xss_attack(self):
        """
        Tests submission with XSS attack attempt.
        """
        response = self.client.post('/submit', data='{"name": "<script>alert(1)</script>"}', content_type='application/json')
        self.assertEqual(response.status_code, 500)  # Expecting a server error due to validation

    def test_empty_submission(self):
        """
        Tests submission with empty data.
        """
        response = self.client.post('/submit', data='', content_type='application/json')
        self.assertEqual(response.status_code, 200)  # Should still succeed, but may need further validation

# Running the application
if __name__ == '__main__':
    app.run(debug=True)

# Note: In a production environment, ensure to handle exceptions properly and log them for further analysis.
