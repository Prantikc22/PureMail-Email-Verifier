# Email Verifier Pro

A powerful web application for bulk email verification and list cleaning.

## Features

- Bulk email verification without sending actual emails
- Support for multiple file formats (Excel, CSV, TXT)
- Real-time email validation using DNS and MX record checks
- Disposable email detection
- User authentication system
- Verification history tracking
- Clean and modern UI

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd email-verifier
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run the application:
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## Usage

1. Sign up for a new account or login if you already have one
2. Navigate to the "Verify Emails" tab
3. Upload your file containing email addresses
4. Wait for the verification process to complete
5. Download the cleaned email list

## File Format Requirements

- CSV files: Emails should be in a single column
- Excel files (.xlsx): Emails should be in a single column
- Text files (.txt): One email per line

## Technical Details

- Built with Flask and SQLAlchemy
- Uses DNS and MX record verification
- Implements email format validation
- Detects disposable email domains
- Supports concurrent processing for faster verification

## Security Features

- Secure password hashing
- Protected routes with Flask-Login
- Input validation and sanitization
- File upload restrictions

## License

MIT License
