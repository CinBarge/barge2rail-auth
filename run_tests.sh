#!/bin/bash

echo "Running Django SSO Test Suite"
echo "=============================="
echo ""

# Activate virtual environment if not already activated
if [ -z "$VIRTUAL_ENV" ]; then
    echo "Activating virtual environment..."
    source .venv/bin/activate
fi

# Load environment variables
echo "Loading environment variables..."
set -a
source .env
set +a

# Run all tests with coverage
echo ""
echo "Running tests with verbosity..."
echo "=============================="
python manage.py test sso.tests --verbosity=2

# Check if tests passed
if [ $? -eq 0 ]; then
    echo ""
    echo "✅ All tests passed!"
    echo ""

    # Generate coverage report if coverage is installed
    if command -v coverage &> /dev/null; then
        echo "Generating coverage report..."
        echo "============================"
        coverage run --source='sso' manage.py test sso.tests
        coverage report
        coverage html

        echo ""
        echo "📊 Coverage report generated in htmlcov/index.html"
    else
        echo "ℹ️  Install coverage for detailed coverage reports: pip install coverage"
    fi
else
    echo ""
    echo "❌ Tests failed. Please review the errors above."
    exit 1
fi

echo ""
echo "Test suite completed successfully!"
