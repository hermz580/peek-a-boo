"""Launch the Peek-a-Boo Flask dashboard."""
from peekaboo.app import app

if __name__ == "__main__":
    app.run(debug=True, port=5000)
