"""
Tests for the file discovery module.
"""

import os
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add the parent directory to the path to import our modules
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.scanner.file_discovery import is_relevant_file, get_all_files, filter_files_with_ai


class TestFileDiscovery(unittest.TestCase):
    """Test the file discovery functionality."""
    
    def test_is_relevant_file(self):
        """Test file relevancy detection."""
        # Relevant files
        self.assertTrue(is_relevant_file(Path("src/components/Button.jsx")))
        self.assertTrue(is_relevant_file(Path("src/pages/Login.vue")))
        self.assertTrue(is_relevant_file(Path("src/utils/auth.js")))
        self.assertTrue(is_relevant_file(Path("src/hooks/useForm.ts")))
        self.assertTrue(is_relevant_file(Path("public/index.html")))
        
        # Irrelevant files
        self.assertFalse(is_relevant_file(Path("node_modules/react/index.js")))
        self.assertFalse(is_relevant_file(Path("build/static/js/main.js")))
        self.assertFalse(is_relevant_file(Path("src/utils/helpers.min.js")))
        self.assertFalse(is_relevant_file(Path("src/components/Button.test.jsx")))
        self.assertFalse(is_relevant_file(Path("src/types/index.d.ts")))
    
    @patch('os.walk')
    def test_get_all_files(self, mock_walk):
        """Test file discovery function."""
        # Mock os.walk to return a predefined structure
        mock_walk.return_value = [
            ('/root/src', ['components', 'pages'], ['index.js', 'App.jsx']),
            ('/root/src/components', [], ['Button.jsx', 'Card.jsx']),
            ('/root/src/pages', ['auth'], ['Home.jsx', 'About.jsx']),
            ('/root/src/pages/auth', [], ['Login.jsx', 'Register.jsx']),
            ('/root/node_modules', ['react'], []),
            ('/root/node_modules/react', [], ['index.js'])
        ]
        
        # Expected output: all files excluding node_modules
        expected_files = [
            Path('/root/src/index.js'),
            Path('/root/src/App.jsx'),
            Path('/root/src/components/Button.jsx'),
            Path('/root/src/components/Card.jsx'),
            Path('/root/src/pages/Home.jsx'),
            Path('/root/src/pages/About.jsx'),
            Path('/root/src/pages/auth/Login.jsx'),
            Path('/root/src/pages/auth/Register.jsx')
        ]
        
        actual_files = get_all_files(Path('/root'))
        self.assertEqual(sorted(str(f) for f in actual_files), sorted(str(f) for f in expected_files))
    
    @patch('src.scanner.file_discovery.get_openai_client')
    def test_filter_files_with_ai(self, mock_get_client):
        """Test AI filtering of files."""
        # Mock OpenAI client
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_message = MagicMock()
        mock_message.content = "src/components/Button.jsx\nsrc/pages/Login.jsx"
        mock_choice = MagicMock()
        mock_choice.message = mock_message
        mock_response.choices = [mock_choice]
        mock_client.chat.completions.create.return_value = mock_response
        mock_get_client.return_value = mock_client
        
        # Input files
        input_files = [
            Path("src/components/Button.jsx"),
            Path("src/pages/Login.jsx"),
            Path("src/utils/helpers.js"),
            Path("src/App.jsx")
        ]
        
        # Expected output: only the files returned by the AI
        expected_output = [
            Path("src/components/Button.jsx"),
            Path("src/pages/Login.jsx")
        ]
        
        actual_output = filter_files_with_ai(input_files, mock_client)
        self.assertEqual(sorted(str(f) for f in actual_output), sorted(str(f) for f in expected_output))


if __name__ == '__main__':
    unittest.main()