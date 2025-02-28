# tests/test_json_files.py
import json
import os
import unittest
from pathlib import Path

class TestJSONFiles(unittest.TestCase):
    """Test case for validating JSON files"""
    
    def test_json_files_validity(self):
        """Test that all JSON files are valid and can be parsed"""
        # Get the project root directory
        project_root = Path(__file__).parent.parent
        
        # Define directories to search for JSON files
        data_dirs = [
            project_root / 'data',
            project_root / 'config',
            project_root / 'static' / 'data'
        ]
        
        # Find all JSON files
        json_files = []
        for data_dir in data_dirs:
            if data_dir.exists():
                json_files.extend(data_dir.glob('**/*.json'))
        
        # Make sure we found some files
        self.assertGreater(len(json_files), 0, "No JSON files found to test")
        
        # Test each file
        for json_file in json_files:
            with self.subTest(file=json_file):
                try:
                    with open(json_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    # If we get here, the JSON is valid
                    self.assertIsNotNone(data, f"JSON parsed but returned None: {json_file}")
                except json.JSONDecodeError as e:
                    self.fail(f"Invalid JSON in {json_file}: {str(e)}")
                except Exception as e:
                    self.fail(f"Error reading {json_file}: {str(e)}")

if __name__ == '__main__':
    unittest.main()
