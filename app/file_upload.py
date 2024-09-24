import os
from werkzeug.utils import secure_filename
from flask import current_app

"""Handles saving the profile picture and returning the file path."""
def save_profile_picture(profile_pic, standard_filename):
    try:
        extension = os.path.splitext(profile_pic.filename)[1]  # Get file extension
        new_filename = f"{standard_filename}{extension}"  # Generate a new filename using user ID
        safe_filename = secure_filename(new_filename)  # Secure the filename

        file_path = os.path.join(current_app.config['PROFILE_PIC_STORAGE_FOLDER'], safe_filename)  # Build the file path
        profile_pic.save(file_path)  # Save the file

        return file_path
    except Exception as e:
        print(f"Error saving file: {str(e)}")
        return None
