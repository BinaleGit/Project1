from flask import Flask, render_template, send_file, send_from_directory
import os

api = Flask(__name__)

# Define the path to the frontend folder
frontend_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend")

@api.route('/')
def index():
    # Send the index.html file from the frontend folder
    return send_file(os.path.join(frontend_folder, 'index.html'))


@api.route('/page1')
def page1():
    # Send the index.html file from the frontend folder
    return send_file(os.path.join(frontend_folder, 'page1.html'))


@api.route('/page2')
def page2():
    # Send the index.html file from the frontend folder
    return send_file(os.path.join(frontend_folder, 'page2.html'))




if __name__ == '__main__':
    api.run(debug=True)


