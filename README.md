# Library Management System

## Overview
The Library Management System is a web-based application designed to manage books, users, and lending activities in a library setting. It allows librarians or administrators to add, delete, update, and lend books, as well as manage user accounts.

## Features
- **User Authentication:** Users can register, login, and logout from the system. Different user roles (e.g., manager, regular user) have different permissions.
- **Book Management:** Admins can add new books, delete existing books, and update book details such as name, author, and publication date.
- **Lending Management:** Books can be lent to users and returned to the library. The system tracks the lending status of each book.
- **User Management:** Admins can view all registered users, delete user accounts, and update user roles.

## Technologies Used
- **Frontend:** HTML, CSS, JavaScript
- **Backend:** Python (Flask framework)
- **Database:** SQLite (for simplicity, can be replaced with a more robust database like PostgreSQL)
- **HTTP Requests:** Axios library for making HTTP requests from the frontend to the backend

## Getting Started
1. **Clone the Repository:**
   ```bash
   git clone https://github.com/BinaleGit/project1.git
   ```

2. **Navigate to the Project Directory:**
   ```bash
   cd project1
   ```

3. **Install Dependencies:**
   Ensure you have Python and Flask installed. Install the required Python packages using pip:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the Application:**
   ```bash
   python app.py
   ```

5. **Access the Application:**
   Open your web browser and navigate to http://localhost:5000 to access the Library Management System.

## Contributors
- [Roee Bina](https://github.com/BinaleGit)

