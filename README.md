Photos App – User Image Upload & Management System 

What is this Application?

This is a lightweight, Flask-based web application that allows users to:

Register and log in securely

Upload JPG and PNG images

Store images in Azure Blob Storage

View, manage, and delete uploaded photos

Reset forgotten passwords

It’s styled using Bootstrap 5 and integrates seamlessly with MySQL and Azure for real-world deployability. Ideal for prototyping cloud-connected gallery apps.

⚙️ Prerequisites & Dependencies
To run this application locally, ensure the following libraries and services are set up:

Python Requirements
Install with pip install -r requirements.txt (create this based on below list):

txt
Copy
Edit
Flask
Flask_SQLAlchemy
Werkzeug
python-magic
pymysql
azure-storage-blob
Additional Requirements
Python 3.8+

MySQL database (local or remote)

An Azure Storage Account with Blob service enabled

Set environment variable for connection string:


export AZURE_STORAGE_CONNECTION_STRING="DefaultEndpointsProtocol=...;"

Application Flow – Step-by-Step
1. User Registration (/register)
Input: username, email, password

Validates password (min 8 chars, 1 uppercase, 1 special)

Stores hashed password in MySQL
![Screenshot_20-7-2025_153149_127 0 0 1](https://github.com/user-attachments/assets/a7c00d06-ae5e-41ba-b51f-7f32c000902b)


2. Login (/login)
Accepts email or username + password

Validates via database and creates session

Redirects to main gallery view
![Screenshot_20-7-2025_153026_127 0 0 1](https://github.com/user-attachments/assets/3abffa4e-6efc-43c0-b742-e3efcba3d82e)

Photosphere Login Error UI – User Not Found Prompt on Authentication Page
![Screenshot_20-7-2025_153121_127 0 0 1](https://github.com/user-attachments/assets/b3783132-e49f-415e-ac0e-4b55f1ad46dc)

Photosphere Login UI – Registration Success Alert on Sign-In Page
![Screenshot_20-7-2025_153456_127 0 0 1](https://github.com/user-attachments/assets/47eaca06-abbb-4bde-91f3-0433f7a512fe)


3. View Gallery (/)
Authenticated users are shown:

Upload form (supports multiple images)
![Screenshot_20-7-2025_153646_127 0 0 1](https://github.com/user-attachments/assets/0ec5991f-8cb6-41bb-8c28-ffc764fcaeff)


A grid of uploaded photos (fetched from Azure)

4. Photo Upload (/upload-photos)
Accepts multiple .jpg, .jpeg, .png files

Checks MIME type using python-magic

Uploads valid files to Azure Blob Storage

Overwrites if filename exists

Shows success/failure flash messages
![Screenshot_20-7-2025_153731_127 0 0 1](https://github.com/user-attachments/assets/3763c841-d446-4a0a-a69a-e0cad3e48091)
![Screenshot_20-7-2025_153835_127 0 0 1](https://github.com/user-attachments/assets/7095709a-84a6-4488-9477-66d5f21f8df7)


5. Delete Photo (/delete-photo/<filename>)

Delete button for each photo
![WhatsApp Image 2025-07-20 at 15 41 10_370ce7fa](https://github.com/user-attachments/assets/2a860831-ccc0-40fc-9fca-98c500dce495)

Deletes blob file from Azure

Confirm modal used before action
![Screenshot_20-7-2025_154057_127 0 0 1](https://github.com/user-attachments/assets/4f81a7e2-7d61-426c-9a2e-15b928ec0324)
![Screenshot_20-7-2025_154131_127 0 0 1](https://github.com/user-attachments/assets/ea3e05b6-d666-4852-bdc6-ec911a15dc88)



6. Forgot Password (/forgot-password)
User enters email

If exists, redirects to /reset-password/<email>
![Screenshot_20-7-2025_154322_127 0 0 1](https://github.com/user-attachments/assets/058eb702-7bde-40a7-bd9a-dcd0cdd5758f)


7. Reset Password
Enter new password twice

Validates and updates the hashed password in DB
![Screenshot_20-7-2025_154435_127 0 0 1](https://github.com/user-attachments/assets/928f8066-017d-4a89-80cf-c774de2eeb9a)

Photosphere Login UI – Password Reset Success Notification
![Screenshot_20-7-2025_154451_127 0 0 1](https://github.com/user-attachments/assets/e36b78a2-406b-4101-9a21-79cf53f58955)


8. Logout (/logout)
Clears session

Redirects to login with flash message
![Screenshot_20-7-2025_15427_127 0 0 1](https://github.com/user-attachments/assets/222a8f5a-d9a5-4117-a214-efadaca20b6d)



Extra Features
Bootstrap 5 UI: Fully responsive and modern design using Bootstrap & Bootstrap Icons

Session-based authentication: Only logged-in users can upload/delete

Secure password hashing: Uses werkzeug.security

MIME type validation: Prevents malicious file uploads

Modal confirmation for delete: Prevents accidental deletions

Flash messaging system: Real-time feedback for actions

Email or Username login: Flexible for end-users

Password reset flow: Realistic recovery implementation

Final Note
This is a demo application, intended to showcase core features such as user auth, cloud storage, and photo management. A fully production-ready module is under development — which will include:

Advanced user role management

Secure file name handling

Rate-limiting and CAPTCHA

End-to-end encryption

Full CI/CD & deployment readiness

Stay tuned — this is just the beginning of something powerful.


