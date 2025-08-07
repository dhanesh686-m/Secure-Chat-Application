# Secure Chat Application 🔒💬

This project implements a basic secure chat application with a client-server architecture using Python. It demonstrates end-to-end encryption for messages exchanged between clients, leveraging RSA for key exchange and AES-256 (GCM mode) for message encryption. The client features a simple Graphical User Interface (GUI) built with tkinter.

# Features ✨

   1.Client-Server Architecture: A central Python server relays encrypted messages between clients.

   2.End-to-End Encryption: Messages are encrypted on the sender's client and decrypted only on the recipient's client. The server never sees plaintext messages.

   3.RSA Key Exchange: RSA asymmetric encryption is used to securely exchange symmetric AES keys between chat participants.

   4.AES-256 GCM Message Encryption: All chat messages are encrypted using AES-256 in Galois/Counter Mode (GCM), providing both confidentiality and integrity.

   5.GUI Client: An interactive graphical interface for ease of use.


# Create Instance on your preferred webservice provider(I have Used AWS as my Webservice Provider)

  1. Sign In to AWS Management Console 🚀 using -  https://aws.amazon.com/console/
    
  2. Navigate to EC2 Dashboard ☁️ AND In the left-hand navigation pane, under "Instances," click on Instances.
    
  3. Launch a New Instance ➕
     
  4. Choose an Amazon Machine Image (AMI) 🐧
     
      i)Give your instance a descriptive Name
     
     ii)Select an Amazon Machine Image (AMI) :- I have used Amazon Linux and Make sure to select the correct architecture (usually 64-bit (x86)).
     
  5.Choose an Instance Type 💻 : I have Used t2.micro
  
  6.Create or Select a Key Pair (Login) 🔑
  
   i)Create new key pair. Give it a Key pair name
        
   ii)Click Create key pair. Your private key file (.pem) will be downloaded automatically. Keep this file secure and            private! You will need it to SSH into               your instance.
       
   iii)If you already have a key pair, select it from the dropdown.
      
  7.Configure Network Settings 🌐
  
   i)Click Edit Network Settings
      
   ii)Security group name: Give it a name
     
   iii)Inbound security group rules:

   Rule 1 (SSH): By default, SSH (Port 22) is usually added. Ensure its Source type is set to My IP (for your current IP) or Anywhere (0.0.0.0/0) if you need to connect from     various locations (less secure).

   Rule 2 (Chat App Port): Click Add security group rule.

   Type: Select Custom TCP.

   Port range: Enter 65432.

   Source type: Select Anywhere-IPv4 (0.0.0.0/0). This is crucial for your chat clients to connect from anywhere on the internet.

   Description (optional): Chat App Port
  
  8.Configure Storage 💾 : The default 8 GiB (Gigabytes) of General Purpose SSD (gp2 or gp3) is usually sufficient for a basic server. You can increase it if needed, but stay     within the free tier limits if applicable.
  
  9.Review and Launch 🚀 : Review all your settings before launching And Click Launch instance.
  
 10. After Launching the Instance , Check the status as Running and then check for your Public IP address.

# Upload your server.py

From your local terminal :scp -i /path/to/your/key-pair-name.pem /path/to/local/server.py ec2-user@YOUR_PUBLIC_IP_ADDRESS:/home/ec2-user

   Replace /path/to/your/key-pair-name.pem with the actual path and filename of your .pem
      
   Replace /path/to/local/server.py with actual path and filename of your server.py file

# Connect EC2 instance using .pem file

  1.Locate Your .pem File 📂
  
  2.Set Correct Permissions using command : chmod 400 /path/to/your/key-pair-name.pem
  
   Replace /path/to/your/key-pair-name.pem with the actual path and filename of your .pem
      
  3.Connect to Your EC2 Instance via SSH 🚀 using command : ssh -i /path/to/your/key-pair-name.pem ec2-user@YOUR_PUBLIC_IP_ADDRESS
  
   Replace /path/to/your/key-pair-name.pem with the actual path and filename of your .pem

# Running Server in EC2 terminal

  1. Use ls cmd to verify the server.py file
    
  2. Install some dependencies using the followinf Commands :
     
         i)sudo apt update
     
         ii)sudo apt install python3-pip
     
         iii)pip3 install cryptography
     
  3. Use the following command to start the server : python3 server.py

# Running Client in Local Machine

  1.Open Terminal on your local machine  :  NOTE:- Not in EC2 terminal
  
  2.Use the following command to run client.py : python3 client.py

## Enter The username and Hit enter

### Enter the username of reciptent in the assinged place 

### Enter the message in the assinged place and hit enter

### To see Active users , Click "List of Active user".


# Enjoy Chatting without any risk of privacy!!
