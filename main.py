import streamlit as st
from cryptography.fernet import Fernet

# objectives 
# user sign up
# login user should be authrized 
#fill in data , data should be stord in stored data object
# decrpt data ask for password if given password is correct show data 
# 3 attempts
st.set_page_config(page_icon="📝" ,layout="wide",page_title="DataEncryption")
st.title("SECURE DATA ENCRYPTION APP✨📔")

stored_Data = {
    "Data_password":"",
    "Encrypted_Data":""    
}
# putting in session state so that data is not lost 
if "stored_Data" not in st.session_state:
    st.session_state.stored_Data = stored_Data.copy()
stored_Data = st.session_state.stored_Data

User = {
    "email":"",
    "Signup_password":"",
}
# putting in session state so that data is not lost 
if "User" not in st.session_state:
    st.session_state.User = User.copy()
User = st.session_state.User

# Generating Fernet Key
KEY = Fernet.generate_key()
# session state
if "KEY" not in st.session_state:
    st.session_state.KEY = Fernet.generate_key()
# variable to store fernet Key    
cipher = Fernet(st.session_state.KEY)

# Global variable for cheking if user is authorized 
is_authorized = False 
# session state
if "is_authorized" not in st.session_state:
    st.session_state.is_authorized = False
is_authorized = st.session_state.is_authorized    

st.sidebar.title("READY TO USE")
choices = st.sidebar.selectbox("CHOOSE FROM THE FOLLOWING",[
    "SIGN UP",
    "LOG IN",
    "ENCRYPT DATA",
    "DECRYPT DATA"
])
  
if choices == "SIGN UP":
    def sign_up(signup_Email,signup_password):
            User["email"]= signup_Email
            User["Signup_password"] = cipher.encrypt(signup_password.encode()).decode()
        
    signup_Email=st.text_input("Enter your Email")
    signup_password =st.text_input("enter yout pasword", type="password")
        
    if st.button("Sign up"):
        if not signup_Email.strip() or not signup_password.strip():
            st.warning("All fields are required.")
        else:    
            sign_up(signup_Email,signup_password)
            st.success("Your Sign up is successful ✨ Make sure to log in now")
    
print(User)    

if choices == "LOG IN":
    def Log_in(login_Email,login_Password):
        passkey = User.get("Signup_password")
        if passkey:
            decrypt_pass = cipher.decrypt(passkey.encode()).decode()
            if decrypt_pass == login_Password and User.get("email") == login_Email:
                st.session_state.is_authorized = True
                st.success("You are logged in successfully ✨")
            else:
                st.error("Log in failed")
        else:
            st.error("Looks like You are not signed up make sure to sign up frist📂")              
          
        
    st.title("TIME TO LOGIN")        
    login_Email= st.text_input("Enter your Email")
    login_Password= st.text_input("Enter your password",type="password")
    if st.button("log in"):
        Log_in(login_Email,login_Password)
        
if choices == "ENCRYPT DATA":
    st.title("ENCRYPT YOUR DATA")

    if st.session_state.is_authorized == True:
        def encrypt_data(data_password, encrypted_data):
            stored_Data["Data_password"] = cipher.encrypt(data_password.encode()).decode()
            stored_Data["Encrypted_Data"] = cipher.encrypt(encrypted_data.encode()).decode()

        data_pass_input = st.text_input("Make a secure data password", type="password") 
        data_input = st.text_area("Enter your Data")              

        if st.button("Encrypt Data"):
            if not data_pass_input.strip() or not data_input.strip():
                st.warning("All fields are required.")
            else:
                encrypt_data(data_pass_input, data_input)
                st.success("Your data is encrypted successfully ✨")    
    else:
        st.error("⚠️ You are not logged in. Please log in to encrypt your data.")
    
    
if choices == "DECRYPT DATA":
    if st.session_state.is_authorized:

        # Initialize attempt counter
        if "decrypt_attempts" not in st.session_state:
            st.session_state.decrypt_attempts = 0

        st.title("🔐 DECRYPT YOUR DATA")

        retrival_pass_input = st.text_input("Enter your encryption password", type="password")

        if st.button("Decrypt Data"):

            if not retrival_pass_input.strip():
                st.warning("Please enter your encryption password.")
            else:
                decrypted_password = cipher.decrypt(stored_Data.get("Data_password").encode()).decode()

                if retrival_pass_input == decrypted_password:
                    data = cipher.decrypt(stored_Data.get("Encrypted_Data").encode()).decode()
                    st.success("Decryption successful!")
                    st.write(f"Your Saved Data:\n\n**{data}**")
                    st.session_state.decrypt_attempts = 0  # Reset on success

                else:
                    st.session_state.decrypt_attempts += 1
                    remaining = 3 - st.session_state.decrypt_attempts

                    if st.session_state.decrypt_attempts >= 3:
                        st.error("🔒 Too many failed attempts. You have been logged out.")
                        st.session_state.is_authorized = False
                        st.session_state.decrypt_attempts = 0
                    else:
                        st.warning(f"❌ Incorrect password. {remaining} attempts remaining.")

    else:
        st.error("🚫 You are not logged in.")
