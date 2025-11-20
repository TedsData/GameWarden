from flask import Flask, request, render_template
import pickle
import pandas as pd
import mailparser

#import function for extracting mail data
from mail_extractor import mail_extract 

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/upload')
def upload_page():
    return render_template('upload.html')

# Load your trained model
with open('Phishing_capstone_model.pkl', 'rb') as f:
    phishing_model = pickle.load(f)

# defines rout for get /post reqyest
@app.route('/', methods=['GET', 'POST'])
def upload():
    #checks for submission
    if request.method == 'POST':
        # retrieve .eml file
        file = request.files['eml_file']

        # checks for eml file
        if not file.filename.lower().endswith('.eml'):
            # returns error message
            error_message = "Invalid file type. Please upload a .eml file."
            return render_template('upload.html', error=error_message)
        try:
            # Parses email
            mail = mailparser.parse_from_bytes(file.read())
            # runs phishing model
            prediction = mail_extract(mail)
            # converts results to words
            #result = "Phishing" if prediction == 1 else "Not Phishing"
            result = "Phishing" if prediction["prediction"] == 1 else "Not Phishing"
            # added
            labels = prediction.get("labels", {})
            # return results
            #return render_template('result.html', result=result)
            return render_template('result.html', result=result, labels=labels)
        
        except Exception as e:
            # returns error message
            error_message = f"Failed to process the file: {str(e)}"
            return render_template('upload.html', error=error_message)

    return render_template('upload.html')


@app.route('/resume')
def resume():
    return render_template('resume.html')

@app.route('/General_Projects')
def powerbi():
    return render_template('General_Projects.html')