# email extraction function
import pandas as pd
import mailparser
from email import policy
from email.parser import BytesParser
import re
import pickle

with open('Phishing_capstone_model.pkl', 'rb') as f:
    phishing_model = pickle.load(f)


def mail_extract(mail):
    #define labels
    labels = [
    'DomainLength','NoOfSubDomain', 'NoOfLetters', 
    'LetterRatio', 'NoOfDigits', 'NoOfAmpersands',
    'IsHTTPS', 'HasSubmitButton',
    'HasPasswordField', 'NoOfImage']

    # extracts email address
    email = mail.from_[0][1]
    # splits domain by @ and only count the last section, should still work with multiple @ signs.
    domain = email.split('@')[-1]
    # takes length of resulting domain
    DomainLength = len(domain)
    # splits domain on '.'
    domain_parts = domain.split('.')
    # counts subdomains
    NoOfSubDomain = max(len(domain_parts) - 2, 0)
    # count the letters in domain
    NoOfLetters = sum(1 for char in domain if char.isalpha())
    #remove periods to count letter ratio
    drop_period = re.sub(r'\.', '', domain)
    # letter ratio: letter/ total. can handle zero sums if necessary
    LetterRatio = round(NoOfLetters / len(drop_period), 3) if len(drop_period) > 0 else 0
    # NoOfDigits
    NoOfDigits = sum(1 for char in domain if char.isdigit())
    # count '&'
    NoOfAmpersands = domain.count('&')
    # define email body / find all https in body with regex / include angel tags
    email_body = mail.body
    #find https links
    https_links = re.findall(r'<https://[^\s"\'>]+>',email_body)
    # binary result
    IsHTTPS = 1 if https_links else 0
    #check subject line to see if there is a title or not
    HasTitle = 1 if mail.subject and mail.subject.strip() else 0 
    # Define password fields htlm and plain text
    html_pass = r'<input[^>]*type=["\']password["\'][^>]*>'
    text_pass = r'\bpassword\b'
    # define for obfuscation with regex / count instances found
    obfuscation = [
        r'&#x[0-9a-fA-F]+;', # HTML hex entities
        r'&#\d+;',           # HTML decimal entities
        r'\\x[0-9a-fA-F]{2}',# Hex escapes
        r'\\u[0-9a-fA-F]{4}'# Unicode escapes
    ]
    # count total obfuscated characters
    NoOfObfuscatedChar = 0
    for char in obfuscation:
        NoOfObfuscatedChar += len(re.findall(char, domain))
    # dataset doesnt count this in the body, or specify type, only in domain.
    #    NoOfObfuscatedChar += len(re.findall(char, email_body))
    # Is obfuscation used
    HasObfuscation = 1 if NoOfObfuscatedChar > 0 else 0
    # define image tag
    image_tag = re.findall(r'<img\s[^>]*src=["\']?[^"\'>]+["\']?[^>]*>', email_body, re.IGNORECASE)
    #NoOfImage
    NoOfImage = len(image_tag)
    #look for password / should show plain text as well as
    HasPasswordField = 0
    if re.search(html_pass, email_body, re.IGNORECASE):
        HasPasswordField = 1
    elif re.search(text_pass, email_body, re.IGNORECASE):
        HasPasswordField = 1
    # Define submit button in email (html)
    submit_button = [r'<button[^>]*type=["\']submit["\'][^>]*>']
    # counts submit button, doesn't need to count past 1, this is a binary categoy / breaks after finding 1 instance of submit
    HasSubmitButton = 0
    for submit in submit_button:
        if re.search(submit, email_body, re.IGNORECASE):
            HasSubmitButton = 1
            break
    # defines features within function
    features = [DomainLength, NoOfSubDomain, NoOfLetters, 
                LetterRatio, NoOfDigits, NoOfAmpersands,
                IsHTTPS, HasSubmitButton,
                HasPasswordField, NoOfImage]

    eml_data = pd.DataFrame([dict(zip(labels, features))])

    #apply the model
    prediction = phishing_model.predict(eml_data)[0]
    
    # returns results
    return {
        "prediction": prediction,
        "labels": {
            "DomainLength": DomainLength,
            "NoOfSubDomain": NoOfSubDomain,
            "NoOfLetters": NoOfLetters,
            "LetterRatio": LetterRatio,
            "NoOfDigits": NoOfDigits,
            "NoOfAmpersands": NoOfAmpersands,
            "IsHTTPs": IsHTTPS,
            "HasSubmitButton": HasSubmitButton,
            "HasPasswordField": HasPasswordField,
            'NoOfImage' : NoOfImage
        }
    }
