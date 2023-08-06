import smtplib
from pathlib import Path
import json
import ssl
from email.mime.text import MIMEText


def send_email(subject, body, sender, receiver, smtp_server, smtp_port):
    base_dir = Path(__file__).parent.resolve()
    cur_path = base_dir.joinpath('config.json')
    print(cur_path)
    with open(cur_path) as json_config:
        cred_data_json = json.load(json_config)
    login = str(cred_data_json['email'])
    password = str(cred_data_json['pass'])
    message = MIMEText(body)
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = receiver

    print(login, password)
    try:
        smtp = smtplib.SMTP(smtp_server, smtp_port)
        context_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS)
        smtp.starttls(context=context_ssl)
        smtp.login(login, password)
        print(login, password)
        smtp.sendmail(sender, receiver, str(message))
        smtp.quit()
        print("Email sent successfully")
    except Exception as e:
        print("Failed to send email:", str(e))


def send_to_yandex(subject, body, sender, receiver):
    send_email(subject, body, sender, receiver, 'smtp.yandex.ru', 587)
