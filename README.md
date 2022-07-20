# Website Phishing Detection
A Heroku-powered web application that supports phishing detection of malicious websites.


## Model Training
Check [Colab Notebook](https://colab.research.google.com/drive/1Ec8_BJpwzPgljvQvRoO36aHy0ql0RQIS?usp=sharing)

## Deploy locally
1. Clone source code
```
git clone https://github.com/ngfuong/phishing-detector
```
2. Create virtual environment
```
python -m venv ./venv
source ./venv/bin/activate
pip install -r requirements.txt
```
3. Run web application locally (in debug mode).
Disable debug in line 25, `app.py`
```
python app.py
```
## Deploy on Heroku (TBU)
