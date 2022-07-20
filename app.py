from flask import Flask, request, render_template

from model import load_model_from_checkpoint, get_prediction 


app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/predict', methods=['POST'])
def predict():
    request_list = request.form.to_dict()
    print("Request:", request_list)
    url = request_list['url']
    prediction = get_prediction(url, model)
    return render_template('index.html', prediction_text='This URL is {}'.format(prediction))

if __name__ ==  "__main__":
    # load model at creation time
    model = load_model_from_checkpoint(path='./rforest.pkl')
    print("Model loaded!")
    app.run(port=5000, debug=True)



