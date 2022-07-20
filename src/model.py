import pickle
import json
import argparse
import numpy as np
from src.feature_extraction import generate_features, features_to_dict 


def load_model_from_checkpoint(path="rforest.pkl"):
    """
    Loads a model from a file
    """
    with open(path, 'rb') as f:
        return pickle.load(f)


def predict_single(X, model):
    """
    X: np array
    Predicts the class of a given instance
    """
    # process single example
    X = X.reshape(1, -1)
    score = model.predict_proba(X)

    return score

def get_prediction(url, model):
    """
    url: string
    model: sklearn model
    """
    features = generate_features(url)
    if features is False:
        return False
    else:
        score = predict_single(features, model)
        classes = ["Malicious", "Benign"]
        prediction = np.argmax(score)
        return classes[prediction]

def parse_arguments():
    parser = argparse.ArgumentParser(description='Predict URL')
    parser.add_argument('-u', '--url', help='URL to be analyzed', required=True)
    parser.add_argument('-o', '--output', help='Output website features to json', default='features.json',required=False)
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    args = parse_arguments()
    #url = args.url
    if args.url is None:
        url = "machinelearningmastery.com"
    else:
        url = args.url

    print(f"Input URL: {url}")
    print(f"***Getting website information...")
    features = generate_features(url)
    if features is False:
        print("!!!Failed to connect to URL. Check your hostname or internet connection.")
    else:
        print(f"***Loading model...")
        model = load_model_from_checkpoint()

        # debug
        # print("Features:", features)
        if args.output:
            print(f"***Printing features to file: {args.output}")
            with open(args.output, 'w') as f:
                dct = features_to_dict(features, args.output)
                f.write(json.dumps(dct))

        print(f"***Predicting...")
        score = get_prediction(features, model)
        # debug
        print("Estimated score:", score)
        
        classes = ["Malicious", "Benign"]

        prediction = np.argmax(score)
        print("Prediction: This website seems to be ", classes[prediction])