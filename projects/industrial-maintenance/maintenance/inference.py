"""SageMaker-style model_fn/input_fn/predict_fn/output_fn; tested locally only."""
import json
from io import StringIO
from pathlib import Path
import joblib
import pandas as pd
from .data import features

def model_fn(model_dir):
    # Only load trusted artifacts; pickle/joblib can execute code.
    return joblib.load(Path(model_dir)/'model.joblib')

def input_fn(body, content_type):
    if content_type=='application/json':
        frame=pd.DataFrame(json.loads(body)['records'])
    elif content_type=='text/csv':
        frame=pd.read_csv(StringIO(body))
    else:
        raise ValueError('Supported: application/json, text/csv')
    return features(frame)

def predict_fn(data,model):
    p=model['pipeline'].predict_proba(data)[:,1]
    return {'probabilities':p.tolist(),'alerts':(p>=model['threshold']).tolist(),
            'threshold':model['threshold'],'task':'current-record fault classification'}

def output_fn(prediction,accept):
    if accept!='application/json':raise ValueError('Only application/json supported')
    return json.dumps(prediction)
