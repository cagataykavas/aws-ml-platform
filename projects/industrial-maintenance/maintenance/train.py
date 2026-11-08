import argparse
import hashlib
import json
import platform
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.metrics import average_precision_score, precision_score, recall_score, f1_score, confusion_matrix
from .data import TARGET, FEATURES, load_data, features, ordered_splits


def make_pipeline(estimator):
    numeric = Pipeline([('impute',SimpleImputer(strategy='median',add_indicator=True)),('scale',StandardScaler())])
    prep = ColumnTransformer([('numeric',numeric,FEATURES[1:]),
                              ('type',OneHotEncoder(handle_unknown='ignore',sparse_output=False),['Type'])])
    return Pipeline([('prepare',prep),('model',estimator)])


def threshold_cost(y, probability, threshold, fn_cost=10, fp_cost=1):
    pred = np.asarray(probability) >= threshold
    y = np.asarray(y)
    return float(fn_cost*np.sum((y==1)&~pred) + fp_cost*np.sum((y==0)&pred))


def metrics(y,p,threshold):
    pred=np.asarray(p)>=threshold
    tn,fp,fn,tp=confusion_matrix(y,pred,labels=[0,1]).ravel()
    return {'rows':len(y),'positives':int(np.sum(y)),
            'average_precision':float(average_precision_score(y,p)),
            'precision':float(precision_score(y,pred,zero_division=0)),
            'recall':float(recall_score(y,pred,zero_division=0)),
            'f1':float(f1_score(y,pred,zero_division=0)),
            'confusion_matrix':{'tn':int(tn),'fp':int(fp),'fn':int(fn),'tp':int(tp)},
            'example_cost_fn10_fp1':threshold_cost(y,p,threshold)}


def run(csv_path, output):
    output=Path(output); output.mkdir(parents=True,exist_ok=True)
    frame=load_data(csv_path); parts=ordered_splits(frame)
    candidates={
        'logistic':LogisticRegression(max_iter=1000,class_weight='balanced',random_state=42),
        'random_forest':RandomForestClassifier(n_estimators=250,min_samples_leaf=3,class_weight='balanced',random_state=42,n_jobs=2),
        'hist_gradient_boosting':HistGradientBoostingClassifier(max_iter=150,max_leaf_nodes=15,l2_regularization=2,random_state=42),
    }
    fitted={}; scores={}
    for name,estimator in candidates.items():
        pipe=make_pipeline(estimator)
        pipe.fit(features(parts['train']),parts['train'][TARGET])
        probability=pipe.predict_proba(features(parts['selection']))[:,1]
        scores[name]=float(average_precision_score(parts['selection'][TARGET],probability))
        fitted[name]=pipe
    winner=max(scores,key=scores.get); pipeline=fitted[winner]
    calibration=parts['calibration']; cp=pipeline.predict_proba(features(calibration))[:,1]
    # Include no-alert policy. Stable tie break favors higher thresholds/fewer alerts.
    thresholds=np.linspace(0,1.0001,1002)
    threshold=float(min(thresholds,key=lambda t:(threshold_cost(calibration[TARGET],cp,t),-t)))
    test=parts['test']; p=pipeline.predict_proba(features(test))[:,1]
    score=metrics(test[TARGET].to_numpy(),p,threshold)
    bundle={'pipeline':pipeline,'threshold':threshold,'features':FEATURES,'model_name':winner}
    joblib.dump(bundle,output/'model.joblib')
    report={'task':'Current-record fault classification, not advance failure prediction or RUL',
            'dataset':'UCI AI4I 2020, public synthetic benchmark',
            'source_sha256':hashlib.sha256(Path(csv_path).read_bytes()).hexdigest(),
            'split':'UDI ordered blocks; no claim that UDI is a real timestamp or machine ID',
            'split_rows':{k:len(v) for k,v in parts.items()},
            'split_positive_counts':{k:int(v[TARGET].sum()) for k,v in parts.items()},
            'selection_average_precision':scores,'winner':winner,'threshold':threshold,
            'test':score,'test_no_skill_average_precision':float(test[TARGET].mean()),
            'test_all_negative_cost':int(10*test[TARGET].sum()),
            'cost_warning':'10:1 is an illustrative preference, not measured economics',
            'versions':{'python':platform.python_version(),'sklearn':sklearn.__version__,'pandas':pd.__version__,'numpy':np.__version__},
            'cloud_execution':False}
    (output/'metrics.json').write_text(json.dumps(report,indent=2))
    pd.DataFrame({'UDI':test.UDI,'actual':test[TARGET],'probability':p,'alert':p>=threshold}).to_csv(output/'predictions.csv',index=False)
    # Precomputed exports for optional approved AWS comparison. Final test never enters AutoML.
    for key in ['train','selection']:
        pd.concat([features(parts[key]),parts[key][TARGET]],axis=1).to_csv(output/f'autopilot_{key}.csv',index=False)
    reference={c:{'mean':float(parts['train'][c].mean()),'std':float(parts['train'][c].std()),'missing':float(parts['train'][c].isna().mean())} for c in FEATURES[1:]}
    (output/'reference.json').write_text(json.dumps(reference,indent=2))
    print(json.dumps(report,indent=2)); return report

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--data',default='data/ai4i2020.csv'); parser.add_argument('--output',default='reports')
    args=parser.parse_args();run(args.data,args.output)
