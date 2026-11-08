import json
import unittest
from pathlib import Path
import pandas as pd
from maintenance.data import load_data,features,ordered_splits,FORBIDDEN,SensorValidator
from maintenance.train import threshold_cost
from maintenance.inference import model_fn,input_fn,predict_fn,output_fn
from maintenance.monitor import quality_report
ROOT=Path(__file__).resolve().parents[1]
class CoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.frame=load_data(ROOT/'data/ai4i2020.csv')
    def test_no_leakage_features(self):
        self.assertFalse(set(features(self.frame).columns)&set(FORBIDDEN))
    def test_disjoint_ordered_splits(self):
        parts=ordered_splits(self.frame); previous=-1; seen=set()
        for part in parts.values():
            self.assertGreater(part.UDI.min(),previous); previous=part.UDI.max()
            ids=set(part.UDI); self.assertFalse(ids&seen);seen|=ids
        self.assertEqual(len(seen),len(self.frame))
    def test_missing_column_rejected(self):
        with self.assertRaises(ValueError):features(self.frame.drop(columns='Torque [Nm]'))
    def test_negative_sensor_rejected(self):
        f=self.frame.head().copy();f.loc[0,'Torque [Nm]']=-1
        with self.assertRaises(ValueError):features(f)
    def test_numeric_strings_rejected(self):
        f=self.frame.head().copy();f['Torque [Nm]']=f['Torque [Nm]'].astype(str)
        with self.assertRaises(ValueError):features(f)
    def test_missing_target_rejected(self):
        f=self.frame.head().copy();f.loc[0,'Machine failure']=None
        with self.assertRaises(ValueError):SensorValidator().validate(f,True)
    def test_cost_tradeoff(self):
        self.assertEqual(threshold_cost([1,0],[.2,.8],.5),11)
    def test_inference_roundtrip(self):
        model=model_fn(ROOT/'reports')
        body=json.dumps({'records':features(self.frame.head(3)).to_dict(orient='records')})
        pred=predict_fn(input_fn(body,'application/json'),model)
        result=json.loads(output_fn(pred,'application/json'))
        self.assertEqual(len(result['probabilities']),3)
        self.assertTrue(all(0<=p<=1 for p in result['probabilities']))
    def test_invalid_content_type(self):
        with self.assertRaises(ValueError):input_fn('','text/plain')
    def test_monitor_detects_large_shift(self):
        ref=json.loads((ROOT/'reports/reference.json').read_text()); f=features(self.frame.head(100))
        f['Torque [Nm]']+=200
        self.assertTrue(quality_report(f,ref)['checks']['Torque [Nm]']['review_required'])
if __name__=='__main__':unittest.main()
