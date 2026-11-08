from pathlib import Path
import pandas as pd
import numpy as np

TARGET = 'Machine failure'
FEATURES = ['Type', 'Air temperature [K]', 'Process temperature [K]',
            'Rotational speed [rpm]', 'Torque [Nm]', 'Tool wear [min]']
FORBIDDEN = ['UDI', 'Product ID', TARGET, 'TWF', 'HDF', 'PWF', 'OSF', 'RNF']

class SensorValidator:
    """Reject invalid records rather than silently clipping physical measurements."""
    def validate(self, frame, require_target=False):
        required = FEATURES + ([TARGET] if require_target else [])
        missing = set(required) - set(frame.columns)
        if missing:
            raise ValueError(f'Missing columns: {sorted(missing)}')
        if len(frame) == 0:
            raise ValueError('Empty batch')
        if not frame.Type.isin(['L','M','H']).all():
            raise ValueError('Unknown product type')
        for col in FEATURES[1:]:
            if not pd.api.types.is_numeric_dtype(frame[col]) or pd.api.types.is_bool_dtype(frame[col]):
                raise ValueError(f'Sensor must contain numeric values, not strings/bools: {col}')
            values = pd.to_numeric(frame[col], errors='raise')
            if np.isinf(values).any():
                raise ValueError(f'Infinite value: {col}')
            if (values.dropna() < 0).any():
                raise ValueError(f'Negative physical value: {col}')
            if values.isna().all():
                raise ValueError(f'Entire sensor missing: {col}')
        if require_target and not frame[TARGET].isin([0,1]).all():
            raise ValueError('Target must be binary and observed')
        return frame


def features(frame):
    # Whitelist prevents accidental leakage from failure-mode columns and identifiers.
    SensorValidator().validate(frame)
    return frame.loc[:, FEATURES].copy()


def load_data(path):
    frame = pd.read_csv(Path(path))
    SensorValidator().validate(frame, require_target=True)
    if 'UDI' not in frame or frame.UDI.duplicated().any():
        raise ValueError('Unique observation identifier required')
    return frame.sort_values('UDI').reset_index(drop=True)


def ordered_splits(frame):
    """Order-preserving sensitivity benchmark, NOT a verified real-time split.

    UDI is an observation identifier, not an asset identifier or real timestamp.
    Train 60%, model selection 15%, threshold calibration 10%, held-out test 15%.
    """
    n = len(frame)
    a,b,c = int(n*.60),int(n*.75),int(n*.85)
    return dict(train=frame.iloc[:a].copy(), selection=frame.iloc[a:b].copy(),
                calibration=frame.iloc[b:c].copy(), test=frame.iloc[c:].copy())
