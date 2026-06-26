import pandas as pd
from clickhouse_driver import Client
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
import torch
import joblib
import numpy as np

class FeatureExtractor:
    def __init__(self, clickhouse_host='localhost'):
        self.client = Client(host=clickhouse_host, user='default', password='admin')
        self.cmd_encoder = LabelEncoder()
        self.args_vectorizer = TfidfVectorizer(max_features=50)
        self.scaler = StandardScaler()

    def fetch_training_data(self, limit=None):
        limit_clause = f" LIMIT {limit}" if limit is not None else ""
        query = f"SELECT uid, command AS comm, 'none' AS args FROM security_logs.execve_events{limit_clause}"
        data = self.client.execute(query)
        df = pd.DataFrame(data, columns=['uid', 'comm', 'args'])
        
        # THE FIX: Strip hidden null bytes from the training database strings
        df['comm'] = df['comm'].astype(str).str.strip().str.replace('\x00', '')
        
        return df
    def preprocess_and_tensorize(self, df, is_training=True):
        df['args'] = df['args'].fillna('none')
        
        if is_training:
            encoded_cmds = self.cmd_encoder.fit_transform(df['comm']).reshape(-1, 1)
            encoded_args = self.args_vectorizer.fit_transform(df['args']).toarray()
            
            # THE FIX: Scale both UID and Command IDs so they don't blow up the math
            raw_numerical = np.hstack((df[['uid']].values, encoded_cmds))
            scaled_numerical = self.scaler.fit_transform(raw_numerical)
            
            joblib.dump(self.cmd_encoder, 'engine/cmd_encoder.pkl')
            joblib.dump(self.args_vectorizer, 'engine/args_vectorizer.pkl')
            joblib.dump(self.scaler, 'engine/scaler.pkl')
        else:
            # Fallback for inference
            pass

        final_matrix = np.hstack((scaled_numerical, encoded_args))
        return torch.FloatTensor(final_matrix)

if __name__ == "__main__":
    extractor = FeatureExtractor()
    df = extractor.fetch_training_data(limit=10)
    print("Extractor Ready!")
