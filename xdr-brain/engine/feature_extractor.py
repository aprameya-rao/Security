import pandas as pd
from clickhouse_driver import Client
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
import torch
import joblib
import numpy as np

class FeatureExtractor:
    def __init__(self, clickhouse_host='localhost'):
        # 1. Database Connection (Replace 'YOUR_PASSWORD' if you used a custom one)
        self.client = Client(
            host=clickhouse_host, 
            user='default', 
            password='admin' 
        )
        
        # 2. AI Preprocessors
        self.cmd_encoder = LabelEncoder()
        self.args_vectorizer = TfidfVectorizer(max_features=50)
        self.scaler = StandardScaler()

    def fetch_training_data(self, limit=None):
        print(f"[*] Fetching top {limit} baseline logs from ClickHouse...")
        
        # THE FINAL SQL FIX: Target security_logs, rename command to comm, and pass 'none' for args
        query = f"SELECT uid, command AS comm, 'none' AS args FROM security_logs.execve_events"
        data = self.client.execute(query)
        
        df = pd.DataFrame(data, columns=['uid', 'comm', 'args'])
        print(f"[+] Fetched {len(df)} rows.")
        return df

    def preprocess_and_tensorize(self, df, is_training=True):
        print("[*] Converting raw telemetry into AI matrices...")
        
        df['args'] = df['args'].fillna('none')
        
        if is_training:
            encoded_uids = self.scaler.fit_transform(df[['uid']])
            encoded_cmds = self.cmd_encoder.fit_transform(df['comm']).reshape(-1, 1)
            encoded_args = self.args_vectorizer.fit_transform(df['args']).toarray()
            
            joblib.dump(self.cmd_encoder, 'engine/cmd_encoder.pkl')
            joblib.dump(self.args_vectorizer, 'engine/args_vectorizer.pkl')
            joblib.dump(self.scaler, 'engine/scaler.pkl')
        else:
            encoded_uids = self.scaler.transform(df[['uid']])
            # Fallback for live inference handled here
            encoded_cmds = self.cmd_encoder.transform(df['comm']).reshape(-1, 1)
            encoded_args = self.args_vectorizer.transform(df['args']).toarray()

        # Combine into one matrix
        final_matrix = np.hstack((encoded_uids, encoded_cmds, encoded_args))
        tensor_data = torch.FloatTensor(final_matrix)
        
        print(f"[+] Output Tensor Shape: {tensor_data.shape} (Rows, Features)")
        return tensor_data

if __name__ == "__main__":
    extractor = FeatureExtractor()
    raw_dataframe = extractor.fetch_training_data(limit=5000)
    training_tensor = extractor.preprocess_and_tensorize(raw_dataframe, is_training=True)
    
    print("\n[SUCCESS] Feature Extraction Complete.")
