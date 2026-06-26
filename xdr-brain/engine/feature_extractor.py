import pandas as pd
from clickhouse_driver import Client
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
import torch
import joblib

class FeatureExtractor:
    def __init__(self, clickhouse_host='localhost'):
        # 1. Connect to our ClickHouse Database
        self.client = Client(host=clickhouse_host)
        
        # 2. Initialize AI Preprocessors
        self.cmd_encoder = LabelEncoder()
        self.args_vectorizer = TfidfVectorizer(max_features=50) # Keep top 50 most important argument tokens
        self.scaler = StandardScaler()

    def fetch_training_data(self, limit=10000):
        print(f"[*] Fetching top {limit} baseline logs from ClickHouse...")
        # Query the eBPF data you streamed in Month 1 & 2
        query = f"SELECT uid, comm, args FROM process_events LIMIT {limit}"
        data = self.client.execute(query)
        
        # Convert to Pandas DataFrame for easy manipulation
        df = pd.DataFrame(data, columns=['uid', 'comm', 'args'])
        print(f"[+] Fetched {len(df)} rows.")
        return df

    def preprocess_and_tensorize(self, df, is_training=True):
        print("[*] Converting raw telemetry into AI matrices...")
        
        # Handle missing values
        df['args'] = df['args'].fillna('')
        
        if is_training:
            # Fit the models on the data AND transform it
            encoded_uids = self.scaler.fit_transform(df[['uid']])
            encoded_cmds = self.cmd_encoder.fit_transform(df['comm']).reshape(-1, 1)
            encoded_args = self.args_vectorizer.fit_transform(df['args']).toarray()
            
            # Save the fitted preprocessors so we can use the EXACT same logic during live inference
            joblib.dump(self.cmd_encoder, 'engine/cmd_encoder.pkl')
            joblib.dump(self.args_vectorizer, 'engine/args_vectorizer.pkl')
            joblib.dump(self.scaler, 'engine/scaler.pkl')
        else:
            # In production, we just transform (we don't learn new normalities on the fly)
            # (Note: Requires adding fallback logic for unseen commands, handled later)
            encoded_uids = self.scaler.transform(df[['uid']])
            encoded_cmds = self.cmd_encoder.transform(df['comm']).reshape(-1, 1)
            encoded_args = self.args_vectorizer.transform(df['args']).toarray()

        # Combine all features into one giant mathematical matrix
        import numpy as np
        final_matrix = np.hstack((encoded_uids, encoded_cmds, encoded_args))
        
        # Convert to a PyTorch Tensor (The native language of our upcoming Neural Network)
        tensor_data = torch.FloatTensor(final_matrix)
        
        print(f"[+] Output Tensor Shape: {tensor_data.shape} (Rows, Features)")
        return tensor_data

if __name__ == "__main__":
    extractor = FeatureExtractor()
    
    # 1. Get the normal behavior data
    raw_dataframe = extractor.fetch_training_data(limit=5000)
    
    # 2. Convert to PyTorch format
    training_tensor = extractor.preprocess_and_tensorize(raw_dataframe, is_training=True)
    
    print("\n[SUCCESS] Feature Extraction Complete.")
    print("Sample vector of a single process execution:")
    print(training_tensor[0])