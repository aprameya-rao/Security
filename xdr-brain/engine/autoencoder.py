import torch
import torch.nn as nn
import torch.optim as optim
from feature_extractor import FeatureExtractor
import os

# ==========================================
# HARDWARE DETECTION (GPU Fallback to CPU)
# ==========================================
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"[*] AI Engine Initializing. Hardware selected: {device.type.upper()}")

class ZeroDayAutoencoder(nn.Module):
    def __init__(self, input_dim):
        super(ZeroDayAutoencoder, self).__init__()
        
        # ENCODER: Compress the system log to learn the "normal" pattern
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, 8) # The Bottleneck
        )
        
        # DECODER: Attempt to reconstruct the original log
        self.decoder = nn.Sequential(
            nn.Linear(8, 16),
            nn.ReLU(),
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.Linear(32, input_dim),
            nn.Sigmoid() # Normalize output
        )

    def forward(self, x):
        bottleneck = self.encoder(x)
        reconstructed = self.decoder(bottleneck)
        return reconstructed

def train_model(epochs=50, batch_size=64):
    # 1. Fetch and Preprocess Data
    extractor = FeatureExtractor()
    df = extractor.fetch_training_data(limit=None)
    
    # Get the Tensor and shoot it to the GPU (or CPU)
    data_tensor = extractor.preprocess_and_tensorize(df, is_training=True)
    data_tensor = data_tensor.to(device)
    
    input_dim = data_tensor.shape[1]

    # 2. Initialize Model, Loss Function, and Optimizer
    model = ZeroDayAutoencoder(input_dim).to(device)
    criterion = nn.MSELoss() # Mean Squared Error (Calculates Reconstruction Error)
    optimizer = optim.Adam(model.parameters(), lr=0.001)

    print(f"\n[*] Commencing Unsupervised Training on {len(df)} Baseline Logs...")
    model.train()
    
    # 3. The Training Loop
    for epoch in range(epochs):
        permutation = torch.randperm(data_tensor.size()[0])
        epoch_loss = 0
        
        for i in range(0, data_tensor.size()[0], batch_size):
            indices = permutation[i:i+batch_size]
            batch_x = data_tensor[indices]

            # Forward pass: Try to reconstruct the data
            reconstructed = model(batch_x)
            loss = criterion(reconstructed, batch_x)

            # Backward pass: Optimize the weights
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            
            epoch_loss += loss.item()
            
        # Print progress every 10 epochs
        if (epoch+1) % 10 == 0:
            print(f"Epoch [{epoch+1}/{epochs}], Reconstruction Loss: {epoch_loss/len(data_tensor):.6f}")

    # 4. Save the trained brain
    os.makedirs('engine/models', exist_ok=True)
    torch.save(model.state_dict(), 'engine/models/autoencoder.pt')
    print("\n[SUCCESS] Model trained and saved successfully as 'engine/models/autoencoder.pt'")
    
    return model

if __name__ == "__main__":
    train_model()