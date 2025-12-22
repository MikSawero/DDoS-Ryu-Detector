import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.preprocessing import MinMaxScaler
import joblib

from autoencoder import DDoSAutoencoder

def train():
    print("Starting learning process...")
    
    try:
        df = pd.read_csv('data.csv', header=0, names=[
            'timestamp', 'datapath_id', 'ip_src', 'ip_dst', 'in_port', 'protocol', 
            'total_packets', 'total_bytes', 'duration_sec', 'flow_bytes_per_sec',
            'flow_packets_per_sec', 'avg_packet_size', 'flows_count_of_src_ip', 'label'
        ])
    except FileNotFoundError:
        print("Couldn't find data.csv file")
        return

    features = [
        'total_packets', 'total_bytes', 'duration_sec', 
        'flow_bytes_per_sec', 'flow_packets_per_sec', 
        'avg_packet_size', 'flows_count_of_src_ip'
    ]

    print('Rows: ')
    print(df['label'].value_counts())


    normal_traffic = df[df['label'] == 0][features].values

    scaler = MinMaxScaler()
    normal_scaled = scaler.fit_transform(normal_traffic)

    data_tensor = torch.FloatTensor(normal_scaled)

    input_dim = len(features)
    model = DDoSAutoencoder(input_dim)
    
    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)

    epochs = 2500
    for epoch in range(epochs):
        optimizer.zero_grad()
        outputs = model(data_tensor)
        loss = criterion(outputs, data_tensor)
        loss.backward()
        optimizer.step()
        
        if epoch % 100 == 0:
            print(f'Epoch {epoch}/{epochs}, Loss: {loss.item():.6f}')

    with torch.no_grad():
        reconstructions = model(data_tensor)
        mse_losses = torch.mean((data_tensor - reconstructions) ** 2, dim=1)
        
        loss_mean = mse_losses.mean().item()
        loss_std = mse_losses.std().item()
        
        threshold = loss_mean + (3 * loss_std)

    print(f"--- STATYSTYKI ---")
    print(f"Avg: {loss_mean:.6f}")
    print(f"Max: {mse_losses.max().item():.6f}")
    print(f"New threshold: {threshold:.6f}")

    torch.save(model.state_dict(), 'ddos_model.pth')
    joblib.dump(scaler, 'scaler.pkl')
    with open('threshold.txt', 'w') as f:
        f.write(str(threshold))

    print("Saved model")

if __name__ == "__main__":
    train()