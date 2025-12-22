import torch
import torch.nn as nn

class DDoSAutoencoder(nn.Module):
    def __init__(self, input_dim):
        super(DDoSAutoencoder, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 5),
            nn.Tanh(),
            nn.Linear(5, 3),
            nn.Tanh()
        )
        # 3 -> 5 -> 7
        self.decoder = nn.Sequential(
            nn.Linear(3, 5),
            nn.Tanh(),
            nn.Linear(5, input_dim),
            nn.Sigmoid()
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded