"""
models/architectures.py
All six model class definitions shared between training scripts and SequenceScorer.
Import these classes in sequence_scorer.py to load saved weights at inference time.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, SAGEConv, GatedGraphConv

# ──────────────────────────────────────────────────────────────────────────────
# BETH MODEL 1 — GraphCL
# Paper: You et al., "Graph Contrastive Learning with Augmentations",
#        NeurIPS 2020. Node-level contrastive learning on provenance graph.
#
# Self-supervised: trains on the benign provenance graph with two augmented
# views per node. Anomaly score at inference = cosine distance from the mean
# benign embedding learned during training.
# ──────────────────────────────────────────────────────────────────────────────
class GraphCL(nn.Module):
    """
    GCN encoder + MLP projection head for node-level contrastive learning.
    in_channels : node feature dimension (9 for LogMend)
    hidden_dim  : GCN hidden and output dimension
    proj_dim    : dimension of the contrastive projection head output
    """
    def __init__(self, in_channels: int = 9, hidden_dim: int = 32, proj_dim: int = 16):
        super().__init__()
        # GCN encoder — two layers with BatchNorm for stable self-supervised training
        self.conv1 = GCNConv(in_channels, hidden_dim)
        self.bn1   = nn.BatchNorm1d(hidden_dim)
        self.conv2 = GCNConv(hidden_dim, hidden_dim)
        self.bn2   = nn.BatchNorm1d(hidden_dim)
        # MLP projection head — maps embeddings to contrastive space
        # Discarded at inference; only the encoder output is used for scoring
        self.projector = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, proj_dim)
        )

    def encode(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """Return node embeddings (used for anomaly scoring at inference)."""
        h = F.relu(self.bn1(self.conv1(x, edge_index)))
        h = F.relu(self.bn2(self.conv2(h, edge_index)))
        return h

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """Return projected embeddings (used during training only)."""
        return self.projector(self.encode(x, edge_index))


# ──────────────────────────────────────────────────────────────────────────────
# BETH MODEL 2 — Deep SAD (Semi-supervised Anomaly Detection)
# Paper: Ruff et al., "Deep Semi-Supervised Anomaly Detection",
#        ICLR 2020. Hypersphere objective with label-guided centre repulsion.
#
# BETH usage: sus=1 nodes are the labelled anomaly class (y=-1).
# All other nodes treated as normal (y=+1).
# ──────────────────────────────────────────────────────────────────────────────
class DeepSAD(nn.Module):
    """
    MLP encoder that maps nodes into a compact hyperspherical latent space.
    The centre c is estimated on benign data and fixed during training.
    Normal nodes are pulled toward c; sus=1 nodes are pushed away.
    """
    def __init__(self, in_channels: int = 9, hidden_dim: int = 32, latent_dim: int = 16):
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(in_channels, hidden_dim),
            nn.ReLU(),
            nn.BatchNorm1d(hidden_dim),
            nn.Linear(hidden_dim, latent_dim),
            nn.ReLU(),
        )
        # c is set after a forward pass on normal data; not a trained parameter
        self.register_buffer('c', torch.zeros(latent_dim))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.network(x)

    def anomaly_score(self, x: torch.Tensor) -> torch.Tensor:
        """Squared distance to centre — used as anomaly score at inference."""
        z = self.forward(x)
        return torch.sum((z - self.c) ** 2, dim=1)


# ──────────────────────────────────────────────────────────────────────────────
# BETH MODEL 3 — Isolation Forest  (sklearn, no class needed here)
# ──────────────────────────────────────────────────────────────────────────────


# ──────────────────────────────────────────────────────────────────────────────
# DARPA MODEL 1 — MAGIC
# Paper: Fang et al., "MAGIC: Detecting Advanced Persistent Threats via Masked
#        Graph Representation Learning", USENIX Security 2024.
#
# Self-supervised masked-feature autoencoder on the provenance graph.
# A fraction of node features is zeroed (masked) before encoding; the decoder
# reconstructs the original features. Anomaly score = masked feature MSE error.
# ──────────────────────────────────────────────────────────────────────────────
class MAGIC(nn.Module):
    """
    Masked Graph Autoencoder.
    Encoder  : two-layer GCN with BatchNorm.
    Decoder  : two-layer MLP that reconstructs ALL in_channels from latent space.
    Training : mask `mask_rate` fraction of features → encode → decode → MSE loss
               on masked positions only (preserves signal from unmasked features).
    Inference: anomaly_score = mean squared reconstruction error per node.
    """
    def __init__(self, in_channels: int = 9, hidden_dim: int = 32,
                 latent_dim: int = 16, mask_rate: float = 0.30):
        super().__init__()
        self.in_channels = in_channels
        self.mask_rate   = mask_rate

        # GCN encoder
        self.enc_conv1 = GCNConv(in_channels, hidden_dim)
        self.enc_bn1   = nn.BatchNorm1d(hidden_dim)
        self.enc_conv2 = GCNConv(hidden_dim, latent_dim)
        self.enc_bn2   = nn.BatchNorm1d(latent_dim)

        # MLP feature decoder — reconstructs original node features
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, in_channels)
        )

    def _mask(self, x: torch.Tensor):
        """Zero out mask_rate fraction of features; return masked x and boolean mask."""
        n, d = x.size()
        # Per-node, independently sample which feature dimensions to mask
        mask = torch.rand(n, d, device=x.device) < self.mask_rate   # True = masked
        x_masked = x.clone()
        x_masked[mask] = 0.0
        return x_masked, mask

    def encode(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        h = F.relu(self.enc_bn1(self.enc_conv1(x, edge_index)))
        h = F.relu(self.enc_bn2(self.enc_conv2(h, edge_index)))
        return h

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor):
        """
        Returns (x_reconstructed, mask) during training.
        Loss should be MSE only on mask==True positions.
        """
        x_masked, mask = self._mask(x)
        z              = self.encode(x_masked, edge_index)
        x_recon        = self.decoder(z)
        return x_recon, mask

    def anomaly_score(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """
        At inference (no masking): full reconstruction error per node.
        Higher error = more anomalous.
        """
        with torch.no_grad():
            z      = self.encode(x, edge_index)
            x_recon = self.decoder(z)
            return torch.mean((x - x_recon) ** 2, dim=1)


# ──────────────────────────────────────────────────────────────────────────────
# DARPA MODEL 2 — FLASH
# Paper: Liu et al., "FLASH: A Comprehensive Approach to Intrusion Detection
#        via Provenance Graph Representation Learning", IEEE S&P 2024.
#
# Key innovation: multi-hop GraphSAGE aggregation compensates for missing node
# attributes by propagating available neighbour attributes.  This is what makes
# it robust to THEIA/TRACE's 54–76% missing attribute rate.
#
# Trained as a graph autoencoder on benign data.
# Anomaly score = node feature reconstruction error.
# ──────────────────────────────────────────────────────────────────────────────
class FLASH(nn.Module):
    """
    GraphSAGE autoencoder with attribute-fallback encoding.
    Encoder : two SAGEConv layers (mean aggregation) pull missing attributes
              from multi-hop neighbourhood.
    Decoder : MLP that projects latent back to original feature space.
    """
    def __init__(self, in_channels: int = 9, hidden_dim: int = 32, latent_dim: int = 16):
        super().__init__()
        # Encoder
        self.enc_sage1 = SAGEConv(in_channels, hidden_dim)
        self.enc_bn1   = nn.BatchNorm1d(hidden_dim)
        self.enc_sage2 = SAGEConv(hidden_dim, latent_dim)
        self.enc_bn2   = nn.BatchNorm1d(latent_dim)

        # Attribute imputation head — projects individual missing features
        # from neighbour mean before encoding (FLASH-specific)
        self.attr_proj = nn.Linear(in_channels, in_channels)

        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, in_channels)
        )

    def _impute(self, x: torch.Tensor) -> torch.Tensor:
        """
        Soft imputation for zero-valued features (proxy for 'missing').
        Zero features are replaced with a learned projection of the
        full feature vector; non-zero features are kept as-is.
        This mimics FLASH's attribute reconstruction step.
        """
        imputed   = torch.relu(self.attr_proj(x))
        is_zero   = (x == 0.0).float()
        return x + is_zero * imputed * 0.1   # small blend avoids overwriting real zeros

    def encode(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        x_imp = self._impute(x)
        h     = F.relu(self.enc_bn1(self.enc_sage1(x_imp, edge_index)))
        h     = F.relu(self.enc_bn2(self.enc_sage2(h,    edge_index)))
        return h

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor):
        z      = self.encode(x, edge_index)
        x_recon = self.decoder(z)
        return x_recon, z

    def anomaly_score(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        with torch.no_grad():
            x_recon, _ = self.forward(x, edge_index)
            return torch.mean((x - x_recon) ** 2, dim=1)


# ──────────────────────────────────────────────────────────────────────────────
# DARPA MODEL 3 — ORTHRUS
# Paper: Han et al., "ORTHRUS: High-Quality Provenance-Based Intrusion Detection
#        via Graph Attribution", USENIX Security 2025.
#
# Key innovation: gated graph convolution + bilinear edge scorer learns to
# attribute which specific edges (causal dependencies) in the provenance graph
# belong to the attack chain vs benign coincidental causality (dependency
# explosion problem).
#
# Training: learns benign node reconstruction AND benign edge importance scores.
# At inference: both node reconstruction error AND edge attribution score are
# available; anomaly score = node error; attack path = top-scored edges.
# ──────────────────────────────────────────────────────────────────────────────
class ORTHRUS(nn.Module):
    """
    Gated Graph Neural Network autoencoder with edge attribution head.
    Node encoder : linear projection + GatedGraphConv (GRU message passing).
    Edge scorer  : bilinear layer over (src_embedding, dst_embedding) → edge_score.
    Node decoder : MLP that reconstructs original features.
    """
    def __init__(self, in_channels: int = 9, hidden_dim: int = 32,
                 latent_dim: int = 16, ggnn_layers: int = 3):
        super().__init__()
        self.node_proj = nn.Linear(in_channels, hidden_dim)
        self.ggnn      = GatedGraphConv(hidden_dim, num_layers=ggnn_layers)
        self.compress  = nn.Linear(hidden_dim, latent_dim)

        # Edge attribution: bilinear over source and destination embeddings
        # Positive score = this edge is important / suspicious
        self.edge_scorer = nn.Bilinear(latent_dim, latent_dim, 1)

        # Node decoder
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, in_channels)
        )

    def encode(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        h = F.relu(self.node_proj(x))
        h = self.ggnn(h, edge_index)
        return F.relu(self.compress(h))

    def score_edges(self, z: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """Return per-edge attribution score. High = causal attack edge."""
        src = z[edge_index[0]]
        dst = z[edge_index[1]]
        return torch.sigmoid(self.edge_scorer(src, dst)).squeeze(1)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor):
        z       = self.encode(x, edge_index)
        x_recon = self.decoder(z)
        e_score = self.score_edges(z, edge_index)
        return x_recon, z, e_score

    def anomaly_score(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        with torch.no_grad():
            z, e_score = self.encode(x, edge_index), None
            x_recon = self.decoder(z)
            node_err = torch.mean((x - x_recon) ** 2, dim=1)
        return node_err