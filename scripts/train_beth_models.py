"""
train_beth_models.py
Trains three models on the BETH provenance graph (benign training data only).
All three are anomaly detectors trained on the benign baseline; they produce
a deviation score at inference — not a supervised classifier.

Models trained:
  1. GraphCL  — self-supervised graph contrastive learning (You et al., NeurIPS 2020)
  2. Deep SAD — semi-supervised hypersphere anomaly detection (Ruff et al., ICLR 2020)
  3. Isolation Forest — unsupervised tabular anomaly isolation (Liu et al., ICDM 2008)

Data source : BETH Neo4j database (training split only)
Node key    : composite (hostName, processId, birthTimestamp)
Feature dim : 9  →  [is_root, event_count, sus_ratio, evil_ratio, bias,
                      net_ratio, c2_event_count, file_write_count, inject_count]
"""

import os
import sys
import numpy as np
import joblib
import torch
import torch.nn.functional as F
import torch.optim as optim
from torch_geometric.data import Data
from torch_geometric.utils import dropout_adj
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ── Add project root to path so imports resolve correctly ─────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from logmend.database.neo4j_router import db_router
from logmend.models.architectures import GraphCL, DeepSAD

os.makedirs("artifacts/saved_models", exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# 1.  EXTRACT FEATURES FROM BETH NEO4J
# ─────────────────────────────────────────────────────────────────────────────

NODE_QUERY = """
MATCH (p:Process)

OPTIONAL MATCH (p)-[:EMITS]->(e)
WITH p,
     count(DISTINCT e)                                                         AS event_count,
     coalesce(sum(CASE WHEN e.sus  = 1 THEN 1 ELSE 0 END), 0)                AS sus_score,
     coalesce(sum(CASE WHEN e.evil = 1 THEN 1 ELSE 0 END), 0)                AS evil_score

OPTIONAL MATCH (p)-[:CONNECTED_TO]->(n:NetFlowObject)
WITH p, event_count, sus_score, evil_score,
     count(DISTINCT n)                                                         AS net_count,
     coalesce(sum(CASE WHEN n.is_c2 = true THEN 1 ELSE 0 END), 0)            AS c2_count

OPTIONAL MATCH (p)-[:ACCESSED]->(f:FileObject)
WITH p, event_count, sus_score, evil_score, net_count, c2_count,
     coalesce(sum(CASE WHEN f.action = 'write' THEN 1 ELSE 0 END), 0)        AS file_write_count

RETURN
    id(p)                                                                       AS neo4j_id,
    CASE WHEN p.userId = '0'  THEN 1.0 ELSE 0.0 END                           AS is_root,
    toFloat(event_count)                                                        AS event_count,
    toFloat(sus_score)  / CASE WHEN event_count > 0 THEN toFloat(event_count) ELSE 1.0 END
                                                                                AS sus_ratio,
    toFloat(evil_score) / CASE WHEN event_count > 0 THEN toFloat(event_count) ELSE 1.0 END
                                                                                AS evil_ratio,
    toFloat(net_count)  / CASE WHEN event_count > 0 THEN toFloat(event_count) ELSE 1.0 END
                                                                                AS net_ratio,
    toFloat(c2_count)                                                           AS c2_event_count,
    toFloat(file_write_count)                                                   AS file_write_count,
    0.0                                                                         AS inject_count,
    CASE WHEN sus_score > 0 THEN -1.0 ELSE 1.0 END                            AS sad_label
"""
# Note: inject_count=0.0 for BETH — kernel-level ptrace injection attacks appear
# in DARPA THEIA, not in the BETH honeypot dataset.  The feature is kept in the
# 9-element vector so BETH and DARPA models share the same input dimension.

EDGE_QUERY = """
MATCH (child:Process)-[:CHILD_OF]->(parent:Process)
RETURN id(child) AS source, id(parent) AS target
"""


def extract_beth_data():
    print("[1/6] Extracting BETH node features (9-feature vector)...")
    records = db_router.query('beth', NODE_QUERY)

    if not records:
        raise RuntimeError(
            "No Process nodes returned from BETH database. "
            "Ensure the BETH training data is loaded into the 'beth' Neo4j database."
        )

    node_mapping = {}   # neo4j internal id → contiguous integer index
    features_raw = []
    sad_labels   = []   # +1 = normal / unlabeled, -1 = known anomaly (sus=1)

    for i, r in enumerate(records):
        node_mapping[r['neo4j_id']] = i
        features_raw.append([
            float(r['is_root']),
            float(r['event_count']),
            float(r['sus_ratio']),
            float(r['evil_ratio']),
            5.0,                         # constant bias term
            float(r['net_ratio']),
            float(r['c2_event_count']),
            float(r['file_write_count']),
            float(r['inject_count']),
        ])
        sad_labels.append(float(r['sad_label']))

    print(f"      Extracted {len(features_raw):,} process nodes.")
    n_anom = sum(1 for l in sad_labels if l == -1.0)
    print(f"      Labelled anomalies (sus=1): {n_anom:,} "
          f"({100.*n_anom/len(sad_labels):.2f}%)")

    print("\n[2/6] Extracting SPAWNED edges...")
    edges   = db_router.query('beth', EDGE_QUERY)
    sources = []
    targets = []
    for e in edges:
        if e['source'] in node_mapping and e['target'] in node_mapping:
            sources.append(node_mapping[e['source']])
            targets.append(node_mapping[e['target']])

    edge_index = torch.tensor([sources, targets], dtype=torch.long)
    print(f"      Extracted {edge_index.shape[1]:,} SPAWNED relationships.")

    return features_raw, sad_labels, node_mapping, edge_index


# ─────────────────────────────────────────────────────────────────────────────
# 2.  GRAPHCL TRAINING
# Augmentation pair: (1) random edge drop 20%, (2) random feature masking 20%.
# Loss: InfoNCE (NT-Xent) — positive pair = same node under both augmentations.
# ─────────────────────────────────────────────────────────────────────────────

def nt_xent_loss(z1: torch.Tensor, z2: torch.Tensor, temperature: float = 0.5) -> torch.Tensor:
    """
    NT-Xent (InfoNCE) contrastive loss.
    z1, z2 : L2-normalised node embeddings from two augmented views  [N, D]
    Positive pair: (z1[i], z2[i]) — same node, different augmentation.
    Negatives    : all other nodes in the batch.
    """
    z1 = F.normalize(z1, dim=1)
    z2 = F.normalize(z2, dim=1)

    N   = z1.size(0)
    # Stack both views: [2N, D]
    z   = torch.cat([z1, z2], dim=0)
    # Cosine similarity matrix [2N, 2N]
    sim = torch.mm(z, z.t()) / temperature
    # Remove self-similarity on the diagonal
    mask = torch.eye(2 * N, device=z.device).bool()
    sim  = sim.masked_fill(mask, -1e9)

    # Positive pair indices: for i in [0,N) the positive is i+N; for i in [N,2N) → i-N
    labels = torch.cat([torch.arange(N, 2*N), torch.arange(N)]).to(z.device)
    loss   = F.cross_entropy(sim, labels)
    return loss


def feature_mask_augment(x: torch.Tensor, mask_rate: float = 0.20) -> torch.Tensor:
    """Zero out a random subset of features for each node independently."""
    mask        = torch.rand_like(x) < mask_rate
    x_augmented = x.clone()
    x_augmented[mask] = 0.0
    return x_augmented


def train_graphcl(x_tensor: torch.Tensor, edge_index: torch.Tensor,
                  device: torch.device, epochs: int = 150):
    """
    Train GraphCL with two heterogeneous augmentations:
      View-1: edge dropout (p=0.20)
      View-2: feature masking (p=0.20)
    """
    print("\n[4/6] Training GraphCL (InfoNCE + edge-drop × feature-mask)...")
    model     = GraphCL(in_channels=9, hidden_dim=32, proj_dim=16).to(device)
    optimizer = optim.Adam(model.parameters(), lr=0.005, weight_decay=1e-5)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

    model.train()
    for epoch in range(1, epochs + 1):
        optimizer.zero_grad()

        # Augmentation 1: structural — drop 20% of edges
        ei_drop, _ = dropout_adj(edge_index, p=0.20, force_undirected=False)
        z1 = model(x_tensor, ei_drop)

        # Augmentation 2: attribute — mask 20% of feature values per node
        x_masked = feature_mask_augment(x_tensor, mask_rate=0.20)
        z2 = model(x_masked, edge_index)

        loss = nt_xent_loss(z1, z2, temperature=0.5)
        loss.backward()
        optimizer.step()
        scheduler.step()

        if epoch % 25 == 0:
            print(f"      Epoch {epoch:>4}/{epochs}  loss={loss.item():.4f}")

    # ── Compute and save mean benign embedding for inference scoring ──────────
    # At inference, anomaly score = cosine distance from this mean vector
    model.eval()
    with torch.no_grad():
        all_embeds       = model.encode(x_tensor, edge_index)
        mean_embed       = all_embeds.mean(dim=0)
    torch.save(model.state_dict(),           "artifacts/saved_models/beth_graphcl.pth")
    torch.save(mean_embed.cpu(),             "artifacts/saved_models/beth_graphcl_mean.pt")
    print("      -> Saved beth_graphcl.pth  +  beth_graphcl_mean.pt")


# ─────────────────────────────────────────────────────────────────────────────
# 3.  DEEP SAD TRAINING
# Ruff et al. (ICLR 2020) — §3.1 Objective:
#   L = (1/n) * Σ_i  dist(φ(xᵢ), c)^(yᵢ)
# where yᵢ=+1 → dist^1 (pull to centre)
#       yᵢ=-1 → dist^(-1) = η/dist (push from centre)
# Centre c is estimated on normal data before training begins.
# ─────────────────────────────────────────────────────────────────────────────

def deep_sad_loss(z: torch.Tensor, c: torch.Tensor,
                  labels: torch.Tensor, eta: float = 1.0,
                  eps: float = 1e-6) -> torch.Tensor:
    """
    Deep SAD hypersphere loss (Ruff 2020, Eq. 4).
    labels : +1 for normal/unlabeled, -1 for known anomalies (sus=1).
    Normal  → minimise dist to c.
    Anomaly → minimise η / (dist + ε)  (equivalently maximise dist).
    """
    dist = torch.sum((z - c) ** 2, dim=1)
    # Separate normal and anomalous contributions
    normal_mask  = (labels == 1.0)
    anomaly_mask = (labels == -1.0)

    loss  = torch.zeros(z.size(0), device=z.device)
    if normal_mask.any():
        loss[normal_mask]  = dist[normal_mask]
    if anomaly_mask.any():
        loss[anomaly_mask] = eta / (dist[anomaly_mask] + eps)

    return loss.mean()


def train_deepsad(x_tensor: torch.Tensor, sad_labels: list,
                  device: torch.device, epochs: int = 100):
    print("\n[5/6] Training Deep SAD (hypersphere, Ruff ICLR 2020)...")
    model     = DeepSAD(in_channels=9, hidden_dim=32, latent_dim=16).to(device)
    optimizer = optim.Adam(model.parameters(), lr=0.001, weight_decay=1e-5)

    label_tensor = torch.tensor(sad_labels, dtype=torch.float32).to(device)
    n_normal  = int((label_tensor ==  1.0).sum().item())
    n_anomaly = int((label_tensor == -1.0).sum().item())
    print(f"      Normal samples: {n_normal:,}  |  Anomaly samples: {n_anomaly:,}")

    # ── Initialise centre c on the normal subset ──────────────────────────────
    # Use all samples that are NOT labelled anomalies to form the initial centre.
    # A small epsilon prevents a collapsed centre.
    model.eval()
    with torch.no_grad():
        normal_mask    = (label_tensor == 1.0)
        normal_outputs = model(x_tensor[normal_mask])
        c              = torch.mean(normal_outputs, dim=0)
        # Avoid centre collapse: components very close to 0 are set to ±ε
        c[(abs(c) < 0.01)] = torch.sign(c[(abs(c) < 0.01)]) * 0.01
    model.c.copy_(c)
    print(f"      Centre c initialised from {n_normal:,} normal nodes.")

    model.train()
    for epoch in range(1, epochs + 1):
        optimizer.zero_grad()
        z    = model(x_tensor)
        loss = deep_sad_loss(z, model.c, label_tensor, eta=1.0)
        loss.backward()
        optimizer.step()

        if epoch % 20 == 0:
            print(f"      Epoch {epoch:>4}/{epochs}  loss={loss.item():.6f}")

    torch.save({'state_dict': model.state_dict(), 'c': model.c.cpu()},
               "artifacts/saved_models/beth_deepsad.pth")
    print("      -> Saved beth_deepsad.pth  (state_dict + centre c)")


# ─────────────────────────────────────────────────────────────────────────────
# 4.  ISOLATION FOREST TRAINING  (sklearn, tabular)
# ─────────────────────────────────────────────────────────────────────────────

def train_iforest(x_np: np.ndarray):
    """
    Isolation Forest — no labels required.
    contamination: estimated fraction of anomalies in the training set.
    For BETH training (benign-only after the 60/20/20 split), we set a small
    contamination value reflecting the ~0.17% sus=1 rate in the training CSV.
    """
    print("\n[3/6] Training Isolation Forest (sklearn)...")
    iforest = IsolationForest(
        n_estimators=200,
        contamination=0.0017,   # 1269 / 763144 ≈ 0.17 %
        max_features=9,
        random_state=42,
        n_jobs=-1
    )
    iforest.fit(x_np)
    joblib.dump(iforest, "artifacts/saved_models/beth_iforest.joblib")
    print("      -> Saved beth_iforest.joblib")


# ─────────────────────────────────────────────────────────────────────────────
# 5.  MAIN
# ─────────────────────────────────────────────────────────────────────────────

def train_beth_ensemble():
    print("=" * 65)
    print("  LOGMEND — BETH ENSEMBLE TRAINING  (9-feature / 3 models)")
    print("=" * 65)

    features_raw, sad_labels, _, edge_index = extract_beth_data()

    # ── Feature normalisation ─────────────────────────────────────────────────
    # Fit StandardScaler on ALL 9 features.
    # This is critical: raw event_count can be O(10^5); the GNN will diverge
    # without normalisation.  Save the scaler for use in sequence_scorer.py.
    print("\n[Normalisation] Fitting StandardScaler on 9 features...")
    X_np     = np.array(features_raw, dtype=np.float32)
    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X_np).astype(np.float32)
    joblib.dump(scaler, "artifacts/saved_models/beth_scaler.joblib")
    print(f"      Scaler fitted on {X_np.shape[0]:,} nodes, saved beth_scaler.joblib")

    # ── Move tensors to device ────────────────────────────────────────────────
    device   = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"\n[Device] Using: {device}")
    x_tensor = torch.tensor(X_scaled, dtype=torch.float32).to(device)
    edge_index = edge_index.to(device)

    # ── Train each model ──────────────────────────────────────────────────────
    train_iforest(X_scaled)
    train_graphcl(x_tensor, edge_index, device)
    train_deepsad(x_tensor, sad_labels, device)

    print("\n" + "=" * 65)
    print("  BETH ENSEMBLE TRAINING COMPLETE")
    print("  Saved files:")
    print("    artifacts/saved_models/beth_scaler.joblib")
    print("    artifacts/saved_models/beth_iforest.joblib")
    print("    artifacts/saved_models/beth_graphcl.pth")
    print("    artifacts/saved_models/beth_graphcl_mean.pt")
    print("    artifacts/saved_models/beth_deepsad.pth  (includes centre c)")
    print("=" * 65)


if __name__ == "__main__":
    train_beth_ensemble()