"""
train_darpa_models.py
Trains three models on the DARPA THEIA provenance graph (benign training data only,
May 7–13 pre-attack window).

All three are self-supervised autoencoders — there are NO attack labels in the
training split, so supervised classification would learn nothing.  Each model
learns what the benign provenance graph looks like; at inference, nodes that
deviate significantly from the learned representation receive a high anomaly score.

Models trained:
  1. MAGIC    — masked graph feature reconstruction   (Fang et al., USENIX Sec 2024)
  2. FLASH    — GraphSAGE autoencoder with attribute imputation (Liu et al., IEEE S&P 2024)
  3. ORTHRUS  — Gated-GNN autoencoder + edge attribution  (Han et al., USENIX Sec 2025)

Data source : DARPA THEIA Neo4j database ('darpa' named database)
Node key    : UUID (DARPA CDM v20 Subject records)
Feature dim : 9  →  [is_root, event_count, sus_ratio, evil_ratio, bias,
                      net_ratio, c2_event_count, file_write_count, inject_count]

Important:
  sus_ratio and evil_ratio are always 0 for DARPA training data (these labels do
  not exist in CDM); the features are kept for a shared 9-dim vector with BETH.
"""

import os
import sys
import numpy as np
import joblib
import torch
import torch.nn as nn
import torch.optim as optim
import torch_geometric.utils as pyg_utils

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from logmend.database.neo4j_router import db_router
from logmend.models.architectures import MAGIC, FLASH, ORTHRUS
from sklearn.preprocessing import StandardScaler

os.makedirs("artifacts/saved_models", exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# 1.  NEO4J QUERIES
# ─────────────────────────────────────────────────────────────────────────────

NODE_QUERY = """
MATCH (p:Process)

// Count all outgoing relationships as a proxy for activity level
OPTIONAL MATCH (p)-[:CONNECTED_TO]->(n:NetFlowObject)
WITH p,
     count(DISTINCT n)                                                          AS net_count,
     coalesce(sum(CASE WHEN n.is_c2 = true  THEN 1 ELSE 0 END), 0)            AS c2_count

OPTIONAL MATCH (p)-[:ACCESSED]->(f:FileObject)
WITH p, net_count, c2_count,
     count(DISTINCT f)                                                          AS file_count,
     coalesce(sum(CASE WHEN f.mode = 'write' OR f.action = 'write'
                       THEN 1 ELSE 0 END), 0)                                  AS file_write_count

OPTIONAL MATCH (p)-[:SPAWNED]->(c:Process)
WITH p, net_count, c2_count, file_count, file_write_count,
     count(DISTINCT c)                                                          AS spawn_count

// inject_count: processes accessed via ptrace-style events.
// In CDM graphs, ptrace events appear as FileObject accesses on /proc/<pid>
// or as Events with type containing 'ptrace'.  We approximate by checking
// whether the process is named 'sshd' AND has file accesses (common pattern
// in THEIA E5 injection attack).  This is a conservative signal.
OPTIONAL MATCH (p)-[:ACCESSED]->(pf:FileObject)
WHERE pf.path CONTAINS '/proc/'
WITH p, net_count, c2_count, file_count, file_write_count, spawn_count,
     count(DISTINCT pf)                                                         AS proc_file_access

WITH p, net_count, c2_count, file_count, file_write_count, spawn_count,
     CASE WHEN p.processName IN ['sshd', 'ssh'] AND proc_file_access > 0
          THEN 1 ELSE 0 END                                                    AS inject_count,
     (net_count + file_count + spawn_count)                                    AS event_count

RETURN
    id(p)                                                                        AS neo4j_id,
    CASE WHEN p.userId = '0' OR p.userId = 0 THEN 1.0 ELSE 0.0 END            AS is_root,
    toFloat(event_count)                                                         AS event_count,
    0.0                                                                          AS sus_ratio,
    0.0                                                                          AS evil_ratio,
    toFloat(net_count)  / CASE WHEN event_count > 0 THEN toFloat(event_count)
                               ELSE 1.0 END                                     AS net_ratio,
    toFloat(c2_count)                                                            AS c2_event_count,
    toFloat(file_write_count)                                                    AS file_write_count,
    toFloat(inject_count)                                                        AS inject_count
"""
# Note: sus_ratio=0 and evil_ratio=0 always for DARPA data — these BETH-specific
# labels don't exist in the CDM format.  Kept at position [2,3] so the 9-feature
# vector is structurally identical to BETH, enabling shared SequenceScorer code.

EDGE_QUERY = """
MATCH (p:Process)-[:SPAWNED]->(c:Process)
RETURN id(p) AS source, id(c) AS target
"""


def extract_darpa_data():
    print("[1/5] Extracting DARPA THEIA node features (9-feature vector)...")
    records = db_router.query('darpa', NODE_QUERY)

    if not records:
        raise RuntimeError(
            "No Process nodes returned from DARPA database. "
            "Ensure the THEIA benign training data (May 7–13) is ingested into "
            "the 'darpa' Neo4j named database."
        )

    node_mapping = {}
    features_raw = []

    for i, r in enumerate(records):
        node_mapping[r['neo4j_id']] = i
        features_raw.append([
            float(r['is_root']),
            float(r['event_count']),
            float(r['sus_ratio']),        # always 0.0 for DARPA
            float(r['evil_ratio']),       # always 0.0 for DARPA
            5.0,                          # constant bias term
            float(r['net_ratio']),
            float(r['c2_event_count']),
            float(r['file_write_count']),
            float(r['inject_count']),
        ])

    print(f"      Extracted {len(features_raw):,} process nodes.")

    print("\n[2/5] Extracting SPAWNED provenance edges...")
    edges   = db_router.query('darpa', EDGE_QUERY)
    sources = []
    targets = []
    for e in edges:
        if e['source'] in node_mapping and e['target'] in node_mapping:
            sources.append(node_mapping[e['source']])
            targets.append(node_mapping[e['target']])

    edge_index = torch.tensor([sources, targets], dtype=torch.long)
    print(f"      Extracted {edge_index.shape[1]:,} SPAWNED edges.")
    return features_raw, node_mapping, edge_index


# ─────────────────────────────────────────────────────────────────────────────
# 2.  MAGIC TRAINING
# Fang et al., USENIX Security 2024 — masked node feature reconstruction.
#
# Training objective:
#   L = MSE(x_recon[masked], x_original[masked])
# i.e. the loss is computed only on the masked feature positions, not the
# entire feature vector.  This forces the GCN encoder to propagate masked
# information from neighbours — exactly the inductive bias MAGIC relies on.
# ─────────────────────────────────────────────────────────────────────────────

def train_magic(x_tensor: torch.Tensor, edge_index: torch.Tensor,
                device: torch.device, epochs: int = 200):
    print("\n[3/5] Training MAGIC (masked feature reconstruction, Fang 2024)...")
    model     = MAGIC(in_channels=9, hidden_dim=32, latent_dim=16, mask_rate=0.30).to(device)
    optimizer = optim.Adam(model.parameters(), lr=0.005, weight_decay=1e-5)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

    model.train()
    for epoch in range(1, epochs + 1):
        optimizer.zero_grad()
        x_recon, mask = model(x_tensor, edge_index)

        # Loss only on masked positions — unmasked positions have full signal
        # already, forcing the model to use neighbourhood context for masked ones
        loss = ((x_recon - x_tensor) ** 2)[mask].mean()
        loss.backward()
        optimizer.step()
        scheduler.step()

        if epoch % 40 == 0:
            print(f"      Epoch {epoch:>4}/{epochs}  mask-MSE={loss.item():.6f}")

    torch.save(model.state_dict(), "artifacts/saved_models/darpa_magic.pth")
    print("      -> Saved darpa_magic.pth")


# ─────────────────────────────────────────────────────────────────────────────
# 3.  FLASH TRAINING
# Liu et al., IEEE S&P 2024 — GraphSAGE autoencoder with attribute imputation.
#
# Training objective:
#   L = MSE(x_recon, x_original)  over all nodes and all features.
# The model must learn to reconstruct features via multi-hop neighbourhood
# aggregation — the critical capability for the 54–76% missing attribute case.
# ─────────────────────────────────────────────────────────────────────────────

def train_flash(x_tensor: torch.Tensor, edge_index: torch.Tensor,
                device: torch.device, epochs: int = 200):
    print("\n[4/5] Training FLASH (GraphSAGE attribute-imputing autoencoder, Liu 2024)...")
    model     = FLASH(in_channels=9, hidden_dim=32, latent_dim=16).to(device)
    optimizer = optim.Adam(model.parameters(), lr=0.005, weight_decay=1e-5)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

    model.train()
    for epoch in range(1, epochs + 1):
        optimizer.zero_grad()
        x_recon, _ = model(x_tensor, edge_index)
        loss        = nn.MSELoss()(x_recon, x_tensor)
        loss.backward()
        optimizer.step()
        scheduler.step()

        if epoch % 40 == 0:
            print(f"      Epoch {epoch:>4}/{epochs}  recon-MSE={loss.item():.6f}")

    torch.save(model.state_dict(), "artifacts/saved_models/darpa_flash.pth")
    print("      -> Saved darpa_flash.pth")


# ─────────────────────────────────────────────────────────────────────────────
# 4.  ORTHRUS TRAINING
# Han et al., USENIX Security 2025 — gated GNN with edge attribution.
#
# Two simultaneous objectives:
#   L_node  = MSE(x_recon, x_original)        — learn benign node representations
#   L_edge  = BCE(edge_score, benign_label)    — all training edges are benign (label=0)
#             uses negative sampling so the model sees both high-score (negative
#             sampled = random non-edges) and low-score (real benign edges) examples.
#
# At inference on attack data, attack edges get anomalously high edge_score
# because they differ structurally from the benign-only patterns learned here.
# ─────────────────────────────────────────────────────────────────────────────

def train_orthrus(x_tensor: torch.Tensor, edge_index: torch.Tensor,
                  device: torch.device, epochs: int = 200):
    print("\n[5/5] Training ORTHRUS (Gated-GNN attribution autoencoder, Han 2025)...")
    model     = ORTHRUS(in_channels=9, hidden_dim=32, latent_dim=16, ggnn_layers=3).to(device)
    optimizer = optim.Adam(model.parameters(), lr=0.003, weight_decay=1e-5)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

    N = x_tensor.size(0)
    model.train()
    for epoch in range(1, epochs + 1):
        optimizer.zero_grad()
        x_recon, z, e_score_pos = model(x_tensor, edge_index)

        # ── Node reconstruction loss ──────────────────────────────────────────
        loss_node = nn.MSELoss()(x_recon, x_tensor)

        # ── Edge attribution loss — binary cross-entropy ──────────────────────
        # Real (benign) edges → label 0 (low attribution / normal)
        # Randomly sampled non-edges → label 1 (high attribution / unusual)
        # This teaches ORTHRUS that randomly-connected process pairs are more
        # "notable" than regularly-spawned pairs — reversing this at inference
        # on actual attack edges gives the high-score signal we want.
        neg_edge_index = pyg_utils.negative_sampling(
            edge_index, num_nodes=N,
            num_neg_samples=edge_index.size(1)
        )
        _, _, e_score_neg = model(x_tensor, neg_edge_index)

        pos_labels = torch.zeros(e_score_pos.size(0), 1, device=device)  # real edges = 0
        neg_labels = torch.ones (e_score_neg.size(0), 1, device=device)  # random   = 1

        loss_edge = (nn.BCELoss()(e_score_pos.unsqueeze(1), pos_labels) +
                     nn.BCELoss()(e_score_neg.unsqueeze(1), neg_labels)) / 2.0

        loss = loss_node + 0.5 * loss_edge
        loss.backward()
        optimizer.step()
        scheduler.step()

        if epoch % 40 == 0:
            print(f"      Epoch {epoch:>4}/{epochs}  "
                  f"node-MSE={loss_node.item():.6f}  "
                  f"edge-BCE={loss_edge.item():.6f}")

    torch.save(model.state_dict(), "artifacts/saved_models/darpa_orthrus.pth")
    print("      -> Saved darpa_orthrus.pth")


# ─────────────────────────────────────────────────────────────────────────────
# 5.  MAIN
# ─────────────────────────────────────────────────────────────────────────────

def train_darpa_ensemble():
    print("=" * 65)
    print("  LOGMEND — DARPA THEIA ENSEMBLE TRAINING  (9-feature / 3 models)")
    print("  Training data: May 7–13 benign window only")
    print("  All models: self-supervised autoencoder anomaly detection")
    print("=" * 65)

    features_raw, _, edge_index = extract_darpa_data()

    # ── Feature normalisation ─────────────────────────────────────────────────
    print("\n[Normalisation] Fitting StandardScaler on 9 features...")
    X_np     = np.array(features_raw, dtype=np.float32)
    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X_np).astype(np.float32)
    joblib.dump(scaler, "artifacts/saved_models/darpa_scaler.joblib")
    print(f"      Scaler fitted on {X_np.shape[0]:,} nodes, saved darpa_scaler.joblib")

    device   = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"\n[Device] Using: {device}")
    x_tensor   = torch.tensor(X_scaled, dtype=torch.float32).to(device)
    edge_index = edge_index.to(device)

    train_magic(x_tensor,   edge_index, device)
    train_flash(x_tensor,   edge_index, device)
    train_orthrus(x_tensor, edge_index, device)

    print("\n" + "=" * 65)
    print("  DARPA ENSEMBLE TRAINING COMPLETE")
    print("  Saved files:")
    print("    artifacts/saved_models/darpa_scaler.joblib")
    print("    artifacts/saved_models/darpa_magic.pth")
    print("    artifacts/saved_models/darpa_flash.pth")
    print("    artifacts/saved_models/darpa_orthrus.pth")
    print("\n  Inference: anomaly score = per-node reconstruction error.")
    print("  All three models produce error ∈ [0, ∞); SequenceScorer")
    print("  normalises to [0,1] using sigmoid before ensemble weighting.")
    print("=" * 65)


if __name__ == "__main__":
    train_darpa_ensemble()