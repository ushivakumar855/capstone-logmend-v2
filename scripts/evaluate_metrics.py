"""
evaluate_metrics.py
Academic Benchmarking for LogMEND 2.0.
Calculates Precision, Recall, F1-Score, AUC-ROC, and AUC-PR for both datasets.
"""

import os
import torch
import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score, average_precision_score
from logmend.database.neo4j_router import db_router

# Import the newly refactored classes and functions
from logmend.tools.sequence_scorer import (
    _Models, score_iforest, score_graphcl, score_deepsad, 
    _autoencoder_score, BETH_W, DARPA_W
)

def evaluate_beth(models):
    print("\n" + "="*50)
    print(" 📊 EVALUATING BETH ENSEMBLE")
    print("="*50)
    print("[1/2] Extracting BETH Graph and Ground Truth Labels...")
    
    query = """
    MATCH (p:Process)
    OPTIONAL MATCH (p)-[:EMITS]->(e)
    WITH p, 
         count(DISTINCT e) AS event_count,
         coalesce(sum(CASE WHEN e.sus = 1 THEN 1 ELSE 0 END), 0) AS sus_score,
         coalesce(sum(CASE WHEN e.evil = 1 THEN 1 ELSE 0 END), 0) AS evil_score
    OPTIONAL MATCH (p)-[:CONNECTED_TO]->(n:NetFlowObject)
    WITH p, event_count, sus_score, evil_score, count(DISTINCT n) AS net_count, coalesce(sum(CASE WHEN n.is_c2 = true THEN 1 ELSE 0 END), 0) AS c2_count
    OPTIONAL MATCH (p)-[:ACCESSED]->(f:FileObject)
    WITH p, event_count, sus_score, evil_score, net_count, c2_count, coalesce(sum(CASE WHEN f.action = 'write' THEN 1 ELSE 0 END), 0) AS file_write_count
    
    RETURN 
        CASE WHEN p.userId = '0' THEN 1.0 ELSE 0.0 END AS is_root,
        toFloat(event_count) AS event_count,
        toFloat(sus_score) AS sus_score,
        toFloat(evil_score) AS evil_score,
        toFloat(net_count) AS net_count,
        toFloat(c2_count) AS c2_event_count,
        toFloat(file_write_count) AS file_write_count,
        0.0 AS inject_count,
        CASE WHEN sus_score > 0 THEN 1 ELSE 0 END AS is_attack
    """
    
    nodes = db_router.query('beth', query)
    if not nodes:
        print("[!] BETH database is not active. Skipping BETH evaluation.")
        return

    features = []
    y_true = []
    for r in nodes:
        ec = r['event_count']
        sus_ratio = r['sus_score'] / ec if ec > 0 else 0.0
        evil_ratio = r['evil_score'] / ec if ec > 0 else 0.0
        net_ratio = r['net_count'] / ec if ec > 0 else 0.0
        
        feats = [
            r['is_root'], ec, sus_ratio, evil_ratio, 5.0, 
            net_ratio, r['c2_event_count'], r['file_write_count'], 0.0
        ]
        features.append(feats)
        y_true.append(r['is_attack'])

    print("[2/2] Running AI Inference and Computing Metrics...")
    
    y_pred_scores = []
    for feat in features:
        x_scaled = models.beth_scaler.transform(np.array(feat, dtype=np.float32).reshape(1, -1)).flatten()
        
        s_gcl = score_graphcl(x_scaled, models.beth_graphcl, models.beth_graphcl_mean, models.device)
        s_if  = score_iforest(x_scaled, models.beth_iforest)
        s_sad = score_deepsad(x_scaled, models.beth_deepsad, models.device)
        
        score = (BETH_W["graphcl"] * s_gcl + BETH_W["iforest"] * s_if + BETH_W["deepsad"] * s_sad)
        y_pred_scores.append(score)
        
    calculate_and_print_metrics(y_true, y_pred_scores)


def evaluate_darpa(models):
    print("\n" + "="*50)
    print(" 📊 EVALUATING DARPA THEIA ENSEMBLE")
    print("="*50)
    print("[1/2] Extracting DARPA Graph and Ground Truth Labels...")
    
    query = """
    MATCH (p:Process)
    OPTIONAL MATCH (p)-[:CONNECTED_TO]->(n:NetFlowObject)
    WITH p, count(DISTINCT n) AS net_count, coalesce(sum(CASE WHEN n.is_c2 = true THEN 1 ELSE 0 END), 0) AS c2_count
    OPTIONAL MATCH (p)-[:ACCESSED]->(f:FileObject)
    WITH p, net_count, c2_count, count(DISTINCT f) AS file_count, coalesce(sum(CASE WHEN f.mode = 'write' OR f.action = 'write' THEN 1 ELSE 0 END), 0) AS file_write_count
    OPTIONAL MATCH (p)-[:SPAWNED]->(c:Process)
    WITH p, net_count, c2_count, file_count, file_write_count, count(DISTINCT c) AS spawn_count
    OPTIONAL MATCH (p)-[:ACCESSED]->(pf:FileObject) WHERE pf.path CONTAINS '/proc/'
    WITH p, net_count, c2_count, file_count, file_write_count, spawn_count, count(DISTINCT pf) AS proc_file_access
    
    WITH p, net_count, c2_count, file_count, file_write_count, spawn_count,
         CASE WHEN p.processName IN ['sshd', 'ssh'] AND proc_file_access > 0 THEN 1 ELSE 0 END AS inject_count,
         (net_count + file_count + spawn_count) AS event_count
         
    RETURN 
        CASE WHEN p.userId IN ['0', 0] THEN 1.0 ELSE 0.0 END AS is_root,
        toFloat(event_count) AS event_count,
        toFloat(net_count) AS net_count,
        toFloat(c2_count) AS c2_event_count,
        toFloat(file_write_count) AS file_write_count,
        toFloat(inject_count) AS inject_count,
        CASE WHEN p.is_evil = 1 OR p.evil = 1 OR p.is_c2 = 1 THEN 1 ELSE 0 END AS is_attack
    """
    
    nodes = db_router.query('darpa', query)
    if not nodes:
        print("[!] THEIA database is not active. Skipping DARPA evaluation.")
        return

    features = []
    y_true = []
    for r in nodes:
        ec = r['event_count']
        net_ratio = r['net_count'] / ec if ec > 0 else 0.0
        
        feats = [
            r['is_root'], ec, 0.0, 0.0, 5.0, 
            net_ratio, r['c2_event_count'], r['file_write_count'], r['inject_count']
        ]
        features.append(feats)
        y_true.append(r['is_attack'])

    print("[2/2] Running AI Inference and Computing Metrics...")
    
    y_pred_scores = []
    for feat in features:
        x_scaled = models.darpa_scaler.transform(np.array(feat, dtype=np.float32).reshape(1, -1)).flatten()
        
        s_magic   = _autoencoder_score(x_scaled, models.darpa_magic, models.device)
        s_flash   = _autoencoder_score(x_scaled, models.darpa_flash, models.device)
        s_orthrus = _autoencoder_score(x_scaled, models.darpa_orthrus, models.device)
        
        score = (DARPA_W["magic"] * s_magic + DARPA_W["flash"] * s_flash + DARPA_W["orthrus"] * s_orthrus)
        y_pred_scores.append(score)
        
    calculate_and_print_metrics(y_true, y_pred_scores)


def calculate_and_print_metrics(y_true, y_pred_scores):
    y_true = np.array(y_true)
    y_pred_scores = np.array(y_pred_scores)
    
    threshold = 0.60
    y_pred_binary = (y_pred_scores > threshold).astype(int)
    
    precision = precision_score(y_true, y_pred_binary, zero_division=0)
    recall = recall_score(y_true, y_pred_binary, zero_division=0)
    f1 = f1_score(y_true, y_pred_binary, zero_division=0)
    
    try:
        roc_auc = roc_auc_score(y_true, y_pred_scores)
        pr_auc = average_precision_score(y_true, y_pred_scores)
    except ValueError:
        roc_auc = 0.0
        pr_auc = 0.0
        print("\n[Warning] Not enough attack labels in this snapshot to calculate AUC.")

    print("\n--------------------------------------------------")
    print(f"Total Nodes Analyzed : {len(y_true):,}")
    print(f"Total Attacks Found  : {sum(y_true)}")
    print("--------------------------------------------------")
    print(f"Precision (Accuracy of Alarms) : {precision * 100:.2f}%")
    print(f"Recall (Stealth Attacks Caught): {recall * 100:.2f}%")
    print(f"F1-Score (Overall Balance)     : {f1 * 100:.2f}%")
    print("--------------------------------------------------")
    print(f"AUC-ROC (Ranking Quality)      : {roc_auc:.4f}")
    print(f"AUC-PR  (Imbalanced Quality)   : {pr_auc:.4f}")
    print("--------------------------------------------------\n")

if __name__ == "__main__":
    print("Initializing LogMEND 2.0 Evaluation Engine...")
    models = _Models()
    
    try:
        evaluate_beth(models)
    except Exception as e:
        print(f"BETH Eval Failed: {e}")
        
    try:
        evaluate_darpa(models)
    except Exception as e:
        print(f"DARPA Eval Failed: {e}")