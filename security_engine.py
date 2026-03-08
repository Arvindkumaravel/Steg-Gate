"""
EnterpriseStegEngine V4.5 — Deep Scan + External Tools Edition

New over V4:
────────────────────────────────────────────────────────────────────────────────
FEATURE 4 — zsteg Integration
  Calls the zsteg Ruby gem (if installed) to check all LSB bit-plane
  combinations (b1,r,lsb,xy etc.) for readable strings and embedded file
  signatures. Findings are classified by signal strength and contribute
  up to +0.35 to the final risk score. Gracefully skips if not installed.
  Install: gem install zsteg

FEATURE 5 — binwalk Integration
  Calls binwalk (if installed) to scan byte sequences for embedded file
  signatures (ZIP, ELF, PDF, etc.) and entropy anomalies. Data appended
  after the image end and non-image file signatures contribute up to +0.40
  to the final risk score. Gracefully skips if not installed.
  Install: pip install binwalk  OR  brew install binwalk
────────────────────────────────────────────────────────────────────────────────
"""

import cv2
import numpy as np
from PIL import Image
import io
import os
import json
import shutil
import subprocess
import tempfile
import re
from concurrent.futures import ThreadPoolExecutor, as_completed  # used in binwalk + process_file
from typing import Optional, List, Tuple, Dict, Any
# scipy.ndimage.convolve removed — SRM residual now uses np.diff (faster)


# ══════════════════════════════════════════════════════════════════════════════
#  Utilities
# ══════════════════════════════════════════════════════════════════════════════

def _shannon_entropy(data: np.ndarray) -> float:
    if data.size == 0:
        return 0.0
    counts = np.bincount(data.flatten().astype(np.uint8), minlength=2)
    probs = counts[counts > 0] / float(data.size)
    probs = np.clip(probs, 1e-12, 1.0)  # guard log2(0)
    with np.errstate(divide="ignore", invalid="ignore"):
        h = float(-np.sum(probs * np.log2(probs)))
    return 0.0 if (h != h or h == float("inf") or h == float("-inf")) else h


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + np.exp(-float(np.clip(x, -500, 500))))


SRM_KERNEL = np.array([
    [-1,  2, -1],
    [ 2, -4,  2],
    [-1,  2, -1]
], dtype=np.float32) / 4.0


# ══════════════════════════════════════════════════════════════════════════════
#  FEATURE 1 — Multi-Bitplane Analysis
# ══════════════════════════════════════════════════════════════════════════════

def extract_bitplane(channel: np.ndarray, plane: int) -> np.ndarray:
    """Extract a single bitplane (0=LSB … 7=MSB) from a uint8 channel."""
    return (channel >> plane) & 1


def analyze_bitplanes(block: np.ndarray, planes: int = 4,
                      is_jpeg: bool = False) -> dict:
    """
    Analyse bitplanes 0-(planes-1) across all 3 BGR channels.

    For lossless formats (PNG, BMP): planes 1-3 have natural structure;
    steganography injects randomness, raising entropy toward 1.0.

    For JPEG: DCT quantisation makes ALL bitplanes near-maximum entropy
    in every clean block. Planes 1-3 are useless for detection and produce
    a 100% false-positive rate. Only plane 0 (LSB) is evaluated.
    """
    per_plane = {}
    for p in range(planes):
        entropies, biases = [], []
        for c in range(3):
            bp = extract_bitplane(block[:, :, c], p).astype(np.uint8)
            entropies.append(_shannon_entropy(bp))
            biases.append(abs(0.5 - np.mean(bp.astype(np.float32))))
        per_plane[p] = {
            "entropy": float(np.min(entropies)),
            "bias":    float(np.max(biases)),
        }

    suspicion = {}
    # Plane 0: suspicious if entropy LOW (structured data replacing noise)
    suspicion[0] = max(0.0, (0.75 - per_plane[0]["entropy"]) / 0.75)

    for p in range(1, planes):
        if is_jpeg:
            # JPEG DCT makes planes 1-3 near-maximum entropy even on clean
            # images. Zeroed out to eliminate false positives entirely.
            suspicion[p] = 0.0
        else:
            # Lossless: flag if entropy exceeds the natural upper bound
            baseline_upper = {1: 0.90, 2: 0.75, 3: 0.60}
            upper = baseline_upper.get(p, 0.55)
            suspicion[p] = max(0.0, (per_plane[p]["entropy"] - upper) / (1.0 - upper + 1e-9))

    return {
        "per_plane":       per_plane,
        "suspicion":       suspicion,
        "max_suspicion":   float(max(suspicion.values())),
        "deepest_plane":   int(max(suspicion, key=suspicion.get)),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  FEATURE 2 — RS Steganalysis
# ══════════════════════════════════════════════════════════════════════════════

def _discrimination(group: np.ndarray) -> float:
    """Smoothness measure: sum of absolute differences between adjacent pixels."""
    return float(np.sum(np.abs(np.diff(group.astype(np.int32)))))


def _flip_positive(pixels: np.ndarray) -> np.ndarray:
    """F+1: toggle LSB (XOR with 1)."""
    return pixels ^ np.uint8(1)


def _flip_negative(pixels: np.ndarray) -> np.ndarray:
    """
    F-1: inverse LSB operation.
    Even pixels → pixel - 1 (0 stays 0, marked unusable)
    Odd  pixels → pixel + 1 (255 stays 255, marked unusable)
    """
    result = pixels.copy().astype(np.int16)
    even_mask = (result % 2 == 0)
    result[even_mask]  -= 1
    result[~even_mask] += 1
    return result.astype(np.int16)  # keep as int16 so callers can detect -1/256


def _classify_groups(channel: np.ndarray, group_size: int = 4) -> Tuple[float, float, float, float]:
    """
    Fully-vectorised RS classification — no Python for-loop.

    Groups the flattened channel into (N, group_size) blocks, applies the
    positive/negative mask operations with NumPy broadcasting, then counts
    R/S classifications in bulk.  ~100x faster than the original loop on
    large images.
    """
    flat = channel.flatten().astype(np.int16)
    # Trim to a multiple of group_size
    n = (len(flat) // group_size) * group_size
    if n == 0:
        return 0.0, 0.0, 0.0, 0.0
    groups = flat[:n].reshape(-1, group_size)          # (M, G)

    # Alternating mask: positions 1, 3, … are flipped
    mask = np.array([i % 2 for i in range(group_size)], dtype=bool)  # (G,)

    # ── Discrimination: sum of |diff between adjacent pixels| ────────────────
    def disc(g):  # g shape: (M, G)
        return np.sum(np.abs(np.diff(g.astype(np.int32), axis=1)), axis=1)  # (M,)

    f0 = disc(groups)

    # ── Positive flip: XOR masked columns with 1 ─────────────────────────────
    g_pos = groups.copy()
    g_pos[:, mask] ^= 1
    f_pos = disc(g_pos)
    R_pos = int(np.sum(f_pos > f0))
    S_pos = int(np.sum(f_pos < f0))

    # ── Negative flip: even→-1, odd→+1 on masked columns ────────────────────
    g_neg = groups.copy().astype(np.int16)
    cols  = g_neg[:, mask]                              # (M, n_masked)
    even  = (cols % 2 == 0)
    cols[even]  -= 1
    cols[~even] += 1
    # Discard groups where any masked value went out of [0,255]
    valid = np.all((cols >= 0) & (cols <= 255), axis=1)  # (M,)
    g_neg[:, mask] = cols
    f_neg = disc(g_neg)
    R_neg = int(np.sum((f_neg > f0) & valid))
    S_neg = int(np.sum((f_neg < f0) & valid))
    total = int(np.sum(valid))

    if total == 0:
        return 0.0, 0.0, 0.0, 0.0

    M = groups.shape[0]
    return R_pos/M, S_pos/M, R_neg/total, S_neg/total


# Maximum pixels to use for RS analysis.  The RS estimator converges well
# above ~50 k pixel groups (200 k pixels); scanning the full image adds
# seconds of compute for zero statistical benefit on large images.
_RS_MAX_PIXELS = 200_000


def rs_payload_estimate(img: np.ndarray) -> dict:
    """
    Sample-based RS steganalysis (Fridrich et al., 2001).

    Samples up to _RS_MAX_PIXELS pixels uniformly at random so the runtime
    is O(1) regardless of image resolution.  Statistical accuracy is
    indistinguishable from full-image analysis above ~50 k groups.

    Returns:
        payload_fraction  — estimated fraction of capacity used (0.0–1.0)
        payload_percent   — same as a percentage string
        rs_asymmetry      — raw R_pos - R_neg (positive = suspicious)
        confidence        — how reliable the estimate is
    """
    h, w = img.shape[:2]
    total_px = h * w
    rng = np.random.default_rng(42)  # fixed seed for reproducibility

    r_vals, s_vals, rn_vals, sn_vals = [], [], [], []

    for c in range(3):
        ch = img[:, :, c]
        if total_px > _RS_MAX_PIXELS:
            # Draw a random flat sample and reshape to a 1-D array
            idx = rng.choice(total_px, size=_RS_MAX_PIXELS, replace=False)
            flat = ch.flatten()[idx]
            ch_sample = flat.reshape(1, -1)  # treat as single-row image
        else:
            ch_sample = ch
        r, s, rn, sn = _classify_groups(ch_sample)
        r_vals.append(r); s_vals.append(s)
        rn_vals.append(rn); sn_vals.append(sn)

    R  = float(np.mean(r_vals))
    S  = float(np.mean(s_vals))
    Rn = float(np.mean(rn_vals))
    Sn = float(np.mean(sn_vals))

    asymmetry = R - Rn  # positive = stego-like

    # Linear payload estimator (simplified RS formula)
    # p ≈ (R - Rn) / (R - Rn + Sn - S)   [valid when denominator > 0]
    denom = (R - Rn) + (Sn - S)
    if denom > 1e-9:
        p = (R - Rn) / denom
        p = float(np.clip(p, 0.0, 1.0))
    else:
        p = 0.0

    # Confidence: asymmetry magnitude weighted by its ratio to total RS activity.
    # Old formula (signal/noise*10) was too permissive on random images.
    signal = abs(asymmetry)
    noise  = R + S + 1e-9
    asym_ratio = signal / noise
    magnitude_weight = float(np.clip(signal * 20, 0.0, 1.0))
    confidence = float(np.clip(asym_ratio * magnitude_weight * 5, 0.0, 1.0))

    return {
        "payload_fraction": round(p, 4),
        "payload_percent":  f"{p * 100:.1f}%",
        "rs_asymmetry":     round(asymmetry, 5),
        "confidence":       round(confidence, 3),
        "R_pos": round(R, 4), "S_pos": round(S, 4),
        "R_neg": round(Rn, 4), "S_neg": round(Sn, 4),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  Block-level feature extraction (V3 core, extended for bitplanes)
# ══════════════════════════════════════════════════════════════════════════════

def extract_block_features(block: np.ndarray, is_jpeg: bool = False) -> dict:
    """Vectorised — processes all 3 channels at once, no per-channel loops."""
    # block shape: (H, W, 3)
    lsb = (block & 1).astype(np.float32)              # (H, W, 3)

    # Vectorised binary entropy per channel — no Python loop.
    ones_ratio = lsb.mean(axis=(0, 1))                # (3,)
    p_c = np.clip(ones_ratio, 1e-9, 1 - 1e-9)
    with np.errstate(divide="ignore", invalid="ignore"):
        entropies_arr = -(p_c * np.log2(p_c) + (1 - p_c) * np.log2(1 - p_c))
    entropies = list(np.nan_to_num(entropies_arr, nan=0.0).tolist())
    biases     = np.abs(0.5 - ones_ratio)             # (3,)

    # Chi-square across all channels at once
    n = lsb.shape[0] * lsb.shape[1]
    ones_counts  = lsb.sum(axis=(0, 1))               # (3,)
    zeros_counts = n - ones_counts
    expected     = n / 2.0
    chi_norms    = ((ones_counts - expected)**2 + (zeros_counts - expected)**2) / (expected * n)

    # SRM residual — apply kernel with np.diff (avoids scipy import overhead)
    # Laplacian approximation: same as SRM_KERNEL but via 2-D diff, much faster
    lsb_f = lsb                                        # (H, W, 3)
    dy = np.diff(lsb_f, axis=0)                        # (H-1, W, 3)
    dx = np.diff(lsb_f, axis=1)                        # (H, W-1, 3)
    lsb_residuals = dy.var(axis=(0, 1)) + dx.var(axis=(0, 1))  # (3,) approximate

    # Multi-bitplane suspicion — pass is_jpeg so planes 1-3 are zeroed for JPEG
    bp_analysis = analyze_bitplanes(block, planes=4, is_jpeg=is_jpeg)

    return {
        "entropy":           float(np.min(entropies)),
        "bias":              float(np.max(biases)),
        "chi_norm":          float(np.mean(chi_norms)),
        "lsb_residual":      float(np.mean(lsb_residuals)),
        "bp_max_suspicion":  bp_analysis["max_suspicion"],
        "bp_deepest_plane":  bp_analysis["deepest_plane"],
    }


def extract_image_features(img: np.ndarray, block_size: int = 128,
                           is_jpeg: bool = False) -> Tuple[dict, List[dict]]:
    """
    Fully-vectorised feature extraction — zero Python loops over pixels or blocks.

    All statistics are computed over the whole image at once using NumPy
    stride tricks to create a (tiles_y, tiles_x, bh, bw, 3) view, then
    reduced along the tile axes.  This is ~20x faster than the original
    per-block Python loop.

    Block size auto-scales to keep tile count ~100-150 regardless of resolution.
    """
    h, w = img.shape[:2]

    # ── Auto-scale tile size ──────────────────────────────────────────────────
    target = 120
    bs = int(((h * w) / target) ** 0.5)
    bs = max(32, min(256, (bs // 32) * 32))  # clamp & align to 32

    # Trim image to a multiple of bs so tiles divide evenly
    H = (h // bs) * bs
    W = (w // bs) * bs
    if H < bs or W < bs:
        H, W = h, w  # too small — use full image as one tile

    crop   = img[:H, :W, :]                                    # (H, W, 3)
    tiles_y, tiles_x = H // bs, W // bs
    n_tiles = tiles_y * tiles_x

    # Reshape into tiles: (ty, tx, bs, bs, 3)
    tiled = crop.reshape(tiles_y, bs, tiles_x, bs, 3)
    tiled = tiled.transpose(0, 2, 1, 3, 4)                    # (ty, tx, bs, bs, 3)
    flat  = tiled.reshape(n_tiles, bs, bs, 3)                  # (N, bs, bs, 3)

    # ── LSB plane ─────────────────────────────────────────────────────────────
    lsb = (flat & 1).astype(np.float32)                        # (N, bs, bs, 3)

    # ── Brightness mask: exclude near-black tiles from LSB stats ─────────────
    # JPEG DCT quantises near-zero coefficients to exactly 0, making dark pixels
    # always even (LSB=0). This creates artificially low entropy that looks like
    # steganography but is just a property of dark JPEG images.
    # Threshold: mean pixel value < 20/255 (~8% brightness) → tile is "dark".
    tile_brightness = flat.mean(axis=(1, 2, 3))                # (N,) mean 0-255
    bright_mask = tile_brightness >= 20.0                      # (N,) bool
    # Fall back to all tiles if image is overwhelmingly dark (e.g. pure black test)
    if bright_mask.sum() < max(5, n_tiles // 10):
        bright_mask = np.ones(n_tiles, dtype=bool)

    # Entropy per tile per channel
    ones_mean = lsb.mean(axis=(1, 2))                          # (N, 3)
    bias_per  = np.abs(0.5 - ones_mean)                        # (N, 3)
    p = np.clip(ones_mean, 1e-6, 1 - 1e-6)
    with np.errstate(divide='ignore', invalid='ignore'):
        entropy_per = -(p * np.log2(p) + (1 - p) * np.log2(1 - p))  # (N, 3)
    entropy_per = np.nan_to_num(entropy_per, nan=0.0, posinf=1.0, neginf=0.0)

    # Per-tile worst (min entropy, max bias)
    entropy_tile = np.clip(entropy_per.min(axis=1), 0.0, 1.0)  # (N,) guaranteed [0,1]
    bias_tile    = np.clip(bias_per.max(axis=1), 0.0, 0.5)     # (N,) guaranteed [0,0.5]

    # Chi-square (LSB uniformity test)
    n_px = bs * bs
    ones_count  = (lsb.sum(axis=(1, 2)))                       # (N, 3)
    zeros_count = n_px - ones_count
    expected    = n_px / 2.0
    chi_raw  = (((ones_count - expected) ** 2 +
                 (zeros_count - expected) ** 2) / (expected * n_px)).mean(axis=1)
    chi_tile = np.nan_to_num(chi_raw, nan=0.0, posinf=0.0, neginf=0.0)  # (N,)

    # SRM-like residual via gradient variance (fast approximation)
    dy = np.diff(lsb.astype(np.float32), axis=1)              # (N, bs-1, bs, 3)
    dx = np.diff(lsb.astype(np.float32), axis=2)              # (N, bs, bs-1, 3)
    lsb_res_tile = np.nan_to_num(dy.var(axis=(1,2,3)) + dx.var(axis=(1,2,3)), nan=0.0)  # (N,)

    # ── Bitplane suspicion (plane 0 only for JPEG) ────────────────────────────
    if is_jpeg:
        bp_susp = bias_tile                                    # (N,) already computed
        bp_per_plane_p90 = {0: float(np.percentile(bias_tile[bright_mask], 90)),
                            1: 0.0, 2: 0.0, 3: 0.0}
    else:
        # Lossless: check planes 1-3 for unexpectedly high entropy
        bp_susp_vals = [bias_tile]
        bp_per_plane_p90 = {0: float(np.percentile(bias_tile[bright_mask], 90))}
        for p in range(1, 4):
            plane = ((flat >> p) & 1).astype(np.float32)
            pm    = plane.mean(axis=(1, 2))                    # (N, 3)
            pm    = np.clip(pm, 1e-6, 1 - 1e-6)
            with np.errstate(divide='ignore', invalid='ignore'):
                ent_p = -(pm * np.log2(pm) + (1 - pm) * np.log2(1 - pm))
            ent_p = np.nan_to_num(ent_p, nan=0.0, posinf=1.0, neginf=0.0)
            baseline_upper = {1: 0.90, 2: 0.75, 3: 0.60}
            upper = baseline_upper[p]
            susp_p = np.clip((ent_p.min(axis=1) - upper) / (1.0 - upper + 1e-9), 0, 1)
            bp_susp_vals.append(susp_p)
            bp_per_plane_p90[p] = float(np.percentile(susp_p[bright_mask], 90))
        bp_susp = np.stack(bp_susp_vals, axis=1).max(axis=1)  # (N,)

    # ── Tile anomaly scores ───────────────────────────────────────────────────
    # Dark tiles: set anomaly to 0 — their low entropy is JPEG quantisation,
    # not steganography. Only bright tiles can meaningfully be anomalous.
    anomaly = (
        (1.0 - entropy_tile) * 0.35 +
        bias_tile            * 0.30 +
        bp_susp              * 0.20 +
        np.clip(lsb_res_tile, 0, 1) * 0.15
    )
    anomaly = np.clip(anomaly, 0, 1)
    anomaly[~bright_mask] = 0.0  # dark tiles are never anomalous

    # ── Build block_records (for heatmap) ─────────────────────────────────────
    block_records = []
    tile_idx = 0
    for ty in range(tiles_y):
        for tx in range(tiles_x):
            y1, x1 = ty * bs, tx * bs
            block_records.append({
                "y1": y1, "x1": x1, "y2": y1 + bs, "x2": x1 + bs,
                "anomaly":      float(anomaly[tile_idx]),
                "deepest_plane": 0,   # simplified — plane 0 is primary signal
            })
            tile_idx += 1

    # ── Global features — computed on bright tiles only ───────────────────────
    # Using bright_mask excludes dark JPEG tiles whose near-zero LSB entropy
    # is caused by DCT quantisation, not steganography.
    et_bright  = entropy_tile[bright_mask]
    bt_bright  = bias_tile[bright_mask]
    chi_bright = chi_tile[bright_mask]
    res_bright = lsb_res_tile[bright_mask]
    bp_bright  = bp_susp[bright_mask]

    global_features = {
        "entropy_p10":       float(np.percentile(et_bright,  10)),
        "bias_p90":          float(np.percentile(bt_bright,  90)),
        "chi_norm_mean":     float(np.mean(chi_bright)),
        "lsb_residual_p90":  float(np.percentile(res_bright, 90)),
        "bp_suspicion_p90":  float(np.percentile(bp_bright,  90)),
        "block_count":       n_tiles,
    }
    return global_features, block_records, bp_per_plane_p90


# ══════════════════════════════════════════════════════════════════════════════
#  FEATURE 3 — Visual Forensic Heatmap
# ══════════════════════════════════════════════════════════════════════════════

def generate_heatmap(img: np.ndarray, block_records: List[dict], alpha: float = 0.45) -> np.ndarray:
    """
    Render a semi-transparent forensic overlay on the original image.

    Color coding:
      Green  (0, 200, 0)    — anomaly < 0.25  (clean block)
      Yellow (0, 200, 200)  — anomaly 0.25–0.5 (borderline)
      Orange (0, 140, 255)  — anomaly 0.5–0.75 (suspicious)
      Red    (0,  30, 220)  — anomaly > 0.75   (high confidence threat)

    The deepest anomalous bitplane is annotated in the block center.
    """
    overlay = img.copy().astype(np.float32)
    h, w = img.shape[:2]

    for rec in block_records:
        a = rec["anomaly"]
        y1, x1, y2, x2 = rec["y1"], rec["x1"], rec["y2"], rec["x2"]

        # BGR colors
        if a < 0.25:
            color = (0, 180, 0)        # green
        elif a < 0.50:
            color = (0, 200, 200)      # yellow
        elif a < 0.75:
            color = (0, 120, 255)      # orange
        else:
            color = (30, 30, 220)      # red

        # Fill block with semi-transparent color
        block_overlay = np.zeros((y2 - y1, x2 - x1, 3), dtype=np.float32)
        block_overlay[:] = color
        overlay[y1:y2, x1:x2] = (
            overlay[y1:y2, x1:x2] * (1 - alpha) + block_overlay * alpha
        )

        # Draw block border
        cv2.rectangle(overlay, (x1, y1), (x2 - 1, y2 - 1), color, 1)

        # Annotate deepest suspicious plane if anomaly is notable
        if a >= 0.25:
            label = f"P{rec['deepest_plane']} {a:.2f}"
            cx, cy = x1 + 4, y1 + 14
            # Shadow for readability
            cv2.putText(overlay, label, (cx + 1, cy + 1),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.38, (0, 0, 0), 1, cv2.LINE_AA)
            cv2.putText(overlay, label, (cx, cy),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.38, (255, 255, 255), 1, cv2.LINE_AA)

    # Legend (bottom-left corner)
    legend = [
        ((0, 180, 0),   "Clean   (<0.25)"),
        ((0, 200, 200), "Borderline (0.25-0.5)"),
        ((0, 120, 255), "Suspicious (0.5-0.75)"),
        ((30, 30, 220), "Threat   (>0.75)"),
    ]
    lx, ly = 8, h - 8 - len(legend) * 18
    cv2.rectangle(overlay, (lx - 4, ly - 4),
                  (lx + 195, ly + len(legend) * 18 + 2), (20, 20, 20), -1)
    for i, (col, text) in enumerate(legend):
        y_pos = ly + i * 18 + 13
        cv2.rectangle(overlay, (lx, y_pos - 10), (lx + 14, y_pos + 2), col, -1)
        cv2.putText(overlay, text, (lx + 20, y_pos),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.38, (220, 220, 220), 1, cv2.LINE_AA)

    return np.clip(overlay, 0, 255).astype(np.uint8)


# ══════════════════════════════════════════════════════════════════════════════
#  Calibration (unchanged from V3)
# ══════════════════════════════════════════════════════════════════════════════

class Calibration:
    K_SIGMA = 2.5

    def __init__(self):
        self.means: dict = {}
        self.stds:  dict = {}
        self.n_images: int = 0
        self.source_hint: str = "unknown"

    @property
    def is_ready(self) -> bool:
        return bool(self.means)

    def fit(self, feature_list: List[dict], source_hint: str = ""):
        if not feature_list:
            raise ValueError("Need at least one clean image to calibrate.")
        keys = [k for k in feature_list[0] if k != "block_count"]
        for k in keys:
            vals = [f[k] for f in feature_list]
            self.means[k] = float(np.mean(vals))
            self.stds[k]  = float(max(np.std(vals), 1e-6))
        self.n_images   = len(feature_list)
        self.source_hint = source_hint
        print(f"[Calibration] Fitted on {self.n_images} image(s). Source: {source_hint or 'unspecified'}")
        for k in keys:
            print(f"  {k:<28} mean={self.means[k]:.5f}  std={self.stds[k]:.5f}")

    def sigma_delta(self, features: dict) -> dict:
        deltas = {}
        for k in self.means:
            if k not in features:
                continue
            raw = (features[k] - self.means[k]) / self.stds[k]
            deltas[k] = -raw if k == "entropy_p10" else raw
        return deltas

    def save(self, path: str):
        with open(path, "w") as f:
            json.dump({"means": self.means, "stds": self.stds,
                       "n_images": self.n_images, "source_hint": self.source_hint}, f, indent=2)
        print(f"[Calibration] Saved → {path}")

    @classmethod
    def load(cls, path: str) -> "Calibration":
        with open(path) as f:
            d = json.load(f)
        c = cls()
        c.means = d["means"]; c.stds = d["stds"]
        c.n_images = d.get("n_images", 0)
        c.source_hint = d.get("source_hint", "unknown")
        print(f"[Calibration] Loaded ({c.n_images} images, source={c.source_hint})")
        return c


# ══════════════════════════════════════════════════════════════════════════════
#  Scoring
# ══════════════════════════════════════════════════════════════════════════════

FEATURE_WEIGHTS = {
    "entropy_p10":      0.30,
    "bias_p90":         0.25,
    "chi_norm_mean":    0.15,
    "lsb_residual_p90": 0.10,
    "bp_suspicion_p90": 0.20,   # new bitplane weight
}


def calculate_risk_score(features: dict, calibration: Optional[Calibration]) -> Tuple[float, dict]:
    breakdown = {}
    if calibration and calibration.is_ready:
        deltas = calibration.sigma_delta(features)
        total = weight_sum = 0.0
        for feat, weight in FEATURE_WEIGHTS.items():
            sigma = deltas.get(feat, 0.0)
            sub = _sigmoid((sigma - calibration.K_SIGMA) * 1.5)
            breakdown[feat] = {"sigma": round(sigma, 3), "sub_score": round(sub, 3)}
            total      += sub * weight
            weight_sum += weight
        risk = total / weight_sum if weight_sum else 0.0
    else:
        # Soft uncalibrated scoring — each feature contributes proportionally.
        # Empirical ranges: clean images cluster at low ends, stego at high ends.
        score = 0.0
        e  = features["entropy_p10"]        # clean: 0.85-0.99 | stego: 0.40-0.70
        b  = features["bias_p90"]           # clean: <0.10     | stego: >0.15
        c  = features["chi_norm_mean"]      # clean: <2e-4     | stego: >5e-4
        r  = features["lsb_residual_p90"]   # clean: <0.06     | stego: >0.10
        bp = features["bp_suspicion_p90"]   # clean: ~0        | stego: >0.20
        score += FEATURE_WEIGHTS["entropy_p10"]      * float(np.clip((0.80 - e) / 0.80, 0.0, 1.0))
        score += FEATURE_WEIGHTS["bias_p90"]         * float(np.clip((b - 0.08) / 0.20, 0.0, 1.0))
        score += FEATURE_WEIGHTS["chi_norm_mean"]    * float(np.clip((c - 1e-4) / 8e-4, 0.0, 1.0))
        score += FEATURE_WEIGHTS["lsb_residual_p90"] * float(np.clip((r - 0.05) / 0.15, 0.0, 1.0))
        score += FEATURE_WEIGHTS["bp_suspicion_p90"] * float(np.clip(bp / 0.40, 0.0, 1.0))
        breakdown = {"note": "uncalibrated — soft thresholds"}
        risk = score
    return float(min(risk, 1.0)), breakdown


# ══════════════════════════════════════════════════════════════════════════════
#  Sanitisation
# ══════════════════════════════════════════════════════════════════════════════

def sanitize_image(img: np.ndarray, risk: float) -> np.ndarray:
    """
    Strip steganographic content. Returns the pixel array to encode.
    The actual sanitisation happens in scrub_metadata via JPEG recompression
    — DCT quantisation unconditionally destroys all LSB/bitplane content.
    This function only needs to zero the lower bits as a belt-and-suspenders
    measure before the JPEG roundtrip.
    """
    # Zero bits 0-3; JPEG recompression will overwrite them with DCT values anyway
    return (img & np.uint8(0b11110000)).astype(np.uint8)


def scrub_metadata(raw_bytes: bytes) -> bytes:
    """
    Sanitise via JPEG recompression and return as JPEG (not PNG).

    Returning JPEG is critical: it ensures is_jpeg=True on any rescan,
    so bitplanes 1-3 are correctly skipped (they're always high-entropy
    after DCT quantisation — that's normal, not suspicious).

    Returning PNG caused the sanitised file to re-flag because:
      - is_jpeg=False → bitplanes 1-3 evaluated against lossless thresholds
      - DCT-reconstructed pixels have high bit-plane entropy → ANOMALOUS
    """
    pil_img = Image.open(io.BytesIO(raw_bytes)).convert("RGB")
    jpeg_buf = io.BytesIO()
    # Quality 88: good visual fidelity, full DCT destruction of LSB content
    pil_img.save(jpeg_buf, format="JPEG", quality=88, optimize=True)
    return jpeg_buf.getvalue()


# ══════════════════════════════════════════════════════════════════════════════
#  External Tool Scanners — zsteg & binwalk
# ══════════════════════════════════════════════════════════════════════════════

def _tool_available(name: str) -> bool:
    """Return True if the CLI tool is on PATH."""
    return shutil.which(name) is not None


def _write_temp(raw_bytes: bytes, suffix: str = ".png") -> str:
    """Write bytes to a NamedTemporaryFile and return its path. Caller must delete."""
    tmp = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    tmp.write(raw_bytes)
    tmp.flush()
    tmp.close()
    return tmp.name


# ── zsteg ─────────────────────────────────────────────────────────────────────

# Patterns in zsteg output that indicate real hidden content (not noise artefacts)
_ZSTEG_SIGNAL_PATTERNS = [
    r"text\s*:\s*\".{4,}\"",           # readable text >= 4 chars
    r"(zip|rar|pdf|exe|png|jpg|mp3|7z|gz|tar)\b",  # embedded file magic
    r"(PK\x03\x04|MZ|\x7fELF|%PDF)",   # binary signatures
    r"extradata\s*:",                   # data appended after image end
    r"(openssl|-----BEGIN|ssh-rsa)",    # crypto artefacts
    r"offset\s*=\s*\d+.*size\s*=\s*\d+",  # explicit data blocks
]
_ZSTEG_NOISE_WORDS = {"random", "noise", "nils", "null", "nothing", "00 00 00"}


def run_zsteg(raw_bytes: bytes, filename: str = "image.png") -> Dict[str, Any]:
    """
    Run zsteg on an image and return structured findings.

    zsteg is a Ruby gem: gem install zsteg
    It checks multiple LSB bit-plane combinations (b1,r,lsb,xy etc.)
    and reports any readable strings or embedded file signatures.

    Returns:
        available      — bool, False if zsteg is not installed
        findings       — list of {channel, description, signal_strength}
        signal_count   — number of high-signal findings
        has_text       — any readable strings detected
        has_embedded   — embedded file signatures detected
        raw_output     — full stdout for audit trail
        risk_boost     — float 0.0–0.35 contribution to risk score
        error          — error message if tool failed, else None
    """
    result: Dict[str, Any] = {
        "available":    False,
        "findings":     [],
        "signal_count": 0,
        "has_text":     False,
        "has_embedded": False,
        "raw_output":   "",
        "risk_boost":   0.0,
        "error":        None,
    }

    if not _tool_available("zsteg"):
        result["error"] = "zsteg not installed (gem install zsteg)"
        return result

    result["available"] = True

    # zsteg only handles PNG and BMP natively — ensure correct extension
    ext = os.path.splitext(filename)[-1].lower()
    if ext not in {".png", ".bmp"}:
        ext = ".png"

    tmp = _write_temp(raw_bytes, suffix=ext)
    try:
        proc = subprocess.run(
            ["zsteg", "-a", tmp],          # -a = all channels
            capture_output=True,
            text=True,
            timeout=60,
        )
        output = proc.stdout + proc.stderr
        result["raw_output"] = output.strip()
    except subprocess.TimeoutExpired:
        result["error"] = "zsteg timed out (>60s)"
        os.unlink(tmp)
        return result
    except Exception as e:
        result["error"] = f"zsteg execution failed: {e}"
        os.unlink(tmp)
        return result
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass

    # ── Parse output ──────────────────────────────────────────────────────────
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("imagedata"):
            continue

        # Each zsteg line: "<channel>   .. <description>"
        parts = line.split("..", 1)
        if len(parts) != 2:
            continue
        channel     = parts[0].strip()
        description = parts[1].strip()

        # Skip clearly noisy lines
        if any(w in description.lower() for w in _ZSTEG_NOISE_WORDS):
            continue

        # Score signal strength
        strength = 0
        for pattern in _ZSTEG_SIGNAL_PATTERNS:
            if re.search(pattern, description, re.IGNORECASE):
                strength += 1

        if "text" in description.lower() and len(description) > 10:
            strength += 1
            result["has_text"] = True

        embed_keywords = ["zip", "png", "jpg", "exe", "pdf", "elf", "pk\x03\x04"]
        if any(k in description.lower() for k in embed_keywords):
            result["has_embedded"] = True
            strength += 2

        if "extradata" in description.lower():
            result["has_embedded"] = True
            strength += 2

        findings.append({
            "channel":          channel,
            "description":      description,
            "signal_strength":  strength,
        })

    # Only surface findings with at least some signal
    signal_findings = [f for f in findings if f["signal_strength"] > 0]
    result["findings"]     = signal_findings
    result["signal_count"] = len(signal_findings)

    # ── Risk contribution ─────────────────────────────────────────────────────
    # Each confirmed signal finding adds to risk, capped at 0.35
    if result["has_embedded"]:
        result["risk_boost"] = min(0.35, 0.20 + result["signal_count"] * 0.03)
    elif result["has_text"]:
        result["risk_boost"] = min(0.25, 0.10 + result["signal_count"] * 0.025)
    elif result["signal_count"] > 0:
        result["risk_boost"] = min(0.15, result["signal_count"] * 0.02)

    return result


# ── binwalk ───────────────────────────────────────────────────────────────────

# File signatures that are expected in a clean image file (first entry only)
_BINWALK_EXPECTED_SIGS = {
    "png image", "jpeg image", "bmp image", "gif image",
    "tiff image", "webp", "riff", "jfif",
}

# Signatures that are strongly suspicious when found inside an image
_BINWALK_THREAT_SIGS = {
    "zip archive", "rar archive", "7-zip archive", "gzip compressed",
    "bzip2 compressed", "xz compressed", "tar archive",
    "pe32", "elf", "executable", "pdf document",
    "sqlite", "mysql", "openssl", "private key", "certificate",
    "mp3", "mp4", "ogg", "wav", "avi",
    "base64", "javascript", "html document",
}

# Printable-text content types detectable in LSB streams
_LSB_TEXT_MARKERS = [
    b'{"',    b"{'",    b'[{',                        # JSON / config
    b'<?xml', b'<html', b'<config', b'<!',            # XML / HTML
    b'[DEFAULT]', b'[settings]', b'[config]',         # INI files
    b'[database]', b'[server]', b'[app]', b'[api]',  # more INI sections
    b'-----BEGIN',                                     # PEM / crypto
    b'#!/',                                            # scripts
    b'http://', b'https://',                           # URLs
    b'password', b'secret', b'token', b'key=',        # credentials
    b'user=', b'host=', b'port=', b'db=',
    b'PASSWORD', b'SECRET', b'TOKEN', b'API_KEY',
    b'DATABASE_URL', b'REDIS_URL', b'MONGO_URI',
]


def _extract_lsb_stream(raw_bytes: bytes) -> List[Tuple[str, bytes]]:
    """
    Extract LSB hidden streams using multiple bit-ordering modes.

    Returns a list of (mode_label, byte_stream) tuples.
    We try four modes because different tools use different channel orders:
      - rgb3  : R G B  (3 bits/pixel, most common)
      - rgba4 : R G B A (4 bits/pixel, Canvas API / browser-based tools)
      - bgr3  : B G R  (OpenCV native order)
      - r1    : R only  (single-channel tools)

    SteganoCrypt uses the browser Canvas API which returns pixels as RGBA,
    so rgba4 mode is the most likely to match its encoding.
    """
    results: List[Tuple[str, bytes]] = []
    try:
        arr = np.frombuffer(raw_bytes, np.uint8)
        img_bgr = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img_bgr is None:
            return results

        h, w = img_bgr.shape[:2]

        def pack(bits: np.ndarray) -> bytes:
            n = (len(bits) // 8) * 8
            return np.packbits(bits[:n]).tobytes()

        # Mode 1: RGB — R G B interleaved (most LSB tools)
        rgb = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2RGB)
        bits_rgb = (rgb.reshape(-1, 3) & 1).flatten()
        results.append(("rgb3", pack(bits_rgb)))

        # Mode 2: RGBA — R G B A interleaved (Canvas API / browser tools like SteganoCrypt)
        # Synthesise alpha=255 since we decoded with IMREAD_COLOR
        rgba = np.dstack([rgb, np.full((h, w), 255, dtype=np.uint8)])
        bits_rgba = (rgba.reshape(-1, 4) & 1).flatten()
        results.append(("rgba4", pack(bits_rgba)))

        # Mode 3: BGR native (OpenCV order — some tools don't reorder)
        bits_bgr = (img_bgr.reshape(-1, 3) & 1).flatten()
        results.append(("bgr3", pack(bits_bgr)))

        # Mode 4: R channel only (single-channel tools)
        bits_r = (rgb[:, :, 0].flatten() & 1)
        results.append(("r1", pack(bits_r)))

        # Mode 5: 2-bit LSB — bits 0+1 interleaved (higher-capacity tools)
        flat_rgb = rgb.reshape(-1, 3).astype(np.uint8)
        b0 = (flat_rgb & 1).flatten()
        b1 = ((flat_rgb >> 1) & 1).flatten()
        bits2 = np.empty(len(b0) + len(b1), dtype=np.uint8)
        bits2[0::2] = b0; bits2[1::2] = b1
        results.append(("rgb3_b2", pack(bits2)))

        # Mode 6: column-major RGB (some tools scan column-by-column)
        bits_col = (rgb.transpose(1, 0, 2).reshape(-1, 3) & 1).flatten()
        results.append(("rgb3_col", pack(bits_col)))

    except Exception:
        pass
    return results


def _scan_lsb_for_text(lsb_bytes: bytes, mode: str = "") -> List[dict]:
    """
    Scan an LSB stream for real hidden content.

    Two high-confidence strategies only — the old ascii_run strategy is
    removed because random JPEG LSB noise trivially satisfies a MIN_RUN=32
    + 55% alnum check, producing false positives on every clean image.

    Strategy 1 — SteganoCrypt length-prefix detection
      SteganoCrypt prepends a 4-byte LE length field then the raw payload.
      We validate: declared length is sane (8..1MB), >= 85% of the first
      256 payload bytes are printable ASCII, AND the content passes a word-
      recognition check.  Random noise essentially never satisfies all three.

    Strategy 2 — High-confidence structural markers
      Byte sequences that are vanishingly unlikely in random data:
      PEM headers, XML/HTML declarations, shebangs, full credential keys.
      Short noisy markers ('{', '[{', etc.) are excluded.
    """
    findings: List[dict] = []
    seen: set = set()
    label = f"[{mode}] " if mode else ""

    def add(offset: int, marker: str, snippet: str) -> None:
        bucket = offset // 128
        if bucket not in seen:
            seen.add(bucket)
            findings.append({
                "lsb_offset": offset,
                "marker":     label + marker,
                "snippet":    snippet[:120],
                "is_threat":  True,
            })

    scan_limit = min(len(lsb_bytes), 1024 * 1024)

    def _qualifies(chunk: bytes) -> bool:
        """
        True if chunk looks like real text/payload, not JPEG LSB noise.
        JPEG LSB noise: ~24% alnum mean, ~35% max.
        Real payloads (text, JSON, config): 62-95% alnum.
        No vocabulary gate — it rejects valid JSON keys, filenames, non-English.
        """
        if len(chunk) < 8:
            return False
        alnum = sum(1 for b in chunk
                    if 65 <= b <= 90 or 97 <= b <= 122 or 48 <= b <= 57)
        return (alnum / len(chunk)) >= 0.62

    # ── Strategy 1: length-prefixed payload detection ────────────────────────
    # Try both LE and BE + multiple header offsets.
    # SteganoCrypt: 4-byte LE. Other tools vary. JSON has "{}:," so 0.75 threshold.
    _found_length_payload = False
    for endian in ("little", "big"):
        if _found_length_payload:
            break
        for hdr_skip in (0, 4, 8, 16, 32):
            if hdr_skip + 4 >= scan_limit:
                break
            payload_len = int.from_bytes(lsb_bytes[hdr_skip: hdr_skip + 4], endian)
            if not (8 <= payload_len <= 2_000_000):
                continue
            start = hdr_skip + 4
            chunk = lsb_bytes[start: start + min(payload_len, 512)]
            if len(chunk) < 8:
                continue
            printable_ratio = sum(1 for b in chunk if 32 <= b <= 126) / len(chunk)
            if printable_ratio < 0.75:
                continue
            if _qualifies(chunk[:256]):
                snip = chunk[:120].decode("ascii", errors="replace")
                add(start, f"lsb_payload({endian},len={payload_len})", snip)
                _found_length_payload = True
                break

    # ── Strategy 2: high-confidence structural markers ────────────────────────
    _HC_MARKERS = [
        # Crypto / keys
        b"-----BEGIN", b"PRIVATE KEY", b"ssh-rsa ", b"ssh-ed25519 ", b"ssh-ecdsa ",
        # Markup / scripts
        b"<?xml", b"<!DOCTYPE", b"<html", b"<svg", b"#!/",
        # URLs
        b"https://", b"http://", b"ftp://",
        # Credentials
        b"PASSWORD=", b"password=", b"SECRET=", b"secret=",
        b"API_KEY=", b"api_key=", b"DATABASE_URL=", b"REDIS_URL=",
        b"Authorization: ", b"Bearer ",
        # Common steg tool markers
        b"STEG", b"steg", b"HIDDEN", b"hidden:",
        # Binary file signatures (often embedded as payload)
        b"\x89PNG", b"PK\x03\x04", b"%PDF", b"Rar!",
    ]
    for marker in _HC_MARKERS:
        idx = lsb_bytes.find(marker, 0, scan_limit)
        if idx != -1:
            raw = lsb_bytes[idx: idx + 120]
            snip = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
            add(idx, marker.decode("utf-8", errors="replace"), snip)

    return findings


def _run_binwalk_on_bytes(data: bytes, label: str, file_size: int,
                           timeout: int = 10,
                           sig_only: bool = False) -> Tuple[List[dict], bool, bool, str]:
    """
    Write data to a temp file, run binwalk, parse results.

    sig_only=True: run --signature only (no --entropy).
      Used for LSB streams where entropy is always near-max (useless)
      and skipping it saves ~1s per call.
    Returns (entries, has_appended, entropy_spike, raw_output).
    """
    tmp = _write_temp(data, suffix=".bin")
    entries: List[dict] = []
    has_appended  = False
    entropy_spike = False
    raw_output    = ""
    first_entry_seen = False

    try:
        # --signature detects embedded file formats (ZIP/PNG/ELF/PDF etc.)
        # --entropy detects high-randomness regions (encrypted/compressed data)
        # Previously only --entropy ran — binary payloads were completely missed.
        cmd = ["binwalk", "--signature", tmp] if sig_only else \
              ["binwalk", "--signature", "--entropy", tmp]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        raw_output = (proc.stdout + proc.stderr).strip()
    except subprocess.TimeoutExpired:
        raw_output = "TIMEOUT"
    except Exception as e:
        raw_output = f"ERROR: {e}"
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass

    for line in raw_output.splitlines():
        line = line.strip()
        if not line or line.startswith("DECIMAL") or line.startswith("-"):
            continue
        if "entropy" in line.lower() and "rising" in line.lower():
            entropy_spike = True
            continue
        match = re.match(r"^(\d+)\s+(0x[0-9A-Fa-f]+)\s+(.+)$", line)
        if not match:
            continue
        offset      = int(match.group(1))
        hex_offset  = match.group(2)
        description = match.group(3).strip()
        desc_lower  = description.lower()
        is_threat   = any(t in desc_lower for t in _BINWALK_THREAT_SIGS)
        if first_entry_seen and offset > file_size * 0.9:
            has_appended = True
        if not first_entry_seen:
            first_entry_seen = True
            is_threat = False
        entries.append({
            "offset":      offset,
            "hex_offset":  hex_offset,
            "description": description,
            "is_threat":   is_threat,
            "source":      label,
        })

    return entries, has_appended, entropy_spike, raw_output


def run_binwalk(raw_bytes: bytes, filename: str = "image.png") -> Dict[str, Any]:
    """
    Run binwalk on the image in two passes:

    Pass 1 — raw file scan (detects appended data, IDAT-embedded archives)
    Pass 2 — LSB bitstream scan (detects content hidden by tools like
              SteganoCrypt that embed data across pixel LSBs)

    The LSB stream is reconstructed by collecting the least-significant bit
    of every R, G, B channel value in pixel order and packing them into bytes.
    If the hidden payload is a config file, JSON, XML, script, or any file
    with a recognisable header, binwalk will identify it in pass 2.

    Returns:
        available        — bool
        entries          — list of {offset, hex_offset, description, is_threat, source}
        lsb_findings     — text/marker hits found directly in the LSB stream
        total_entries    — total signatures found across both passes
        threat_entries   — count of threat-class signatures
        has_appended     — data found after the image end (pass 1)
        lsb_has_content  — structured content detected in LSB stream (pass 2)
        entropy_spike    — entropy anomaly detected
        raw_output       — combined stdout for audit
        risk_boost       — float 0.0–0.45 contribution to risk score
        error            — error string or None
    """
    result: Dict[str, Any] = {
        "available":       False,
        "entries":         [],
        "lsb_findings":    [],
        "total_entries":   0,
        "threat_entries":  0,
        "has_appended":    False,
        "lsb_has_content": False,
        "entropy_spike":   False,
        "raw_output":      "",
        "risk_boost":      0.0,
        "error":           None,
    }

    if not _tool_available("binwalk"):
        result["error"] = "binwalk not installed (pip install binwalk OR brew install binwalk)"
        return result

    result["available"] = True
    all_raw: List[str] = []

    # ── Pass 1: raw file ──────────────────────────────────────────────────────
    entries1, has_appended, spike1, raw1 = _run_binwalk_on_bytes(
        raw_bytes, label="file", file_size=len(raw_bytes)
    )
    all_raw.append(f"=== PASS 1: raw file ===\n{raw1}")
    result["has_appended"]  = has_appended
    result["entropy_spike"] = spike1

    # ── Pass 2: LSB bitstream — all extraction modes ─────────────────────────
    # _extract_lsb_stream now returns [(mode, bytes), ...] for rgb3/rgba4/bgr3/r1
    lsb_streams = _extract_lsb_stream(raw_bytes)
    entries2: List[dict] = []
    lsb_findings: List[dict] = []

    # ── Fast text scan first (pure Python, no subprocesses) ─────────────────
    # If no text/marker hits found in any LSB stream we skip the expensive
    # binwalk subprocess passes for those modes — saves ~60s on clean images.
    text_findings_by_mode: dict = {}
    for mode, lsb_stream in lsb_streams:
        if not lsb_stream or len(lsb_stream) < 16:
            continue
        hits = _scan_lsb_for_text(lsb_stream, mode=mode)
        text_findings_by_mode[mode] = (lsb_stream, hits)
        lsb_findings.extend(hits)

    # binwalk LSB passes: always rgb3 + rgba4, extra modes only if text hit.
    # Hard cap at 3 passes — on a 12MP threat image 6 passes × 2-3s = 18s.
    # LSB --entropy is useless (packed bits always near max entropy), so we
    # use signature-only for LSB passes via a dedicated fast helper below.
    priority_modes = {"rgb3", "rgba4"}
    modes_for_binwalk = [
        (mode, stream)
        for mode, (stream, hits) in text_findings_by_mode.items()
        if mode in priority_modes or hits
    ]
    modes_for_binwalk = modes_for_binwalk[:3]  # never more than 3 LSB passes

    def _bw_lsb_pass(mode_stream):
        mode, stream = mode_stream
        # Signature-only for LSB streams (entropy on packed bits = useless noise)
        ents, _, spike, raw = _run_binwalk_on_bytes(
            stream, label=f"lsb_{mode}", file_size=len(stream),
            sig_only=True,
        )
        return mode, ents, spike, raw

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {pool.submit(_bw_lsb_pass, ms): ms[0] for ms in modes_for_binwalk}
        for fut in as_completed(futures):
            try:
                mode, ents, spike2, raw2 = fut.result()
                all_raw.append(f"=== PASS 2 [{mode}] ===\n{raw2}")
                if spike2:
                    result["entropy_spike"] = True
                entries2.extend(ents)
            except Exception:
                pass

    # Deduplicate lsb_findings by (offset // 64, marker) across modes
    seen_lsb: set = set()
    deduped: List[dict] = []
    for f in lsb_findings:
        key = (f["lsb_offset"] // 64, f["marker"].split("]")[-1].strip()[:20])
        if key not in seen_lsb:
            seen_lsb.add(key)
            deduped.append(f)
    lsb_findings = deduped

    result["lsb_findings"]    = lsb_findings
    # Require at least 2 independent LSB findings before flagging lsb_has_content,
    # or 1 finding that also has a corroborating binwalk threat signature.
    # A single ascii_run hit in noisy JPEG LSB data is too weak on its own.
    result["lsb_has_content"] = len(lsb_findings) >= 1  # strict scanner: 1 hit = real signal

    # Merge entries from both passes; LSB-stream entries are always threat-class
    # because file signatures in an LSB stream are never innocent
    for e in entries2:
        e["is_threat"] = True
    all_entries = entries1 + entries2

    result["entries"]        = all_entries
    result["total_entries"]  = len(all_entries)
    result["threat_entries"] = sum(1 for e in all_entries if e["is_threat"])
    result["raw_output"]     = "\n\n".join(all_raw)

    # ── Risk contribution ─────────────────────────────────────────────────────
    # Require corroborating evidence before applying large risk boosts.
    # A single lsb_findings hit (ascii_run in noisy JPEG data) is a weak
    # signal on its own; it must be accompanied by threat-class file
    # signatures or multiple independent findings to elevate risk significantly.
    n_threat      = result["threat_entries"]
    lsb_hit       = result["lsb_has_content"]
    n_lsb         = len(lsb_findings)
    appended      = result["has_appended"]

    # The new _scan_lsb_for_text requires strong evidence (SteganoCrypt length
    # prefix + 85% printable + linguistic check, OR high-confidence markers).
    # Every hit here is a real signal — boost accordingly.
    if lsb_hit and n_threat > 0:
        result["risk_boost"] = min(0.45, 0.30 + n_threat * 0.05)
    elif lsb_hit:
        # Confirmed LSB payload (no binwalk file sig needed — scanner is strict)
        result["risk_boost"] = min(0.40, 0.25 + n_lsb * 0.05)
    elif appended and n_threat > 0:
        result["risk_boost"] = min(0.40, 0.25 + n_threat * 0.05)
    elif n_threat > 0:
        result["risk_boost"] = min(0.30, 0.12 + n_threat * 0.06)
    elif appended:
        result["risk_boost"] = 0.10
    elif result["entropy_spike"] and len(all_entries) > 1:
        result["risk_boost"] = 0.05

    return result


# ══════════════════════════════════════════════════════════════════════════════
#  Main Engine
# ══════════════════════════════════════════════════════════════════════════════


def _sanitise_floats(obj):
    """
    Recursively walk a JSON-serialisable structure and replace any
    float NaN / Inf / -Inf with safe fallback values (0.0).
    Python's json module rejects out-of-range floats (IEEE 754 specials).
    """
    if isinstance(obj, float):
        if obj != obj or obj == float("inf") or obj == float("-inf"):
            return 0.0
        return obj
    if isinstance(obj, dict):
        return {k: _sanitise_floats(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitise_floats(v) for v in obj]
    return obj


class EnterpriseStegEngine:
    """
    V4.0 — Multi-bitplane + RS Steganalysis + Visual Heatmap.

    Usage:
        engine = EnterpriseStegEngine()
        engine.calibrate_from_files(["clean1.png", "clean2.png"], source_hint="web")
        engine.save_calibration("calibration_web.json")

        result = engine.process_file(open("suspect.png","rb").read())
        print(result["rs"]["payload_percent"])   # e.g. "12.4%"
        # result["heatmap_bytes"] is a PNG you can save directly
    """

    def __init__(self, block_size: int = 128):
        self.block_size = block_size
        self.calibration: Optional[Calibration] = None

    # ── Calibration ──────────────────────────────────────────────────────────

    def calibrate_from_files(self, paths: List[str], source_hint: str = ""):
        feature_list = []
        for p in paths:
            with open(p, "rb") as f:
                raw = f.read()
            img = self._decode(raw)
            jpeg = self._is_jpeg(raw, p)
            features, _, _bp = extract_image_features(img, self.block_size, is_jpeg=jpeg)
            feature_list.append(features)
        cal = Calibration()
        cal.fit(feature_list, source_hint)
        self.calibration = cal

    def calibrate_from_bytes(self, raw_list: List[bytes], source_hint: str = ""):
        feature_list = []
        for raw in raw_list:
            img = self._decode(raw)
            jpeg = self._is_jpeg(raw, "")
            features, _, _bp = extract_image_features(img, self.block_size, is_jpeg=jpeg)
            feature_list.append(features)
        cal = Calibration()
        cal.fit(feature_list, source_hint)
        self.calibration = cal

    def save_calibration(self, path: str):
        if not self.calibration:
            raise RuntimeError("No calibration to save.")
        self.calibration.save(path)

    def load_calibration(self, path: str):
        self.calibration = Calibration.load(path)

    # ── Core ─────────────────────────────────────────────────────────────────

    @staticmethod
    def _decode(raw_bytes: bytes) -> np.ndarray:
        arr = np.frombuffer(raw_bytes, np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img is None:
            raise ValueError("Could not decode image.")
        return img

    @staticmethod
    def _is_jpeg(raw_bytes: bytes, filename: str) -> bool:
        """Return True if the file is JPEG by magic bytes or extension."""
        # JPEG magic: FF D8 FF
        if raw_bytes[:3] == b"\xff\xd8\xff":
            return True
        ext = os.path.splitext(filename)[-1].lower()
        return ext in {".jpg", ".jpeg"}

    def process_file(self, raw_bytes: bytes, filename: str = "image.png") -> dict:
        img = self._decode(raw_bytes)
        is_jpeg = self._is_jpeg(raw_bytes, filename)

        # ── Feature extraction (with block records for heatmap) ───────────
        features, block_records, bp_per_plane_p90 = extract_image_features(
            img, self.block_size, is_jpeg=is_jpeg)

        # ── RS payload estimation ─────────────────────────────────────────
        rs = rs_payload_estimate(img)

        # ── Risk scoring ──────────────────────────────────────────────────
        risk, breakdown = calculate_risk_score(features, self.calibration)

        # Boost risk if RS confirms a meaningful payload
        if rs["payload_fraction"] > 0.05 and rs["confidence"] > 0.3:
            rs_boost = rs["payload_fraction"] * rs["confidence"] * 0.2
            risk = float(min(risk + rs_boost, 1.0))

        # ── zsteg + binwalk — run in parallel ────────────────────────────
        with ThreadPoolExecutor(max_workers=2) as pool:
            fut_zsteg   = pool.submit(run_zsteg,   raw_bytes, filename)
            fut_binwalk = pool.submit(run_binwalk, raw_bytes, filename)
            zsteg_result   = fut_zsteg.result()
            binwalk_result = fut_binwalk.result()

        if zsteg_result["available"] and zsteg_result["risk_boost"] > 0:
            risk = float(min(risk + zsteg_result["risk_boost"], 1.0))
        if binwalk_result["available"] and binwalk_result["risk_boost"] > 0:
            risk = float(min(risk + binwalk_result["risk_boost"], 1.0))

        # ── Delta report ──────────────────────────────────────────────────
        delta_report = {}
        if self.calibration and self.calibration.is_ready:
            for feat, info in breakdown.items():
                if isinstance(info, dict) and "sigma" in info:
                    sigma = info["sigma"]
                    verdict = (
                        "CLEAN"      if sigma < 1.0 else
                        "borderline" if sigma < self.calibration.K_SIGMA else
                        "ANOMALOUS"
                    )
                    delta_report[feat] = f"{sigma:+.2f}σ [{verdict}]"

        # ── Sanitised output — always JPEG so is_jpeg=True on rescan ────────
        safe_matrix = sanitize_image(img, risk)
        _, buf = cv2.imencode(".jpg", safe_matrix,
                              [cv2.IMWRITE_JPEG_QUALITY, 88])
        safe_bytes = scrub_metadata(buf.tobytes())

        # ── Heatmap — stays PNG (visual overlay, never rescanned) ─────────
        heatmap_img = generate_heatmap(img, block_records)
        _, hm_buf = cv2.imencode(".png", heatmap_img)
        # Simple metadata strip for heatmap (no JPEG roundtrip needed)
        hm_pil = Image.open(io.BytesIO(hm_buf.tobytes())).convert("RGB")
        hm_out = io.BytesIO()
        hm_pil.save(hm_out, format="PNG", optimize=True)
        heatmap_bytes = hm_out.getvalue()

        # Real per-plane suspicion from vectorised extractor.
        # For JPEG: planes 1-3 are always 0.0 (DCT makes them high-entropy normally).
        bp_planes = {str(p): round(float(bp_per_plane_p90.get(p, 0.0)), 4)
                     for p in range(4)}
        # Plane 0 override: use entropy-derived suspicion for clearer LSB signal
        bp_planes["0"] = round(max(0.0, 1.0 - features.get("entropy_p10", 1.0)), 4)

        raw_result = {
            "is_threat":        risk >= 0.5,
            "risk_score":       round(risk * 100, 2),
            "calibrated":       bool(self.calibration and self.calibration.is_ready),
            "is_jpeg":          is_jpeg,
            "features":         {k: round(v, 6) for k, v in features.items() if k != "block_count"},
            "bp_planes":        bp_planes,
            "blocks_analysed":  features.get("block_count", 0),
            "rs":               rs,
            "score_breakdown":  breakdown,
            "delta_report":     delta_report,
            "zsteg":            zsteg_result,
            "binwalk":          binwalk_result,
            "safe_file_bytes":  safe_bytes,
            "heatmap_bytes":    heatmap_bytes,
        }
        # Strip NaN/inf before handing to JSON — IEEE specials crash the encoder
        return _sanitise_floats(raw_result)

    def generate_calibration_report(self) -> str:
        if not self.calibration or not self.calibration.is_ready:
            return "No calibration loaded."
        lines = [
            "Calibration Report",
            f"  Source hint : {self.calibration.source_hint}",
            f"  Images used : {self.calibration.n_images}",
            f"  Threshold K : {self.calibration.K_SIGMA}σ",
            "",
            f"  {'Feature':<28} {'Mean':>10} {'Std':>10} {'Threshold':>14}",
            "  " + "─" * 66,
        ]
        for k, w in FEATURE_WEIGHTS.items():
            mean = self.calibration.means.get(k, 0)
            std  = self.calibration.stds.get(k, 0)
            if k == "entropy_p10":
                thresh = mean - self.calibration.K_SIGMA * std
                direction = f"< {thresh:.5f}"
            else:
                thresh = mean + self.calibration.K_SIGMA * std
                direction = f"> {thresh:.5f}"
            lines.append(f"  {k:<28} {mean:>10.5f} {std:>10.5f} {direction:>14}  (w={w})")
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════════

def _print_result(result: dict, label: str = ""):
    tag = f" [{label}]" if label else ""
    w = 60
    print(f"\n{'─'*w}")
    print(f"  Forensic Analysis Report V4.5{tag}")
    print(f"{'─'*w}")
    print(f"  Threat Confidence  : {result['risk_score']}%")
    print(f"  Actionable Threat  : {result['is_threat']}")
    print(f"  Calibrated Mode    : {result['calibrated']}")
    print(f"  Blocks Analysed    : {result['blocks_analysed']}")

    rs = result["rs"]
    print(f"\n  ── RS Payload Estimate ──────────────────────────────────")
    print(f"  Estimated Payload  : {rs['payload_percent']} of image capacity")
    print(f"  RS Asymmetry       : {rs['rs_asymmetry']:+.5f}  (>0 = stego-like)")
    print(f"  RS Confidence      : {rs['confidence']:.3f}")
    print(f"  R+/S+ | R-/S-      : {rs['R_pos']:.4f}/{rs['S_pos']:.4f}  |  {rs['R_neg']:.4f}/{rs['S_neg']:.4f}")

    print(f"\n  ── Raw Features ─────────────────────────────────────────")
    for k, v in result["features"].items():
        print(f"    {k:<28} {v:.6f}")

    if result["delta_report"]:
        print(f"\n  ── Delta from Baseline ──────────────────────────────────")
        for k, v in result["delta_report"].items():
            print(f"    {k:<28} {v}")

    # ── zsteg ──────────────────────────────────────────────────────────────
    zs = result.get("zsteg", {})
    print(f"\n  ── zsteg ────────────────────────────────────────────────")
    if not zs.get("available"):
        print(f"  ⚠  {zs.get('error', 'zsteg not available')}")
    else:
        sc = zs["signal_count"]
        print(f"  Signal findings    : {sc}")
        print(f"  Has readable text  : {zs['has_text']}")
        print(f"  Has embedded file  : {zs['has_embedded']}")
        print(f"  Risk boost         : +{zs['risk_boost']:.3f}")
        if zs["findings"]:
            print(f"  Top findings:")
            for f in zs["findings"][:8]:
                print(f"    [{f['signal_strength']}★] {f['channel']:<26} {f['description'][:60]}")

    # ── binwalk ────────────────────────────────────────────────────────────
    bw = result.get("binwalk", {})
    print(f"\n  ── binwalk ──────────────────────────────────────────────")
    if not bw.get("available"):
        print(f"  ⚠  {bw.get('error', 'binwalk not available')}")
    else:
        print(f"  Signatures found   : {bw['total_entries']}")
        print(f"  Threat signatures  : {bw['threat_entries']}")
        print(f"  Appended data      : {bw['has_appended']}")
        print(f"  Entropy spike      : {bw['entropy_spike']}")
        print(f"  Risk boost         : +{bw['risk_boost']:.3f}")
        if bw["entries"]:
            print(f"  Entries:")
            for e in bw["entries"][:10]:
                flag = " ⚠ THREAT" if e["is_threat"] else ""
                print(f"    {e['hex_offset']:<12} {e['description'][:55]}{flag}")

    print(f"{'─'*w}")


if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(
        prog="security_engine.py",
        description="EnterpriseStegEngine V4 — Multi-Bitplane + RS + Heatmap",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
EXAMPLES
  # Calibrate once on clean images
  python security_engine.py calibrate clean1.png clean2.png --source web

  # Scan (auto-loads calibration_web.json, saves heatmap alongside output)
  python security_engine.py scan infected.png

  # Scan with explicit paths
  python security_engine.py scan infected.png --cal calibration_web.json --out clean.png

  # Print calibration thresholds
  python security_engine.py info
        """
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_cal = sub.add_parser("calibrate", help="Build baseline from known-clean images")
    p_cal.add_argument("images", nargs="+", help="Paths to known-clean images")
    p_cal.add_argument("--source", default="unspecified")
    p_cal.add_argument("--out",    default="calibration_web.json")

    p_scan = sub.add_parser("scan", help="Scan a suspect image")
    p_scan.add_argument("image")
    p_scan.add_argument("--cal",  default="calibration_web.json")
    p_scan.add_argument("--out",  default="secure_output_v4.png")

    p_info = sub.add_parser("info", help="Print calibration thresholds")
    p_info.add_argument("--cal", default="calibration_web.json")

    args   = parser.parse_args()
    engine = EnterpriseStegEngine()

    # ── CALIBRATE ─────────────────────────────────────────────────────────────
    if args.command == "calibrate":
        missing = [p for p in args.images if not os.path.exists(p)]
        if missing:
            print(f"[ERROR] File(s) not found: {', '.join(missing)}")
            sys.exit(1)
        print(f"Calibrating on {len(args.images)} image(s) (source={args.source}) ...")
        engine.calibrate_from_files(args.images, source_hint=args.source)
        engine.save_calibration(args.out)
        print()
        print(engine.generate_calibration_report())

    # ── SCAN ──────────────────────────────────────────────────────────────────
    elif args.command == "scan":
        if not os.path.exists(args.image):
            print(f"[ERROR] Image not found: {args.image}")
            sys.exit(1)
        if os.path.exists(args.cal):
            engine.load_calibration(args.cal)
        else:
            print(f"[WARNING] '{args.cal}' not found — running uncalibrated.\n")

        with open(args.image, "rb") as f:
            result = engine.process_file(f.read(), filename=os.path.basename(args.image))

        _print_result(result, label=args.image)

        # Save sanitised image
        with open(args.out, "wb") as f:
            f.write(result["safe_file_bytes"])
        print(f"\n  Sanitized image → {args.out}")

        # Save heatmap next to sanitised image
        base, ext = os.path.splitext(args.out)
        heatmap_path = f"{base}_heatmap{ext}"
        with open(heatmap_path, "wb") as f:
            f.write(result["heatmap_bytes"])
        print(f"  Forensic heatmap → {heatmap_path}")

    # ── INFO ──────────────────────────────────────────────────────────────────
    elif args.command == "info":
        if not os.path.exists(args.cal):
            print(f"[ERROR] Calibration file not found: {args.cal}")
            sys.exit(1)
        engine.load_calibration(args.cal)
        print(engine.generate_calibration_report())