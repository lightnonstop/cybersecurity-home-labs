#!/bin/bash
# volatility-batch.sh
# Runs standard Volatility 3 triage plugins against any memory dump
# Usage: ./volatility-batch.sh <memory_dump> <output_directory>
# Example: ./volatility-batch.sh memdump.raw ./output

DUMP=$1
OUTDIR=$2
VOL="python3 $HOME/volatility3/vol.py"

mkdir -p "$OUTDIR"

echo "[*] All plugins complete. Output saved to $OUTDIR/"

echo "[*] Running windows.info..."
$VOL -f "$DUMP" windows.info | tee "$OUTDIR/info.txt"

echo "[*] Running windows.pslist..."
$VOL -f "$DUMP" windows.pslist | tee "$OUTDIR/pslist.txt"

echo "[*] Running windows.pstree..."
$VOL -f "$DUMP" windows.pstree | tee "$OUTDIR/pstree.txt"

echo "[*] Running windows.netscan..."
$VOL -f "$DUMP" windows.netscan | tee "$OUTDIR/netscan.txt"

echo "[*] Running windows.cmdline..."
$VOL -f "$DUMP" windows.cmdline | tee "$OUTDIR/cmdline.txt"

echo "[*] Running windows.dlllist..."
$VOL -f "$DUMP" windows.dlllist | tee "$OUTDIR/dlllist.txt"

echo "[*] Running windows.filescan..."
$VOL -f "$DUMP" windows.filescan | tee "$OUTDIR/filescan.txt"

echo "[*] Running windows.malfind..."
$VOL -f "$DUMP" windows.malware.malfind | tee "$OUTDIR/malfind.txt"

echo "[+] All plugins complete. Output saved to $OUTDIR/"