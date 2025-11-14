#!/usr/bin/env python3
import argparse, os, json, time, subprocess
from pathlib import Path
from utils.artifact import write_artifact

DEFAULT_WORDLIST = 'wordlists/backup_files.txt'

def run_ffuf(target, wordlist, outdir, threads=10, rate=1):
    Path(outdir).mkdir(parents=True, exist_ok=True)
    output_file = os.path.join(outdir, f'ffuf_{int(time.time())}.json')
    cmd = ['ffuf','-u', f'{target}/FUZZ', '-w', wordlist, '-of','json','-o', output_file, '-t', str(threads), '-p', str(rate)]
    print('Running:', ' '.join(cmd))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        meta = {'cmd': ' '.join(cmd), 'returncode': p.returncode, 'stdout': p.stdout[:2000], 'stderr': p.stderr[:2000]}
        write_artifact(output_file, text=(open(output_file).read() if os.path.exists(output_file) else p.stdout), meta=meta)
        return output_file, meta
    except FileNotFoundError:
        # ffuf not installed fallback: try common paths
        results = []
        commons = ['.git/index','.env','backup.tar.gz','backup.zip','wp-config.php.bak','database.sql.gz']
        for c in commons:
            url = f'{target.rstrip("/")}/{c}'
            results.append({'path': c, 'url': url, 'status': 'skipped-ffuf'})
        out = os.path.join(outdir, 'ffuf_fallback.json')
        write_artifact(out, text=json.dumps(results, indent=2), meta={'cmd':'fallback','note':'ffuf missing'})
        return out, {'cmd':'fallback'}

def run(target, wordlist, output):
    outdir = output
    Path(outdir).mkdir(parents=True, exist_ok=True)
    wf = wordlist or DEFAULT_WORDLIST
    outpath, meta = run_ffuf(target.rstrip('/'), wf, outdir)
    print('Wrote', outpath)
    return outpath

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--target', required=True)
    ap.add_argument('--wordlist', default=None)
    ap.add_argument('--output', required=True)
    args = ap.parse_args()
    run(args.target, args.wordlist, args.output)
