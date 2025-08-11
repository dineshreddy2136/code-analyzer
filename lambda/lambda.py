# lambda_function.py
# Python 3.11
import os
import io
import csv
import json
import gzip
import time
import hashlib
import logging
import traceback
from datetime import datetime, timezone
from typing import Dict, Any, Iterable, List, Tuple, Optional

import boto3
from botocore.exceptions import ClientError

# ------------- Config via env vars -------------
OUTPUT_BUCKET = os.getenv("OUTPUT_BUCKET", "")                       # required
OUTPUT_PREFIX = os.getenv("OUTPUT_PREFIX", "transformed/")           # s3 prefix
DLQ_URL = os.getenv("DLQ_URL", "")                                   # optional SQS URL
TRANSFORM_SPEC_SSM_PARAM = os.getenv("TRANSFORM_SPEC_SSM_PARAM", "") # optional SSM param
ENRICH_DDB_TABLE = os.getenv("ENRICH_DDB_TABLE", "")                 # optional DynamoDB table
DEDUPE_PK = os.getenv("DEDUPE_PK", "")                               # optional primary key name for dedupe
MASK_FIELDS = set((os.getenv("MASK_FIELDS") or "").split(",")) if os.getenv("MASK_FIELDS") else set()
MAX_OUTPUT_BYTES = int(os.getenv("MAX_OUTPUT_BYTES", "50_000_000"))  # 50MB per gzip shard
BATCH_WRITE = int(os.getenv("BATCH_WRITE", "5000"))                  # records per shard flush
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
PARTITION_BY = os.getenv("PARTITION_BY", "ingest_date")              # 'ingest_date' or a record field
IDEMPOTENCY = os.getenv("IDEMPOTENCY", "true").lower() == "true"

logging.basicConfig(level=getattr(logging, LOG_LEVEL.upper(), logging.INFO))
log = logging.getLogger(__name__)

s3 = boto3.client("s3")
ssm = boto3.client("ssm")
sqs = boto3.client("sqs") if DLQ_URL else None
ddb = boto3.resource("dynamodb").Table(ENRICH_DDB_TABLE) if ENRICH_DDB_TABLE else None

# ------------- Helpers -------------

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def snake_case(s: str) -> str:
    out = []
    prev_lower = False
    for ch in s:
        if ch.isupper() and prev_lower:
            out.append("_")
        out.append(ch.lower())
        prev_lower = ch.islower()
    return "".join(out).replace(" ", "_")

def mask_value(v: Any) -> str:
    """Hash-based masking (stable but non-reversible)"""
    raw = json.dumps(v, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()

def coerce_type(value: Any, target: str) -> Any:
    if value is None or value == "":
        return None
    try:
        if target == "int": return int(value)
        if target == "float": return float(value)
        if target == "bool":
            if isinstance(value, bool): return value
            return str(value).strip().lower() in {"1","true","t","yes","y"}
        if target == "str": return str(value)
        if target == "iso8601":
            # allow unix seconds too
            if isinstance(value, (int, float)): 
                return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
            return datetime.fromisoformat(str(value)).astimezone(timezone.utc).isoformat()
    except Exception:
        return None
    return value

def load_transform_spec() -> Dict[str, Any]:
    """
    Optional transform spec from SSM Parameter Store (SecureString or String).
    Expected structure (example):
    {
      "rename": {"UserID":"user_id","Full Name":"full_name"},
      "coerce": {"user_id":"int","price":"float","created_at":"iso8601"},
      "drop": ["debug","unused_field"],
      "derive": {
        "full_name_upper": "record.get('full_name','').upper()",
        "order_total": "(record.get('price') or 0) * (record.get('qty') or 1)"
      },
      "required": ["user_id","email"],
      "enrich_key": "user_id"  # used if ENRICH_DDB_TABLE is set
    }
    """
    if not TRANSFORM_SPEC_SSM_PARAM:
        return {}
    try:
        resp = ssm.get_parameter(Name=TRANSFORM_SPEC_SSM_PARAM, WithDecryption=True)
        spec = json.loads(resp["Parameter"]["Value"])
        return spec if isinstance(spec, dict) else {}
    except Exception as e:
        log.warning("Could not load transform spec from SSM: %s", e)
        return {}

def partition_value(record: Dict[str, Any], event_time: str) -> str:
    if PARTITION_BY == "ingest_date":
        return event_time[:10]  # YYYY-MM-DD
    return str(record.get(PARTITION_BY, "unknown"))

def iter_s3_object_lines(bucket: str, key: str) -> Iterable[str]:
    obj = s3.get_object(Bucket=bucket, Key=key)
    body = obj["Body"]
    for chunk in body.iter_lines():
        if chunk:
            yield chunk.decode("utf-8", errors="replace")

def detect_format(key: str, first_line: Optional[str]) -> str:
    if key.lower().endswith(".csv"): return "csv"
    if key.lower().endswith(".json") or key.lower().endswith(".ndjson"): return "jsonl"
    # fallback by sniffing
    if first_line and first_line.strip().startswith("{"):
        return "jsonl"
    return "csv"

def parse_csv(lines: Iterable[str]) -> Iterable[Dict[str, Any]]:
    it = iter(lines)
    try:
        header_line = next(it)
    except StopIteration:
        return
    reader = csv.DictReader([header_line, *list(it)])
    for row in reader:
        yield {k: (v if v != "" else None) for k, v in row.items()}

def parse_jsonl(lines: Iterable[str]) -> Iterable[Dict[str, Any]]:
    for line in lines:
        try:
            yield json.loads(line)
        except Exception:
            continue

def normalize_keys(rec: Dict[str, Any]) -> Dict[str, Any]:
    return {snake_case(k): v for k, v in rec.items()}

def apply_spec_transforms(rec: Dict[str, Any], spec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not spec:
        return rec
    # rename
    for src, dst in spec.get("rename", {}).items():
        if src in rec:
            rec[dst] = rec.pop(src)
    # drop
    for f in spec.get("drop", []):
        rec.pop(f, None)
    # coerce
    for f, t in spec.get("coerce", {}).items():
        if f in rec:
            rec[f] = coerce_type(rec[f], t)
    # derive (safe eval with limited globals)
    for f, expr in spec.get("derive", {}).items():
        try:
            rec[f] = eval(expr, {"__builtins__": {}}, {"record": rec})
        except Exception:
            rec[f] = None
    # required
    for f in spec.get("required", []):
        if f not in rec or rec[f] in (None, "", []):
            return None
    return rec

def mask_fields(rec: Dict[str, Any]) -> Dict[str, Any]:
    if not MASK_FIELDS:
        return rec
    for f in MASK_FIELDS:
        if f in rec and rec[f] is not None:
            rec[f] = mask_value(rec[f])
    return rec

def enrich_record(rec: Dict[str, Any], spec: Dict[str, Any]) -> Dict[str, Any]:
    if not ddb:
        return rec
    key_field = spec.get("enrich_key") if spec else None
    key_field = key_field or next(iter(rec.keys()), None)
    if not key_field or rec.get(key_field) in (None, ""):
        return rec
    try:
        resp = ddb.get_item(Key={key_field: rec[key_field]})
        if "Item" in resp:
            # merge with prefix "enrich_" to avoid collisions
            for k, v in resp["Item"].items():
                rec[f"enrich_{k}"] = v
    except Exception as e:
        log.debug("DDB enrich failed: %s", e)
    return rec

def put_s3_gzip_lines(bucket: str, key: str, lines: Iterable[str]) -> None:
    bio = io.BytesIO()
    with gzip.GzipFile(fileobj=bio, mode="wb") as gz:
        for line in lines:
            gz.write((line + "\n").encode("utf-8"))
    bio.seek(0)
    s3.put_object(Bucket=bucket, Key=key, Body=bio, ContentType="application/x-ndjson", ContentEncoding="gzip")

def object_exists(bucket: str, key: str) -> bool:
    try:
        s3.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] in ("404", "NotFound"):
            return False
        raise

def send_dlq(message: Dict[str, Any]):
    if not sqs:
        return
    try:
        sqs.send_message(QueueUrl=DLQ_URL, MessageBody=json.dumps(message))
    except Exception as e:
        log.error("DLQ send failed: %s", e)

def shard_writer(base_prefix: str, event_time: str) -> Tuple:
    """
    Returns a small writer that accumulates NDJSON, chunks by size/records, and writes to S3.
    """
    shard_idx = 0
    buf: List[str] = []
    byte_count = 0

    def flush():
        nonlocal shard_idx, buf, byte_count
        if not buf:
            return None
        shard_key = f"{base_prefix}/part-{shard_idx:05d}.ndjson.gz"
        put_s3_gzip_lines(OUTPUT_BUCKET, shard_key, buf)
        log.info("Wrote %s records to s3://%s/%s (%d shards)", len(buf), OUTPUT_BUCKET, shard_key, shard_idx + 1)
        shard_idx += 1
        buf = []
        byte_count = 0

    def write(rec: Dict[str, Any]):
        nonlocal byte_count
        line = json.dumps(rec, ensure_ascii=False)
        buf.append(line)
        byte_count += len(line)
        if byte_count >= MAX_OUTPUT_BYTES or len(buf) >= BATCH_WRITE:
            flush()

    def close():
        flush()
        return shard_idx

    return write, close

# ------------- Handler -------------

def handler(event, context):
    """
    S3 ObjectCreated event → transform → S3 (gzip ndjson)
    """
    t0 = time.time()
    # Extract S3 info (supports single-record events)
    try:
        rec = event["Records"][0]
        s3e = rec["s3"]
        bucket = s3e["bucket"]["name"]
        key = s3e["object"]["key"]
        event_time = rec.get("eventTime") or _utc_now_iso()
    except Exception:
        # Also allow manual invocation with {"bucket": "...", "key": "..."}
        bucket = event.get("bucket")
        key = event.get("key")
        event_time = _utc_now_iso()
    if not bucket or not key:
        raise ValueError("Missing S3 bucket/key in event")

    log.info("Processing s3://%s/%s", bucket, key)
    # Idempotency: compute output base prefix and skip if already present (first shard)
    spec = load_transform_spec()

    # Decide partition (YYYY-MM-DD or by field later)
    # For field partitioning we’ll compute per-record, so here put a base prefix
    base_out = f"{OUTPUT_PREFIX.rstrip('/')}/source={bucket}/object={hashlib.md5(key.encode()).hexdigest()}"
    # optional: mark overall manifest
    manifest_key = f"{base_out}/_SUCCESS.json"

    if IDEMPOTENCY and object_exists(OUTPUT_BUCKET, manifest_key):
        log.info("Output already exists for this object (manifest found). Skipping.")
        return {"status": "skipped", "output_prefix": f"s3://{OUTPUT_BUCKET}/{base_out}"}

    # Stream the input
    line_iter = iter_s3_object_lines(bucket, key)
    first = None
    try:
        first = next(line_iter)
    except StopIteration:
        log.warning("Empty object.")
        # still create empty manifest
        s3.put_object(Bucket=OUTPUT_BUCKET, Key=manifest_key, Body=json.dumps({"empty": True}))
        return {"status": "empty", "output_prefix": f"s3://{OUTPUT_BUCKET}/{base_out}"}
    # Rebuild iterator with first line included
    lines = iter([first, *list(line_iter)])
    fmt = detect_format(key, first)

    # Choose parser
    if fmt == "csv":
        records = parse_csv(lines)
    else:
        records = parse_jsonl(lines)

    # Write shards; if PARTITION_BY != 'ingest_date', shard per value (small fanout)
    total_in = 0
    total_out = 0
    total_err = 0
    writers: Dict[str, Tuple] = {}  # partition_value -> (write, close)

    def get_writer(pval: str):
        if pval not in writers:
            # final prefix: .../pkey=val/ingest_date=YYYY-MM-DD
            ingest = event_time[:10]
            safe_val = str(pval).replace("/", "_") if pval else "unknown"
            final_prefix = f"{base_out}/{PARTITION_BY}={safe_val}/ingest_date={ingest}"
            writers[pval] = shard_writer(final_prefix, event_time)
        return writers[pval]

    seen_keys = set()

    try:
        for rec in records:
            total_in += 1
            try:
                rec = normalize_keys(rec)
                rec = apply_spec_transforms(rec, spec)
                if rec is None:
                    continue
                # dedupe (optional)
                if DEDUPE_PK and rec.get(DEDUPE_PK) is not None:
                    keyval = rec[DEDUPE_PK]
                    if keyval in seen_keys:
                        continue
                    seen_keys.add(keyval)
                rec = mask_fields(rec)
                rec = enrich_record(rec, spec)
                rec["_ingest_time"] = event_time
                # choose partition
                pval = partition_value(rec, event_time)
                writer, closer = get_writer(pval)
                writer(rec)
                total_out += 1
            except Exception as e:
                total_err += 1
                if DLQ_URL:
                    send_dlq({"bucket": bucket, "key": key, "line_record": rec, "error": str(e)})
                else:
                    log.debug("Record failed: %s", e)
                continue
    except Exception as e:
        # Fatal stream error → DLQ object reference
        log.error("Fatal error processing object: %s", e)
        if DLQ_URL:
            send_dlq({"bucket": bucket, "key": key, "fatal": True, "error": str(e), "trace": traceback.format_exc()})
        raise
    finally:
        # Close all writers
        shards = 0
        for pval, (writer, closer) in writers.items():
            shards += closer() or 0

        # Write manifest for idempotency & auditing
        manifest = {
            "source_bucket": bucket,
            "source_key": key,
            "output_prefix": f"s3://{OUTPUT_BUCKET}/{base_out}",
            "records_in": total_in,
            "records_out": total_out,
            "errors": total_err,
            "partitions": list(writers.keys()),
            "shards": shards,
            "completed_at": _utc_now_iso(),
            "transform_spec": bool(spec),
            "format": "ndjson.gz"
        }
        s3.put_object(Bucket=OUTPUT_BUCKET, Key=manifest_key, Body=json.dumps(manifest, ensure_ascii=False))

    dur_ms = int((time.time() - t0) * 1000)
    log.info("DONE in %d ms: in=%d out=%d err=%d → s3://%s/%s",
             dur_ms, total_in, total_out, total_err, OUTPUT_BUCKET, base_out)
    return {"status": "ok", "duration_ms": dur_ms, "manifest": f"s3://{OUTPUT_BUCKET}/{manifest_key}"}

# For local testing:
if __name__ == "__main__":
    # Run with: python lambda_function.py
    # Provide a local event for manual test (adjust values)
    test_event = {"bucket": "my-input-bucket", "key": "incoming/sample.json"}
    print(handler(test_event, None))
