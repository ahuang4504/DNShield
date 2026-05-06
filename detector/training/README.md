Follow these steps:

1. Prepare the train/test split and root zone

```bash
uv run python scripts/split_benign_domains.py
uv run python scripts/generate_benign_root_zone.py
```

2. Build containers

```bash
docker compose build detector client resolver authoritative
```

3. Start the detector, resolver, and authority with detector disabled

```bash
DETECTOR_ENABLED=0 docker compose up -d detector resolver authoritative
```

4. Start passive feature collection inside detector

```bash
docker compose exec detector \
  uv run dnshield-collect-training-features \
    --domains /app/detector/training/data/tranco_top4k_train.txt \
    --output /app/detector/training/data/normal_features.parquet
```

5. In another terminal, generate benign training traffic

```bash
docker compose run --rm --no-deps \
  -e CLIENT_EXIT_AFTER_RUN=1 \
  -e CLIENT_DOMAIN_CORPUS_PATH=/app/detector/training/data/tranco_top4k_train.txt \
  -e CLIENT_QUERY_COUNT=4000 \
  -e CLIENT_QUERIES_PER_SECOND=50 \
  client
```

6. Run the same client command 2 times (2 passes)

```bash
docker compose run --rm --no-deps \
  -e CLIENT_EXIT_AFTER_RUN=1 \
  -e CLIENT_DOMAIN_CORPUS_PATH=/app/detector/training/data/tranco_top4k_train.txt \
  -e CLIENT_QUERY_COUNT=4000 \
  -e CLIENT_QUERIES_PER_SECOND=50 \
  client
```

7. Stop the collector with `Ctrl+C` in terminal

8. Copy the parquet file out of the detector container

```bash
docker cp dnshield-detector:/app/detector/training/data/normal_features.parquet \
  detector/training/data/normal_features.parquet
```

9. Train the model

```bash
uv run --group training python detector/training/train_model.py \
  --input detector/training/data/normal_features.parquet \
  --output detector/training/data/iforest.joblib
```

10. Shut down when done

```bash
docker compose down --remove-orphans
```
