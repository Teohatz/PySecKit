import hashlib
import itertools
import os
import time
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

SUPPORTED_ALGORITHMS = {
    "md5":      hashlib.md5,
    "sha1":     hashlib.sha1,
    "sha224":   hashlib.sha224,
    "sha256":   hashlib.sha256,
    "sha384":   hashlib.sha384,
    "sha512":   hashlib.sha512,
    "blake2b":  hashlib.blake2b,
    "blake2s":  hashlib.blake2s,
    "sha3_224": hashlib.sha3_224,
    "sha3_256": hashlib.sha3_256,
    "sha3_384": hashlib.sha3_384,
    "sha3_512": hashlib.sha3_512,
}


def _hash_word(word: str, hash_func, target: str) -> str | None:
    try:
        if hash_func(word.encode()).hexdigest() == target:
            return word
    except UnicodeEncodeError:
        pass
    return None


def _save_result(output_path: str, result: dict):
    ext = os.path.splitext(output_path)[1].lower()
    with open(output_path, "w", encoding="utf-8") as f:
        if ext == ".json":
            json.dump(result, f, indent=2)
        else:
            for k, v in result.items():
                f.write(f"{k}: {v}\n")
    logger.info("Result saved to %s", output_path)


def crack_with_wordlist(
    hash_to_crack: str,
    algorithm: str,
    wordlist_path: str,
    threads: int = 4,
    output_path: str = None,
) -> str | None:
    hash_func = SUPPORTED_ALGORITHMS.get(algorithm.lower())
    if not hash_func:
        logger.error(
            "Unsupported algorithm '%s'. Available: %s",
            algorithm,
            ", ".join(SUPPORTED_ALGORITHMS),
        )
        return None

    if not os.path.isfile(wordlist_path):
        logger.error("Wordlist not found: %s", wordlist_path)
        return None

    logger.info("Starting wordlist attack | algorithm=%s | file=%s | threads=%d",
                algorithm.upper(), wordlist_path, threads)

    start = time.time()
    result = None
    found = [False]   # mutable so inner function can signal

    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                batch = {}
                for line in f:
                    if found[0]:
                        break
                    word = line.strip()
                    future = executor.submit(_hash_word, word, hash_func, hash_to_crack)
                    batch[future] = word

                    if len(batch) >= 2000:
                        for done in as_completed(batch):
                            res = done.result()
                            if res:
                                found[0] = True
                                result = res
                                break
                        batch = {}

                if not found[0] and batch:
                    for done in as_completed(batch):
                        res = done.result()
                        if res:
                            result = res
                            break

    except KeyboardInterrupt:
        logger.warning("Interrupted by user.")
        return None

    elapsed = time.time() - start

    if result:
        logger.info("Hash cracked in %.2fs | plaintext=%s", elapsed, result)
        print(f"\n  [+] Hash cracked in {elapsed:.2f}s")
        print(f"  [+] Plaintext : {result}")
        if output_path:
            _save_result(output_path, {
                "hash": hash_to_crack,
                "algorithm": algorithm,
                "plaintext": result,
                "elapsed_seconds": round(elapsed, 2),
            })
        return result

    logger.info("No match found in wordlist after %.2fs.", elapsed)
    print(f"\n  [-] No match found in wordlist. ({elapsed:.2f}s)")
    return None


def crack_with_brute(
    hash_to_crack: str,
    algorithm: str,
    charset: str,
    min_len: int,
    max_len: int,
    output_path: str = None,
) -> str | None:
    hash_func = SUPPORTED_ALGORITHMS.get(algorithm.lower())
    if not hash_func:
        logger.error(
            "Unsupported algorithm '%s'. Available: %s",
            algorithm,
            ", ".join(SUPPORTED_ALGORITHMS),
        )
        return None

    logger.info(
        "Starting brute-force attack | algorithm=%s | charset_len=%d | lengths=%d-%d",
        algorithm.upper(), len(charset), min_len, max_len,
    )

    start = time.time()

    try:
        for length in range(min_len, max_len + 1):
            total = len(charset) ** length
            logger.debug("Trying length %d (%d combinations)", length, total)
            print(f"  [*] Trying length {length} ({total:,} combinations)...")
            for combo in itertools.product(charset, repeat=length):
                word = "".join(combo)
                if _hash_word(word, hash_func, hash_to_crack):
                    elapsed = time.time() - start
                    logger.info("Hash cracked in %.2fs | plaintext=%s", elapsed, word)
                    print(f"\n  [+] Hash cracked in {elapsed:.2f}s")
                    print(f"  [+] Plaintext : {word}")
                    if output_path:
                        _save_result(output_path, {
                            "hash": hash_to_crack,
                            "algorithm": algorithm,
                            "plaintext": word,
                            "elapsed_seconds": round(elapsed, 2),
                        })
                    return word
    except KeyboardInterrupt:
        logger.warning("Interrupted by user.")
        return None

    elapsed = time.time() - start
    logger.info("Brute-force exhausted after %.2fs.", elapsed)
    print(f"\n  [-] No match found. ({elapsed:.2f}s)")
    return None


def run_hash_cracker(args):
    print(f"\n  Target hash : {args.hash}")
    print(f"  Algorithm   : {args.algo.upper()}")

    if args.wordlist:
        print(f"  Mode        : Wordlist ({args.wordlist})")
        print(f"  Threads     : {args.threads}\n")
        crack_with_wordlist(
            args.hash,
            args.algo,
            args.wordlist,
            threads=args.threads,
            output_path=getattr(args, "output", None),
        )
    else:
        print(f"  Mode        : Brute-force")
        print(f"  Charset     : {args.charset}")
        print(f"  Length      : {args.min_len}-{args.max_len}\n")
        crack_with_brute(
            args.hash,
            args.algo,
            args.charset,
            args.min_len,
            args.max_len,
            output_path=getattr(args, "output", None),
        )
