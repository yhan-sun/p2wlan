"""Bounded original-image storage; copies bytes without executing programs."""
import hashlib
import json
import os
import stat

MAX_IMAGE_BYTES = 1024 * 1024 * 1024
ROLES = ("daemon", "control", "relay")
STORE_NAME = "linux-tun-original-images"


def prepare(args, manifest):
    store = getattr(args, "image_store", None)
    if store is None:
        return None
    if store.name != STORE_NAME or store.parent.resolve() != args.output.parent.resolve():
        raise ValueError("image store must be the fixed sibling archive directory")
    if store.is_symlink():
        raise ValueError("image store cannot be a symlink")
    owner = {k: manifest[k] for k in ("actual_checkout", "run_id", "run_attempt")}
    if not all(isinstance(owner[k], str) and owner[k].isdigit() and int(owner[k]) > 0
               for k in ("run_id", "run_attempt")):
        raise ValueError("shared image store requires the original run identity")
    if not store.exists():
        # Non-secret program images are retained by sudo, then uploaded by
        # the ordinary CI runner. Keep read/traverse access for that reader.
        store.mkdir(mode=0o755)
        with (store / "owner.json").open("x") as stream:
            json.dump(owner, stream)
    if not store.is_dir() or (store / "owner.json").is_symlink():
        raise ValueError("invalid original image store")
    if (store / "owner.json").stat().st_size > 1024:
        raise ValueError("image store owner exceeds capacity")
    if json.loads((store / "owner.json").read_text()) != owner:
        raise ValueError("image store checkout or run mismatch")
    if set(p.name for p in store.iterdir()) - {"owner.json", *("p2wlan-" + r for r in ROLES)}:
        raise ValueError("image store contains unexpected entries")
    store.chmod(0o755)
    (store / "owner.json").chmod(0o444)
    manifest.update(schema_version=2, image_store=STORE_NAME)
    return store


def identity(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
            value.st_ctime_ns, value.st_mode)


def read_image(source, saved=None):
    path_before = source.stat(follow_symlinks=False)
    if not stat.S_ISREG(path_before.st_mode):
        raise ValueError("original image path is not regular")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(source, flags), "rb") as original:
        before = os.fstat(original.fileno())
        if ((path_before.st_dev, path_before.st_ino, path_before.st_size, path_before.st_mtime_ns)
                != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)):
            raise ValueError("original image path changed before retention")
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_IMAGE_BYTES:
            raise ValueError("original image exceeds capacity or is not regular")
        copied, value = 0, hashlib.sha256()
        for block in iter(lambda: original.read(1024 * 1024), b""):
            copied += len(block)
            if copied > before.st_size:
                raise ValueError("original image changed during retention")
            value.update(block)
            if saved is not None:
                saved.write(block)
        after = os.fstat(original.fileno())
    if copied != before.st_size or identity(before) != identity(after):
        raise ValueError("original image changed during retention")
    # Windows path stat may expose birth time as ctime while fstat exposes
    # change time (CPython #157671). Compare each through the same API, keeping
    # descriptor change-time checks and path replacement checks separately.
    if identity(source.stat(follow_symlinks=False)) != identity(path_before):
        raise ValueError("original image path changed during retention")
    return copied, value.hexdigest()


def retain(source, target, expected, row, shared):
    if target.is_symlink():
        raise ValueError("retained image cannot be a symlink")
    reused = target.exists()
    if reused:
        if not shared:
            raise FileExistsError(target.name)
        if not stat.S_ISREG(target.stat(follow_symlinks=False).st_mode):
            raise ValueError("retained image is not regular")
        copied, actual = read_image(source)
        if read_image(target) != (copied, actual) or actual not in expected:
            raise ValueError("retained original image conflicts with current report")
    else:
        with target.open("xb") as saved:
            row["unverified_file"] = target.name
            copied, actual = read_image(source, saved)
            saved.flush()
            os.fsync(saved.fileno())
        target.chmod(0o444)
        if actual not in expected or read_image(target) != (copied, actual):
            raise ValueError("retained original image digest mismatch")
        del row["unverified_file"]
    row.update(available=True, file=target.name, bytes=copied, sha256=actual,
               matched_original_report_digest=True)
    if shared:
        row.update(archive_member=STORE_NAME + "/" + target.name, shared_image_reused=reused)
