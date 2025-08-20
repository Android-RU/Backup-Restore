#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
backup-restore.py — бэкап и восстановление APK/данных Android-приложений через ADB.
Автор: вы :)
Лицензия: MIT (при желании поменяйте перед публикацией на GitHub)

Основные возможности (см. --help):
- backup:      Бэкап APK, данных (/data/data/<pkg>), медиа (/sdcard/Android/data/<pkg>)
- restore:     Восстановление из каталога бэкапа (APK / данные / медиа)
- verify:      Проверка целостности файлов бэкапа по SHA-256
- prune:       Чистка старых бэкапов, оставляя N свежих
- list-backups Перечень доступных бэкапов
- list-devices Список подключённых устройств ADB
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import io
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

# --------------------------- Константы и настройки ---------------------------

DEFAULT_BACKUP_ROOT = Path("backups")
LOG_FORMAT_CONSOLE = "[%(levelname)s] %(message)s"
LOG_FORMAT_FILE = "%(asctime)s %(levelname)s %(message)s"

EXIT_OK = 0
EXIT_ARGS = 1
EXIT_ADB = 2
EXIT_PACKAGE = 3
EXIT_PERMS = 4
EXIT_VERIFY = 5
EXIT_MISC = 6

# Маски исключения данных (можно расширить по желанию)
DEFAULT_EXCLUDES = [
    "./cache",
    "./code_cache",
    "./no_backup",
    "./files/.__override__",  # пример
]

# --------------------------- Утилиты ----------------------------------------


class DryRunContext:
    """Контекст «сухого запуска»: если включён, команды не выполняются, а только логируются."""

    def __init__(self, enabled: bool):
        self.enabled = enabled

    def run(self, fn, *args, **kwargs):
        if self.enabled:
            logging.info("[dry-run] %s(%s %s)", getattr(fn, "__name__", str(fn)), args, kwargs)
            return None
        return fn(*args, **kwargs)


def which_adb() -> str:
    """Проверяем доступность adb и возвращаем путь к бинарю."""
    try:
        out = subprocess.run(["adb", "version"], capture_output=True, text=True, check=True)
        logging.debug("ADB version: %s", out.stdout.strip().splitlines()[0] if out.stdout else "unknown")
        return "adb"
    except (OSError, subprocess.CalledProcessError) as e:
        logging.error("ADB не найден или не запускается: %s", e)
        sys.exit(EXIT_ADB)


def adb_base(serial: Optional[str] = None) -> List[str]:
    """Базовая часть команды adb с учётом -s <serial>."""
    cmd = [which_adb()]
    if serial:
        cmd += [" -s ", serial] if os.name == "nt" else ["-s", serial]
    return cmd


def run(cmd: List[str], *, check=True, text=True, input_data: Optional[bytes] = None) -> subprocess.CompletedProcess:
    """
    Безопасный запуск внешней команды.
    cmd — список аргументов (без shell=True).
    """
    logging.debug("RUN: %s", " ".join(cmd))
    try:
        return subprocess.run(cmd, check=check, capture_output=True, text=text, input=input_data)
    except subprocess.CalledProcessError as e:
        logging.error("Команда завершилась ошибкой (%s): %s", e.returncode, " ".join(cmd))
        if e.stdout:
            logging.error("STDOUT:\n%s", e.stdout if text else "<binary>")
        if e.stderr:
            logging.error("STDERR:\n%s", e.stderr if text else "<binary>")
        raise
    except FileNotFoundError:
        logging.error("Команда не найдена: %s", cmd[0])
        raise


def adb(cmd_args: List[str], serial: Optional[str] = None, check=True, text=True) -> subprocess.CompletedProcess:
    """Выполнить `adb <args>` и вернуть CompletedProcess."""
    cmd = adb_base(serial) + cmd_args
    return run(cmd, check=check, text=text)


def adb_shell(sh_cmd: str, serial: Optional[str] = None, check=True, text=True) -> subprocess.CompletedProcess:
    """
    Запуск команды на устройстве: adb shell "sh -c '<sh_cmd>'"
    Используем sh -c, чтобы корректно проходили пайпы/кавычки.
    """
    # На Windows безопаснее не использовать один аргумент с пробелами в конце
    cmd = adb_base(serial) + ["shell", "sh", "-c", sh_cmd]
    return run(cmd, check=check, text=text)


def adb_exec_out(sh_cmd: str, serial: Optional[str] = None) -> subprocess.Popen:
    """
    Запуск `adb exec-out sh -c '<sh_cmd>'` и возврат Popen для чтения stdout потоком (binary).
    Используется для потоковой передачи tar-архива с устройства.
    """
    cmd = adb_base(serial) + ["exec-out", "sh", "-c", sh_cmd]
    logging.debug("EXEC-OUT: %s", " ".join(cmd))
    # В binary-режиме text=False и без capture_output, чтобы читать поток по кускам
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False)


def now_ts() -> str:
    """Метка времени для каталога бэкапа."""
    return dt.datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")


def write_json(path: Path, data: Dict):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """SHA-256 файла (потоково)."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def write_hashes(backup_dir: Path, filenames: Iterable[str]) -> Path:
    """Создать файл hashes.sha256 с контрольными суммами указанных файлов (если существуют)."""
    lines = []
    for name in filenames:
        p = backup_dir / name
        if p.exists():
            digest = sha256_file(p)
            lines.append(f"SHA256  {name}  {digest}")
    out = backup_dir / "hashes.sha256"
    out.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return out


def verify_hashes(backup_dir: Path) -> Tuple[bool, List[str]]:
    """
    Проверить hashes.sha256. Возвращает (ok, errors).
    Формат строки: 'SHA256  <filename>  <digest>'
    """
    errors: List[str] = []
    f = backup_dir / "hashes.sha256"
    if not f.exists():
        return False, ["Отсутствует файл hashes.sha256"]

    for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), start=1):
        m = re.match(r"^SHA256\s+(?P<fname>.+?)\s+(?P<hash>[0-9a-fA-F]{64})$", line.strip())
        if not m:
            errors.append(f"Строка {i}: неверный формат")
            continue
        fname, expected = m.group("fname"), m.group("hash").lower()
        p = backup_dir / fname
        if not p.exists():
            errors.append(f"{fname}: файл отсутствует")
            continue
        actual = sha256_file(p)
        if actual != expected:
            errors.append(f"{fname}: несовпадение SHA-256 (expected {expected}, got {actual})")
    return len(errors) == 0, errors


# --------------------------- Метаданные пакета/устройства --------------------


def list_devices() -> List[Dict[str, str]]:
    """Список устройств `adb devices -l`."""
    out = adb(["devices", "-l"]).stdout
    devices: List[Dict[str, str]] = []
    for line in out.splitlines()[1:]:
        if not line.strip():
            continue
        if "device" in line and not any(x in line for x in ["offline", "unauthorized"]):
            parts = line.split()
            serial = parts[0]
            info = {"serial": serial, "raw": line.strip()}
            devices.append(info)
    return devices


def ensure_single_device(serial: Optional[str]) -> str:
    """Проверить, что подключено одно устройство, либо вернуть указанный serial."""
    if serial:
        return serial
    devs = list_devices()
    if not devs:
        logging.error("Не найдено ни одного устройства ADB.")
        sys.exit(EXIT_ADB)
    if len(devs) > 1:
        logging.error("Подключено несколько устройств. Укажите --serial из списка:")
        for d in devs:
            logging.error("  %s", d["raw"])
        sys.exit(EXIT_ADB)
    return devs[0]["serial"]


def package_paths(pkg: str, serial: str) -> List[str]:
    """Получить список путей APK (включая сплиты) через `pm path`."""
    # Некоторые прошивки требуют --user 0 для полного набора путей
    res = adb_shell(f"pm path --user 0 {sh_quote(pkg)} || pm path {sh_quote(pkg)}", serial=serial)
    paths = []
    for line in res.stdout.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            paths.append(line[len("package:"):])
    if not paths:
        logging.error("Пакет %s не найден (pm path пуст).", pkg)
        sys.exit(EXIT_PACKAGE)
    logging.debug("APK paths: %s", paths)
    return paths


def sh_quote(s: str) -> str:
    """Простейшее экранирование для вставки строки в sh -c '...' (одинарные кавычки)."""
    return "'" + s.replace("'", "'\\''") + "'"


def dumpsys_package(pkg: str, serial: str) -> str:
    """Сырой вывод dumpsys package <pkg>."""
    res = adb_shell(f"dumpsys package {sh_quote(pkg)}", serial=serial)
    return res.stdout


def get_package_meta(pkg: str, serial: str) -> Dict:
    """Парсим полезные поля из dumpsys package."""
    ds = dumpsys_package(pkg, serial)
    def grab(pattern: str, default: Optional[str] = None) -> Optional[str]:
        m = re.search(pattern, ds)
        return m.group(1) if m else default

    version_name = grab(r"versionName=(.+)")
    version_code = grab(r"versionCode=(\d+)")
    target_sdk = grab(r"targetSdk=(\d+)")
    requested_perms = re.findall(r"requested permissions:\s*((?:\s+[\w\.]+)+)", ds, re.MULTILINE)
    perms: List[str] = []
    if requested_perms:
        block = requested_perms[0]
        perms = [p.strip() for p in block.splitlines() if p.strip()]
    # userId/appId для chown при восстановлении
    user_id = grab(r"userId=(\d+)")
    app_id = grab(r"appId=(\d+)")
    # Метка приложения (label) достать сложно без aapt; попытаемся через resolves:
    label = grab(r"pkg=Package\{[^}]+ (.+?)\}")
    sdk_int = adb_shell("getprop ro.build.version.sdk", serial=serial).stdout.strip()

    return {
        "package": pkg,
        "label": label or pkg,
        "version_name": version_name,
        "version_code": int(version_code) if version_code and version_code.isdigit() else None,
        "target_sdk": int(target_sdk) if target_sdk and target_sdk.isdigit() else None,
        "sdk_int": int(sdk_int) if sdk_int.isdigit() else None,
        "requested_permissions": perms,
        "user_id": int(user_id) if user_id and user_id.isdigit() else None,
        "app_id": int(app_id) if app_id and app_id.isdigit() else None,
    }


def is_root(serial: str) -> bool:
    """Проверка наличия root через su -c id."""
    try:
        res = adb_shell("su -c id", serial=serial, check=True)
        return res.returncode == 0 and "uid=0" in res.stdout
    except subprocess.CalledProcessError:
        return False


def has_run_as(pkg: str, serial: str) -> bool:
    """Проверить возможность run-as для пакета (обычно для debuggable)."""
    try:
        res = adb_shell(f"run-as {sh_quote(pkg)} id", serial=serial, check=True)
        return res.returncode == 0 and "uid=" in res.stdout
    except subprocess.CalledProcessError:
        return False


# --------------------------- Бэкап -------------------------------------------


def backup_apk(pkg: str, dest_dir: Path, serial: str, *, skip_apk: bool, dry: DryRunContext) -> List[str]:
    """Скачать APK/сплиты в dest_dir. Возвращает список локальных имён файлов."""
    saved: List[str] = []
    if skip_apk:
        logging.info("Пропуск бэкапа APK (--skip-apk).")
        return saved
    apk_paths = package_paths(pkg, serial)
    if len(apk_paths) == 1:
        # Обычный одиночный APK
        local_name = "app.apk"
        dry.run(pull_file, apk_paths[0], dest_dir / local_name, serial)
        saved.append(local_name)
    else:
        # Split-APK: сохраняем все
        for i, ap in enumerate(apk_paths, start=1):
            # выделим "split_config.xx.apk" если есть
            base = Path(ap).name
            local_name = f"{i:02d}_{base}"
            dry.run(pull_file, ap, dest_dir / local_name, serial)
            saved.append(local_name)
    return saved


def pull_file(remote_path: str, local_path: Path, serial: str):
    """Скачать файл с устройства."""
    local_path.parent.mkdir(parents=True, exist_ok=True)
    logging.info("Скачивание %s → %s", remote_path, local_path)
    adb(["pull", remote_path, str(local_path)], serial=serial, check=True)


def backup_stream_tar_gz(sh_cmd: str, out_path: Path, serial: str):
    """
    Потоково выполнить команду на устройстве, которая отдаёт TAR в stdout,
    и сжать на ПК в GZIP (без буферизации всей пачки в память/диск).
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    logging.info("Сохранение tar.gz → %s", out_path)
    p = adb_exec_out(sh_cmd, serial=serial)
    assert p.stdout is not None
    # Записываем gzip по потокам
    with out_path.open("wb") as f_out, gzip.GzipFile(fileobj=f_out, mode="wb") as gz:
        while True:
            chunk = p.stdout.read(1024 * 1024)
            if not chunk:
                break
            gz.write(chunk)
    # Проверяем stderr
    _, err = p.communicate(timeout=5)
    if p.returncode not in (None, 0):
        logging.error("Команда exec-out завершилась с кодом %s", p.returncode)
        if err:
            logging.error("stderr: %s", err.decode("utf-8", errors="ignore"))
        raise subprocess.CalledProcessError(p.returncode or 1, "adb exec-out")
    if err:
        logging.debug("exec-out stderr: %s", err.decode("utf-8", errors="ignore"))


def backup_data(pkg: str, dest_dir: Path, serial: str, *, skip_data: bool, dry: DryRunContext) -> Tuple[Optional[str], str]:
    """
    Бэкап /data/data/<pkg> в data.tar.gz.
    Возвращает (filename|None, method: 'root'|'run-as'|'none').
    """
    if skip_data:
        logging.info("Пропуск бэкапа данных (--skip-data).")
        return None, "none"

    method = "none"
    out_name = "data.tar.gz"
    # Порядок попыток: root → run-as
    if is_root(serial):
        method = "root"
        # Исключения передаём через --exclude для tar (на устройстве)
        exclude_args = " ".join([f"--exclude {sh_quote(x)}" for x in DEFAULT_EXCLUDES])
        sh_cmd = f"su -c 'cd /data/data/{sh_quote(pkg)[1:-1]} && tar -cpf - {exclude_args} . || exit 7'"
        dry.run(backup_stream_tar_gz, sh_cmd, dest_dir / out_name, serial)
        return (out_name if not dry.enabled else out_name), method

    if has_run_as(pkg, serial):
        method = "run-as"
        exclude_args = " ".join([f"--exclude {sh_quote(x)}" for x in DEFAULT_EXCLUDES])
        sh_cmd = f"run-as {sh_quote(pkg)} sh -c 'cd /data/data/{sh_quote(pkg)[1:-1]} && tar -cpf - {exclude_args} . || exit 7'"
        dry.run(backup_stream_tar_gz, sh_cmd, dest_dir / out_name, serial)
        return (out_name if not dry.enabled else out_name), method

    logging.warning("Нет доступа к данным: требуется root или debuggable приложение (run-as).")
    return None, "none"


def backup_media(pkg: str, dest_dir: Path, serial: str, *, include_media: bool, dry: DryRunContext) -> Optional[str]:
    """
    Бэкап медиа-каталога /sdcard/Android/data/<pkg> в media.tar.gz (если каталог есть).
    """
    if not include_media:
        return None
    out_name = "media.tar.gz"
    # Проверим наличие каталога
    res = adb_shell(f"[ -d /sdcard/Android/data/{sh_quote(pkg)[1:-1]} ] && echo OK || echo NO", serial=serial)
    if "OK" not in res.stdout:
        logging.info("Каталог медиа отсутствует: /sdcard/Android/data/%s", pkg)
        return None
    sh_cmd = f"tar -cpf - -C /sdcard/Android/data/{sh_quote(pkg)[1:-1]} . || exit 7"
    dry.run(backup_stream_tar_gz, sh_cmd, dest_dir / out_name, serial)
    return out_name


def generate_manifest(backup_dir: Path, meta: Dict, components: Dict, device_serial: str, note: Optional[str]) -> Path:
    """Создать manifest.json."""
    man = {
        "package": meta["package"],
        "label": meta.get("label") or meta["package"],
        "version_name": meta.get("version_name"),
        "version_code": meta.get("version_code"),
        "sdk_int": meta.get("sdk_int"),
        "target_sdk": meta.get("target_sdk"),
        "device_serial": device_serial,
        "timestamp_utc": dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "backup_components": components,
        "notes": note or "",
    }
    path = backup_dir / "manifest.json"
    write_json(path, man)
    return path


def do_backup(args: argparse.Namespace) -> int:
    serial = ensure_single_device(args.serial)
    dry = DryRunContext(args.dry_run)

    # Подготовим каталог бэкапа
    root = Path(args.output or DEFAULT_BACKUP_ROOT)
    pkg_dir = root / args.package
    bdir = pkg_dir / now_ts()
    if not args.dry_run:
        bdir.mkdir(parents=True, exist_ok=True)

    # Логи в файл бэкапа
    logfile = bdir / "log.txt"
    file_handler = logging.FileHandler(logfile, encoding="utf-8") if not args.dry_run else None
    if file_handler:
        file_handler.setLevel(logging.DEBUG if args.verbose else logging.INFO)
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT_FILE))
        logging.getLogger().addHandler(file_handler)

    try:
        # Метаданные
        meta = get_package_meta(args.package, serial)
        logging.info("Пакет: %s  v%s (code %s), SDK=%s",
                     meta["package"], meta.get("version_name"), meta.get("version_code"), meta.get("sdk_int"))

        # APK
        saved_apks = backup_apk(args.package, bdir, serial, skip_apk=args.skip_apk, dry=dry)

        # Данные
        data_name, data_method = backup_data(args.package, bdir, serial, skip_data=args.skip_data, dry=dry)

        # Медиа
        media_name = backup_media(args.package, bdir, serial, include_media=args.include_media, dry=dry)

        # Манифест + хэши
        comps = {
            "apk": bool(saved_apks),
            "data": data_method,
            "media": bool(media_name),
        }
        if not args.dry_run:
            generate_manifest(bdir, meta, comps, serial, args.note)
            files_for_hash = ["manifest.json", "log.txt"] + saved_apks
            if data_name:
                files_for_hash.append(data_name)
            if media_name:
                files_for_hash.append(media_name)
            write_hashes(bdir, files_for_hash)

        logging.info("Бэкап завершён: %s", bdir)
        return EXIT_OK
    finally:
        if file_handler:
            logging.getLogger().removeHandler(file_handler)
            file_handler.close()


# --------------------------- Восстановление ----------------------------------


def install_apks(apk_files: List[Path], serial: str, *, force_downgrade: bool, dry: DryRunContext):
    """Установка одного APK или набора сплитов."""
    if not apk_files:
        logging.info("APK-файлы для установки не найдены — пропуск.")
        return
    # Сортируем, чтобы 01_, 02_ шли по порядку
    apk_files = sorted(apk_files)
    if len(apk_files) == 1:
        args = ["install", "-r"]
        if force_downgrade:
            args.append("-d")
        args += [str(apk_files[0])]
        if dry.enabled:
            dry.run(adb, args, serial, check=True)
        else:
            logging.info("Установка APK: %s", apk_files[0].name)
            adb(args, serial=serial, check=True)
    else:
        # install-multiple
        args = ["install-multiple", "-r"]
        if force_downgrade:
            args.append("-d")
        args += [str(p) for p in apk_files]
        if dry.enabled:
            dry.run(adb, args, serial, check=True)
        else:
            logging.info("Установка split-APK (%d файлов)", len(apk_files))
            adb(args, serial=serial, check=True)


def push_and_extract_tar_gz(local_path: Path, remote_dir: str, serial: str, *, use_root: bool):
    """
    Загрузка .tar.gz на устройство и распаковка в целевой каталог.
    Для совместимости используем пайп: toybox/bin/gzip -d -c | tar -xpf -
    """
    if not local_path.exists():
        logging.warning("Файл для восстановления отсутствует: %s", local_path)
        return
    tmp_remote = f"/sdcard/Download/.tmp_{local_path.name}"
    logging.info("Загрузка %s → %s", local_path.name, tmp_remote)
    adb(["push", str(local_path), tmp_remote], serial=serial, check=True)

    # Создадим целевой каталог
    mkdir_cmd = f"mkdir -p {sh_quote(remote_dir)}"
    if use_root:
        adb_shell(f"su -c {sh_quote(mkdir_cmd)}", serial=serial, check=False)
    else:
        adb_shell(mkdir_cmd, serial=serial, check=False)

    # toybox gzip есть на большинстве современных Android; делаем совместимую команду:
    extract_cmd = (
        f"(toybox gzip -d -c {sh_quote(tmp_remote)} 2>/dev/null || gzip -d -c {sh_quote(tmp_remote)})"
        f" | tar -xpf - -C {sh_quote(remote_dir)}"
    )
    if use_root:
        adb_shell(f"su -c {sh_quote(extract_cmd)}", serial=serial, check=True)
    else:
        adb_shell(extract_cmd, serial=serial, check=True)

    # Удалим временный файл
    adb_shell(f"rm -f {sh_quote(tmp_remote)}", serial=serial, check=False)


def restore_data(pkg: str, bdir: Path, serial: str, *, dry: DryRunContext):
    """Восстановление данных приложения (/data/data/<pkg>). Требует root или run-as."""
    data_path = bdir / "data.tar.gz"
    if not data_path.exists():
        logging.info("data.tar.gz отсутствует — пропуск восстановления данных.")
        return

    root = is_root(serial)
    if root:
        logging.info("Восстановление данных с root.")
        # Распаковка
        dry.run(push_and_extract_tar_gz, data_path, f"/data/data/{pkg}", serial, use_root=True)
        # Выставим владельца по uid (numeric), если удастся его определить
        meta = read_manifest(bdir) or {}
        uid = meta.get("app_id") or meta.get("user_id")
        if not uid:
            # fallback: возьмём текущий uid каталога
            try:
                out = adb_shell(f"stat -c %u /data/data/{sh_quote(pkg)[1:-1]}", serial=serial)
                uid = int(out.stdout.strip())
            except Exception:
                uid = None
        if uid is not None:
            chown_cmd = f"chown -R {uid}:{uid} /data/data/{sh_quote(pkg)[1:-1]}"
            restorecon_cmd = f"restorecon -R /data/data/{sh_quote(pkg)[1:-1]}"
            dry.run(adb_shell, f"su -c {sh_quote(chown_cmd)}", serial, True)
            dry.run(adb_shell, f"su -c {sh_quote(restorecon_cmd)}", serial, True)
        else:
            logging.warning("Не удалось определить uid владельца — пропуск chown.")
        return

    # Без root — попробуем run-as (только для debuggable)
    if has_run_as(pkg, serial):
        logging.info("Восстановление данных через run-as (debuggable).")
        # Поставим во временный путь и распакуем run-as
        tmp_remote = f"/sdcard/Download/.tmp_{data_path.name}"
        dry.run(adb, ["push", str(data_path), tmp_remote], serial, True)
        cmd = (
            f"run-as {sh_quote(pkg)} sh -c "
            f"'cd /data/data/{sh_quote(pkg)[1:-1]} && "
            f"(toybox gzip -d -c {sh_quote(tmp_remote)} 2>/dev/null || gzip -d -c {sh_quote(tmp_remote)}) | tar -xpf - && "
            f"rm -f {sh_quote(tmp_remote)}'"
        )
        dry.run(adb_shell, cmd, serial, True)
        return

    logging.error("Нет прав для восстановления данных. Нужен root или debuggable (run-as).")
    raise SystemExit(EXIT_PERMS)


def restore_media(pkg: str, bdir: Path, serial: str, *, dry: DryRunContext):
    """Восстановление медиа каталога (/sdcard/Android/data/<pkg>)."""
    media_path = bdir / "media.tar.gz"
    if not media_path.exists():
        return
    logging.info("Восстановление медиа в /sdcard/Android/data/%s", pkg)
    dry.run(push_and_extract_tar_gz, media_path, f"/sdcard/Android/data/{pkg}", serial, use_root=False)


def read_manifest(bdir: Path) -> Optional[Dict]:
    mf = bdir / "manifest.json"
    if not mf.exists():
        return None
    try:
        return json.loads(mf.read_text(encoding="utf-8"))
    except Exception:
        return None


def grant_permissions(pkg: str, serial: str, requested: List[str]):
    """Выдать наиболее типовые «опасные» разрешения из списка запрошенных (best-effort)."""
    # Список можно расширять по потребности
    dangerous_candidates = {
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_MEDIA_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.POST_NOTIFICATIONS",
    }
    to_grant = [p for p in requested if p in dangerous_candidates]
    if not to_grant:
        logging.info("Нет подходящих разрешений для автовыдачи.")
        return
    for perm in to_grant:
        logging.info("Выдача разрешения: %s", perm)
        adb_shell(f"pm grant {sh_quote(pkg)} {sh_quote(perm)}", serial=serial, check=False)


def do_restore(args: argparse.Namespace) -> int:
    # Проверим каталог бэкапа
    bdir = Path(args.path).resolve()
    if not bdir.exists():
        logging.error("Каталог бэкапа не найден: %s", bdir)
        return EXIT_ARGS

    serial = ensure_single_device(args.serial)
    dry = DryRunContext(args.dry_run)

    # Верификация хэшей (перед восстановлением)
    if not args.dry_run:
        ok, errs = verify_hashes(bdir)
        if not ok:
            logging.error("Проверка хэшей провалена:\n- %s", "\n- ".join(errs))
            return EXIT_VERIFY

    manifest = read_manifest(bdir) or {}
    pkg = manifest.get("package")
    if not pkg:
        logging.warning("manifest.json отсутствует или повреждён; потребуется указать пакет вручную.")
        pkg = args.package or ""
    if args.only_apk:
        do_apk = True; do_data = False; do_media = False
    elif args.only_data:
        do_apk = False; do_data = True; do_media = False
    elif args.only_media:
        do_apk = False; do_data = False; do_media = True
    else:
        do_apk = True; do_data = True; do_media = True

    # Установка APK
    if do_apk:
        # Соберём список APK из каталога: либо app.apk, либо набор *.apk
        apks = []
        single = bdir / "app.apk"
        if single.exists():
            apks = [single]
        else:
            apks = sorted(p for p in bdir.glob("*.apk"))
        install_apks(apks, serial, force_downgrade=args.force_downgrade, dry=dry)

    # Восстановление данных
    if do_data:
        restore_data(pkg, bdir, serial, dry=dry)

    # Восстановление медиа
    if do_media:
        restore_media(pkg, bdir, serial, dry=dry)

    # Выдача разрешений (если просили)
    if args.grant_perms and manifest:
        req = manifest.get("requested_permissions") or []
        grant_permissions(pkg, serial, req)

    # Запуск приложения (если просили)
    if args.launch and pkg:
        logging.info("Запуск приложения: %s", pkg)
        # Попробуем найти main activity автоматически
        try:
            res = adb_shell(
                f"cmd package resolve-activity --brief {sh_quote(pkg)} | tail -n 1",
                serial=serial, check=True
            )
            comp = res.stdout.strip()
            if comp:
                adb_shell(f"am start -n {sh_quote(comp)}", serial=serial, check=False)
            else:
                # Fallback через monkey
                adb_shell(f"monkey -p {sh_quote(pkg)} -c android.intent.category.LAUNCHER 1", serial=serial, check=False)
        except Exception:
            adb_shell(f"monkey -p {sh_quote(pkg)} -c android.intent.category.LAUNCHER 1", serial=serial, check=False)

    logging.info("Восстановление завершено.")
    return EXIT_OK


# --------------------------- Сервисные операции ------------------------------


def do_list_devices(args: argparse.Namespace) -> int:
    devs = list_devices()
    if not devs:
        print("Нет подключённых устройств.")
        return EXIT_OK
    print("Подключённые устройства:")
    for d in devs:
        print("  ", d["raw"])
    return EXIT_OK


def do_list_backups(args: argparse.Namespace) -> int:
    root = Path(args.output or DEFAULT_BACKUP_ROOT)
    if args.package:
        pkg_dir = root / args.package
        if not pkg_dir.exists():
            print("Бэкапы для пакета не найдены:", args.package)
            return EXIT_OK
        print(f"{args.package}:")
        items = sorted((d for d in pkg_dir.iterdir() if d.is_dir()), reverse=True)
        for d in items:
            print("  ", d.name)
        return EXIT_OK
    else:
        if not root.exists():
            print("Каталог с бэкапами пуст.")
            return EXIT_OK
        for pkg_dir in sorted((d for d in root.iterdir() if d.is_dir())):
            backups = sorted((d for d in pkg_dir.iterdir() if d.is_dir()), reverse=True)
            print(pkg_dir.name, ("— нет бэкапов" if not backups else ""))
            for b in backups:
                print("   •", b.name)
        return EXIT_OK


def do_verify(args: argparse.Namespace) -> int:
    bdir = Path(args.path).resolve()
    ok, errs = verify_hashes(bdir)
    if ok:
        print("OK: все хэши совпадают.")
        return EXIT_OK
    print("Проблемы при проверке:")
    for e in errs:
        print(" -", e)
    return EXIT_VERIFY


def do_prune(args: argparse.Namespace) -> int:
    root = Path(args.output or DEFAULT_BACKUP_ROOT)
    pkg_dir = root / args.package
    keep = max(0, int(args.keep))
    if not pkg_dir.exists():
        print("Бэкапы для пакета не найдены:", args.package)
        return EXIT_OK
    backups = sorted((d for d in pkg_dir.iterdir() if d.is_dir()), reverse=True)
    to_remove = backups[keep:]
    for d in to_remove:
        print("Удаление:", d)
        shutil.rmtree(d, ignore_errors=True)
    print(f"Готово. Оставлено: {keep}, удалено: {len(to_remove)}.")
    return EXIT_OK


# --------------------------- Парсер аргументов --------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Бэкап и восстановление APK/данных Android-приложений через ADB (один файл).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--verbose", action="store_true", help="Подробные логи (DEBUG).")

    sub = p.add_subparsers(dest="cmd", required=True)

    # backup
    b = sub.add_parser("backup", help="Сделать бэкап приложения.")
    b.add_argument("-p", "--package", required=True, help="Имя пакета (например, com.example.app).")
    b.add_argument("--output", default=str(DEFAULT_BACKUP_ROOT), help="Каталог для бэкапов.")
    b.add_argument("--include-media", action="store_true", help="Сохранить /sdcard/Android/data/<pkg>.")
    b.add_argument("--skip-apk", action="store_true", help="Не сохранять APK.")
    b.add_argument("--skip-data", action="store_true", help="Не сохранять данные приложения.")
    b.add_argument("--note", help="Свободная заметка, попадёт в manifest.json.")
    b.add_argument("--serial", help="ADB serial устройства.")
    b.add_argument("--dry-run", action="store_true", help="Показать план без выполнения.")
    b.set_defaults(func=do_backup)

    # restore
    r = sub.add_parser("restore", help="Восстановить из бэкапа.")
    r.add_argument("--path", required=True, help="Путь к каталогу бэкапа.")
    g = r.add_mutually_exclusive_group()
    g.add_argument("--only-apk", action="store_true", help="Восстановить только APK.")
    g.add_argument("--only-data", action="store_true", help="Восстановить только данные.")
    g.add_argument("--only-media", action="store_true", help="Восстановить только медиа.")
    r.add_argument("--force-downgrade", action="store_true", help="Разрешить даунгрейд APK (-d).")
    r.add_argument("--grant-perms", action="store_true", help="Попробовать выдать runtime-разрешения из манифеста.")
    r.add_argument("--launch", action="store_true", help="Запустить приложение после восстановления.")
    r.add_argument("--serial", help="ADB serial устройства.")
    r.add_argument("--dry-run", action="store_true", help="Показать план без выполнения.")
    r.add_argument("--package", help="Имя пакета (если manifest.json отсутствует).")
    r.set_defaults(func=do_restore)

    # verify
    v = sub.add_parser("verify", help="Проверить целостность файлов бэкапа.")
    v.add_argument("--path", required=True, help="Путь к каталогу бэкапа.")
    v.set_defaults(func=do_verify)

    # prune
    pr = sub.add_parser("prune", help="Удалить старые бэкапы, оставив N свежих.")
    pr.add_argument("-p", "--package", required=True, help="Имя пакета.")
    pr.add_argument("--keep", type=int, required=True, help="Сколько бэкапов оставить.")
    pr.add_argument("--output", default=str(DEFAULT_BACKUP_ROOT), help="Корневой каталог бэкапов.")
    pr.set_defaults(func=do_prune)

    # list-backups
    lb = sub.add_parser("list-backups", help="Показать бэкапы.")
    lb.add_argument("-p", "--package", help="Фильтр по пакету.")
    lb.add_argument("--output", default=str(DEFAULT_BACKUP_ROOT), help="Корневой каталог бэкапов.")
    lb.set_defaults(func=do_list_backups)

    # list-devices
    ld = sub.add_parser("list-devices", help="Список подключённых устройств.")
    ld.set_defaults(func=do_list_devices)

    return p


def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format=LOG_FORMAT_CONSOLE)


# --------------------------- Точка входа -------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args.verbose)
    try:
        which_adb()  # ранняя проверка наличия adb
        return args.func(args)
    except SystemExit as e:
        # Позволяет корректно возвращать коды выхода из глубоких мест
        return int(e.code) if isinstance(e.code, int) else EXIT_MISC
    except subprocess.CalledProcessError:
        return EXIT_ADB
    except KeyboardInterrupt:
        logging.error("Операция прервана пользователем.")
        return EXIT_MISC
    except Exception as e:
        logging.exception("Неожиданная ошибка: %s", e)
        return EXIT_MISC


if __name__ == "__main__":
    sys.exit(main())