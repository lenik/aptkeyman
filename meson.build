project(
    'aptkeyman',
    version: run_command(
        'sh',
        '-c', '''
        v=$(
            command -v zfr >/dev/null 2>&1 && zfr version 2>/dev/null || true
        )
        if [ -z "$v" ] && [ -f VERSION ]; then
            v=$(head -n1 VERSION | tr -d '\r')
            v=${v#v}
        fi
        if [ -z "$v" ]; then
            v="0.0.0" # FIXED TO 0.0.0, DO NOT MODIFY
        fi
        printf '%s' "$v"
        ''',
        check: false,
    ).stdout().strip(),
    license: 'AGPL-3.0-or-later',
)

project_author = 'Lenik'
project_email = 'aptkeyman@bodz.net'
project_year = 2026

py = import('python').find_installation('python3')
fs = import('fs')
asciidoctor = find_program('asciidoctor', required: true)

prefix = get_option('prefix')
bindir = prefix / get_option('bindir')
datadir = prefix / get_option('datadir')
localedir = prefix / get_option('localedir')
mandir = prefix / get_option('mandir')
pkgdocdir = datadir / 'doc' / meson.project_name()
pkgdatadir = datadir / meson.project_name()

subdir('po')

# Main executable
aptkeyman_exe = custom_target(
    'aptkeyman',
    input: 'src/aptkeyman.py',
    output: 'aptkeyman',
    command: [
        py,
        '-c',
        'import os, shutil, sys; shutil.copyfile(sys.argv[1], sys.argv[2]); os.chmod(sys.argv[2], 0o755)',
        '@INPUT@',
        '@OUTPUT@',
    ],
    build_by_default: true,
    install: true,
    install_dir: bindir,
)

# Helper modules installed next to the executable (importable via PATH dir)
py_modules = [
    'commons.py',
    'aptkeyman_db.py',
    'aptkeyman_patterns.py',
    'aptkeyman_sources.py',
    'aptkeyman_fetch.py',
    'aptkeyman_progress.py',
    'aptkeyman_keys.py',
    'aptkeyman_proxy.py',
    'aptkeyman_seed.py',
    'aptkeyman_verify.py',
    'aptkeyman_gui.py',
]

foreach mod : py_modules
    custom_target(
        mod,
        input: 'src' / mod,
        output: mod,
        command: ['cp', '@INPUT@', '@OUTPUT@'],
        build_by_default: true,
        install: true,
        install_dir: bindir,
    )
endforeach

# Builtin key database (download blobs at build time when network allows)
build_db = custom_target(
    'aptkeyman-db',
    input: ['data/wellknown.json', 'scripts/build_db.py'],
    output: 'aptkeyman.db',
    command: [
        py,
        meson.project_source_root() / 'scripts/build_db.py',
        '--json', meson.project_source_root() / 'data/wellknown.json',
        '--out', '@OUTPUT@',
    ],
    build_by_default: true,
    install: true,
    install_dir: pkgdatadir,
)

install_data(
    'data/wellknown.json',
    install_dir: pkgdatadir,
)

install_data(
    'aptkeyman.bash',
    install_dir: datadir / 'bash-completion' / 'completions',
    rename: 'aptkeyman',
)

install_data(
    [
        'LICENSE',
        'README.md',
        'README-zh_CN.md',
        'VERSION',
    ],
    install_dir: pkgdocdir,
)

man_asciidoctor_args = [
    asciidoctor,
    '-b', 'manpage',
    '-a', 'project-version=' + meson.project_version(),
    '-a', 'project-year=@0@'.format(project_year),
    '-a', 'project-author=' + project_author,
    '-a', 'project-email=' + project_email,
]

custom_target(
    'aptkeyman-man',
    input: 'man/aptkeyman.adoc',
    output: 'aptkeyman.1',
    command: man_asciidoctor_args + ['-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
    install: true,
    install_dir: mandir / 'man1',
)

man_locales = ['fr', 'it', 'de', 'es', 'zh_CN', 'ja', 'ko', 'ar']
foreach loc : man_locales
    # Unique build-dir name; install as aptkeyman.1 under mandir/<loc>/man1/
    locale_man = custom_target(
        'aptkeyman-man-' + loc,
        input: 'man' / loc / 'aptkeyman.adoc',
        output: loc + '-aptkeyman.1',
        command: man_asciidoctor_args + ['-o', '@OUTPUT@', '@INPUT@'],
        build_by_default: true,
    )
    meson.add_install_script(
        'sh',
        '-c',
        'mkdir -p "${DESTDIR}' + (mandir / loc / 'man1') + '" && cp -f "'
        + locale_man.full_path()
        + '" "${DESTDIR}'
        + (mandir / loc / 'man1' / 'aptkeyman.1')
        + '"',
    )
endforeach

test(
    'python-unit',
    py,
    args: ['-m', 'unittest', 'discover', '-s', (meson.project_source_root() / 'tests'), '-p', 'test_*.py'],
    env: [
        'PYTHONPATH=' + (meson.project_source_root() / 'src'),
        'APTKEYMAN_LOCALEDIR=' + (meson.project_build_root() / 'po'),
        'APTKEYMAN_DATADIR=' + (meson.project_source_root() / 'data'),
    ],
)

run_target(
    'posync',
    command: [
        find_program('zfr'),
        'translate',
        '--sync',
        '-C', meson.project_source_root(),
    ],
)

run_target(
    'look',
    command: [
        find_program('zfr'),
        'build',
        '--look',
        '-C', meson.project_source_root(),
        '-b', meson.project_build_root(),
    ],
)

run_target(
    'install-symlinks',
    command: [
        'bash',
        meson.project_source_root() / 'scripts' / 'install-symlinks.sh',
        meson.project_source_root(),
        meson.project_build_root(),
    ],
)

run_target(
    'uninstall-symlinks',
    command: [
        'bash',
        meson.project_source_root() / 'scripts' / 'uninstall-symlinks.sh',
        meson.project_source_root(),
        meson.project_build_root(),
    ],
)
