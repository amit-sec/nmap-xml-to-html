# nmap2html.spec
# Build: pyinstaller nmap2html.spec

block_cipher = None

a = Analysis(
    ['nmap2html.py'],
    pathex=['.'],
    binaries=[],
    datas=[],
    hiddenimports=[
        'xml.etree.ElementTree',
        'ipaddress',
        'json'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Only exclude heavy third-party modules (safe)
        'numpy',
        'pandas',
        'PIL',
        'cv2',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='nmap2html',
    debug=False,
    strip=False,
    upx=False,                 # Correct: avoid AV false positives
    console=True,              # Keep CLI
    disable_windowed_traceback=False,
)