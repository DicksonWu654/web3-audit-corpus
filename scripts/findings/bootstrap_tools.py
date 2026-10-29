"""Optionally acquire the exact local Ubuntu toolchain used for this extraction run.

Network is used only with --download. Packages are unpacked under the ignored local
cache, never installed on the host. No report/repository code is executed.
"""
import argparse
import subprocess
from common import ROOT

PACKAGES = ("poppler-utils=24.02.0-1ubuntu9.10", "libpoppler134=24.02.0-1ubuntu9.10", "libopenjp2-7=2.5.0-2ubuntu0.5",
            "tesseract-ocr=5.3.4-1build5", "libtesseract5=5.3.4-1build5", "liblept5=1.82.0-3build4", "tesseract-ocr-eng=1:4.1.0-2")


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--download",action="store_true")
    a=p.parse_args()
    cache=ROOT/"local-cache"
    target=cache/"fulltext/tools"
    target.mkdir(parents=True,exist_ok=True)
    if a.download:
        subprocess.run(["apt-get","download",*PACKAGES],cwd=cache,check=True)
    for package in PACKAGES:
        name=package.split("=")[0]
        matches=sorted(cache.glob(name+"_*.deb"))
        if len(matches)!=1:
            raise SystemExit(f"Expected one cached package for {name}; use --download on compatible Ubuntu repositories")
        subprocess.run(["dpkg-deb","-x",str(matches[0]),str(target)],check=True)


if __name__=="__main__":
    main()
