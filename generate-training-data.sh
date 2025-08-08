#!/usr/bin/env bash 



mkdir -p .training/extracted && find ../defcon33/.mirror -name "*.pdf" -type f -exec sh -c 'pdf_text "$1" > ".training/extracted/$(basename "$1" .pdf).txt"' _ {} \;

