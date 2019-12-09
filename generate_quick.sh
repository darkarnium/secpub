#!/bin/bash

# Trim old links from README.md
HEADER=$(grep -n '\#\# Vulnerabilities' README.md | cut -d ':' -f 1)
head -n ${HEADER} README.md | tee README.md

# Generate new links
find ./Vulnerabilities | grep -i README.md | \
    xargs -I{} sh -c "stat -t %s {} | awk '{print \$10 \",\" \$16}'" | \
    sort -hr | cut -d ',' -f 2 | \
    xargs -I{} sh -c "echo \* \[\$(head -n 1 {} | sed -E 's/\#+[[:space:]]*//')]\({}\)" \
        >> README.md
