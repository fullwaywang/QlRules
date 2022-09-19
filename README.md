# Auto-generated CodeQL Rules for OSS Vulnerabilites

## Background

[CodeQL](https://codeql.github.com/) is an industry-leading semantic code analysis engine supported by GitHub. With its rich storage of built-in rules covering multiple developing languages and CWE catogaries, CodeQL has been extensively used by whitehat security experts for hunting for vulnerabilites in open-source-software (OSS) repositries.

However, locating known CVEs in old codebases remains as a difficult task for SAST tools like CodeQL. A large portion of vulnerablities, especially those found by hackers manually, have very complicated code context and cannot be matched with generic-purpose rules.

To this end, our attemp of automating the generation of CVE-oriented CodeQL rules comes to real life.

## About patch2ql

patch2ql is our solution, which aims at turning OSS bugfix patches into CodeQL rules (ql). Its basic idea is that reasons and causes of a defect of codes is reflected in the code patch, and by querying the similar code context of the unpatched functions, we can locate a vulnerable codebase. The matched code may be an out-of-date submodule, homologous functions, or even some other repository which `borrows' the very function.

patch2ql is currently under tensive research and development, and many features are still to be tested. This is why it is not yet ready for openning source.

## About this repository

This repository is the place to hold auto-generated rules we retrieve against some top OSS projects along the evolution stage of patch2ql. These released rules, organized according to their corresponding source projects and commit IDs, can be freely used for analyzing some other OSS project which originates/forked from or contains OSS projects whose CVEs we already covered.
