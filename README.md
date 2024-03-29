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

## About target OSS and CVEs

As for now, we mainly focus on OSS written in C/C++, where package management and SCA techniques don't apply.

To focus on the most important, infra-like OSS, we borrowed the list from [google/oss-fuzz](https://github.com/google/oss-fuzz/tree/master/projects), filtered out those denoted `language: c/c++` in their yaml files. Besides, since our tool depends on Git commit to revert code-base to specific versions and to generate patches, we currently only support those hosted or mirrored on any Git platforms.

To collect patching commit IDs for any CVE vulnerability more easily, we utilized the amazing [Ubuntu Security](https://ubuntu.com/security) and [Red Hat Bugzilla](https://bugzilla.redhat.com/) as processed info sources, which contain patches urls of corresponding upstream OSS if possible.Some specific projects required more manual handling, such as those repos hosted originally with Mercurial and SVN and patch urls don't contain a git commit ID.

Considering SAST queries/rules make a step further towards finding similar vulnerabilities, we are more than careful in opening source the whole storage of our rules. Rules of only a part of target OSS are made public, and some of them were generated by a former version of patch2ql.

Right now we welcome the maintainers of these OSS to contact us requiring its rules. The complete set of rules will be made public once we determine that it may not greatly lower the security level of the whole OSS domain.

## Cognate vulnerabilities (0days) and issues found

The rules generated by patch2ql have been proved effective in finding cognate vulnerabilities in downstream OSS. However, it turned out that it is also useful to find cognate defects in the original upstream project, i.e. those similar to historical CVEs in root causes. I have not tried it for long, and a list of vulnerabilities found is as follows:

- CVE: CVE-2023-24151, CVE-2023-24152, CVE-2023-24153, CVE-2023-2977, CVE-2023-38559, CVE-2023-38560, CVE-2023-3896 (involving ImageMagick, GhostScript, OpenSC);
- issues: reports involving OpenSSL, cURL, VIM, graphicsmagick.

## License

The CodeQL queries/rules in this repository is licensed under the MIT License.

The tool for generating these rules, i.e. patch2ql, is not ready for publication yet. It may be made public under a separate license.

When using the rules here together with CodeQL CLI to analyze any projects, you should follow the restrictions of [CodeQL CLI LICENSE](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md).

## Reference

Wang, Fuwei. "Patch2QL: Discover Cognate Defects in Open Source Software Supply Chain With Auto-generated Static Analysis Rules." arXiv preprint arXiv:2401.12443 (2024).

## Contact

Technical representations and explanations are still on their way. To exchange ideas, feel free to contact the [maintainer](mailto:forward.wfw@hotmail.com). Any suggestions or collaborations are welcomed.
