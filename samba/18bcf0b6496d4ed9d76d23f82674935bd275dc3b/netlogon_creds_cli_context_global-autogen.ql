/**
 * @name samba-18bcf0b6496d4ed9d76d23f82674935bd275dc3b-netlogon_creds_cli_context_global
 * @id cpp/samba/18bcf0b6496d4ed9d76d23f82674935bd275dc3b/netlogon-creds-cli-context-global
 * @description samba-18bcf0b6496d4ed9d76d23f82674935bd275dc3b-libcli/auth/netlogon_creds_cli.c-netlogon_creds_cli_context_global CVE-2022-38023
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="1"
		and target_0.getParent() instanceof Initializer
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="0"
		and not target_1.getValue()="1"
		and target_1.getParent() instanceof Initializer
		and target_1.getEnclosingFunction() = func
}

from Function func, Literal target_0, Literal target_1
where
func_0(func, target_0)
and func_1(func, target_1)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
