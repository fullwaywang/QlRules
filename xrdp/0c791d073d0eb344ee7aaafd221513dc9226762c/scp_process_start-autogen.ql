/**
 * @name xrdp-0c791d073d0eb344ee7aaafd221513dc9226762c-scp_process_start
 * @id cpp/xrdp/0c791d073d0eb344ee7aaafd221513dc9226762c/scp-process-start
 * @description xrdp-0c791d073d0eb344ee7aaafd221513dc9226762c-sesman/scp.c-scp_process_start CVE-2020-4044
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="unknown protocol version specified. connection refused."
		and not target_0.getValue()="protocol violation. connection refused."
		and target_0.getEnclosingFunction() = func
}

from Function func, StringLiteral target_0
where
func_0(func, target_0)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
