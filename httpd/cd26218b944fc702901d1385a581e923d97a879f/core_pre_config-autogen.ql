/**
 * @name httpd-cd26218b944fc702901d1385a581e923d97a879f-core_pre_config
 * @id cpp/httpd/cd26218b944fc702901d1385a581e923d97a879f/core-pre-config
 * @description httpd-cd26218b944fc702901d1385a581e923d97a879f-server/core.c-core_pre_config CVE-2020-1927
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(BitwiseOrExpr target_0 |
		target_0.getValue()="576"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ap_regcomp_set_default_cflags")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_0.getEnclosingFunction() = func)
}

from Function func
where
not func_0(func)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
