/**
 * @name linux-b32a7dc8aef1882fbf983eb354837488cc9d54dc-aead_sock_destruct
 * @id cpp/linux/b32a7dc8aef1882fbf983eb354837488cc9d54dc/aead-sock-destruct
 * @description linux-b32a7dc8aef1882fbf983eb354837488cc9d54dc-aead_sock_destruct NULL
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("crypto_put_default_null_skcipher2")
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

from Function func
where
func_0(func)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
