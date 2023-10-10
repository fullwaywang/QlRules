/**
 * @name linux-b32a7dc8aef1882fbf983eb354837488cc9d54dc-aead_release
 * @id cpp/linux/b32a7dc8aef1882fbf983eb354837488cc9d54dc/aead-release
 * @description linux-b32a7dc8aef1882fbf983eb354837488cc9d54dc-aead_release 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("crypto_put_default_null_skcipher2")
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0))
}

from Function func
where
not func_0(func)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
