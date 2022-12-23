/**
 * @name linux-23567fd052a9abb6d67fe8e7a9ccdd9800a540f2-join_session_keyring
 * @id cpp/linux/23567fd052a9abb6d67fe8e7a9ccdd9800a540f2/join_session_keyring
 * @description linux-23567fd052a9abb6d67fe8e7a9ccdd9800a540f2-join_session_keyring CVE-2016-0728
 * @kind problem
 * @tags security
 */

import cpp

predicate func_1(Variable vkeyring_757, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("key_put")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vkeyring_757
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_2(Variable vkeyring_757) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="serial"
		and target_2.getQualifier().(VariableAccess).getTarget()=vkeyring_757)
}

from Function func, Variable vkeyring_757
where
func_1(vkeyring_757, func)
and vkeyring_757.getType().hasName("key *")
and func_2(vkeyring_757)
and vkeyring_757.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
