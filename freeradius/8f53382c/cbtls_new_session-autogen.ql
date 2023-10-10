/**
 * @name freeradius-8f53382c-cbtls_new_session
 * @id cpp/freeradius/8f53382c/cbtls-new-session
 * @description freeradius-8f53382c-src/main/tls.c-cbtls_new_session CVE-2017-9148
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Variable vfd_1353, VariableAccess target_3, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("fchmod")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfd_1353
		and target_2.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
}

predicate func_3(Variable vrequest_1342, VariableAccess target_3) {
		target_3.getTarget()=vrequest_1342
}

from Function func, Variable vrequest_1342, Variable vfd_1353, ExprStmt target_2, VariableAccess target_3
where
func_2(vfd_1353, target_3, target_2)
and func_3(vrequest_1342, target_3)
and vrequest_1342.getType().hasName("REQUEST *")
and vfd_1353.getType().hasName("int")
and vrequest_1342.getParentScope+() = func
and vfd_1353.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
