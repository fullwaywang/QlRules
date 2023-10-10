/**
 * @name linux-77f8269606bf95fcb232ee86f6da80886f1dfae8-ipmi_destroy_user
 * @id cpp/linux/77f8269606bf95fcb232ee86f6da80886f1dfae8/ipmi_destroy_user
 * @description linux-77f8269606bf95fcb232ee86f6da80886f1dfae8-ipmi_destroy_user 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vuser_1259, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("cleanup_srcu_struct")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="release_barrier"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vuser_1259
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

from Function func, Parameter vuser_1259
where
func_0(vuser_1259, func)
and vuser_1259.getType().hasName("ipmi_user *")
and vuser_1259.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
