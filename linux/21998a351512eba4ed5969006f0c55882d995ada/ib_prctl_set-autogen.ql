/**
 * @name linux-21998a351512eba4ed5969006f0c55882d995ada-ib_prctl_set
 * @id cpp/linux/21998a351512eba4ed5969006f0c55882d995ada/ib_prctl_set
 * @description linux-21998a351512eba4ed5969006f0c55882d995ada-ib_prctl_set 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vspectre_v2_user) {
	exists(VariableAccess target_0 |
		target_0.getTarget()=vspectre_v2_user
		and target_0.getParent().(EQExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_8(Function func) {
	exists(LogicalAndExpr target_8 |
		target_8.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("spectre_v2_user_mitigation")
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("spectre_v2_user_mitigation")
		and target_8.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Function func) {
	exists(LogicalOrExpr target_9 |
		target_9.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("spectre_v2_user_mitigation")
		and target_9.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("spectre_v2_user_mitigation")
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("spectre_v2_user_mitigation")
		and target_9.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_9.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_9.getEnclosingFunction() = func)
}

from Function func, Variable vspectre_v2_user
where
func_0(vspectre_v2_user)
and not func_8(func)
and not func_9(func)
and not vspectre_v2_user.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
