/**
 * @name linux-9c09b214f30e3c11f9b0b03f89442df03643794d-hiddev_open
 * @id cpp/linux/9c09b214f30e3c11f9b0b03f89442df03643794d/hiddev_open
 * @description linux-9c09b214f30e3c11f9b0b03f89442df03643794d-hiddev_open 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vlist_249, Variable vres_253, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="exist"
		and target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="hiddev"
		and target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlist_249
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vres_253
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="19"
		and target_0.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_0))
}

predicate func_3(Variable vlist_249) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="hiddev"
		and target_3.getQualifier().(VariableAccess).getTarget()=vlist_249)
}

from Function func, Variable vlist_249, Variable vres_253
where
not func_0(vlist_249, vres_253, func)
and vlist_249.getType().hasName("hiddev_list *")
and func_3(vlist_249)
and vres_253.getType().hasName("int")
and vlist_249.getParentScope+() = func
and vres_253.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
