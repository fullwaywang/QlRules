/**
 * @name linux-34b88a68f26a75e4fded796f1a49c40f82234b7d-__sys_recvmmsg
 * @id cpp/linux/34b88a68f26a75e4fded796f1a49c40f82234b7d/--sys-recvmmsg
 * @description linux-34b88a68f26a75e4fded796f1a49c40f82234b7d-__sys_recvmmsg 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable verr_2172) {
	exists(GotoStmt target_0 |
		target_0.toString() = "goto ..."
		and target_0.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=verr_2172
		and target_0.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

predicate func_4(Variable verr_2172, Variable vdatagrams_2172) {
	exists(ReturnStmt target_4 |
		target_4.getExpr().(VariableAccess).getTarget()=vdatagrams_2172
		and target_4.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=verr_2172
		and target_4.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

predicate func_5(Variable verr_2172, Variable vsock_2173) {
	exists(IfStmt target_5 |
		target_5.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=verr_2172
		and target_5.getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-11"
		and target_5.getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getOperand().(Literal).getValue()="11"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sk_err"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sk"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsock_2173
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(VariableAccess).getTarget()=verr_2172
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof EqualityOperation)
}

predicate func_7(Function func) {
	exists(Literal target_7 |
		target_7.getValue()="0"
		and target_7.getEnclosingFunction() = func)
}

predicate func_11(Variable verr_2172, Function func) {
	exists(ReturnStmt target_11 |
		target_11.getExpr().(VariableAccess).getTarget()=verr_2172
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_11)
}

from Function func, Variable verr_2172, Variable vdatagrams_2172, Variable vsock_2173
where
not func_0(verr_2172)
and func_4(verr_2172, vdatagrams_2172)
and func_5(verr_2172, vsock_2173)
and func_7(func)
and func_11(verr_2172, func)
and verr_2172.getType().hasName("int")
and vdatagrams_2172.getType().hasName("int")
and vsock_2173.getType().hasName("socket *")
and verr_2172.getParentScope+() = func
and vdatagrams_2172.getParentScope+() = func
and vsock_2173.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
