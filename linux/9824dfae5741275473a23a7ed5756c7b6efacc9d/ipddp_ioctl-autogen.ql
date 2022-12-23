/**
 * @name linux-9824dfae5741275473a23a7ed5756c7b6efacc9d-ipddp_ioctl
 * @id cpp/linux/9824dfae5741275473a23a7ed5756c7b6efacc9d/ipddp_ioctl
 * @description linux-9824dfae5741275473a23a7ed5756c7b6efacc9d-ipddp_ioctl 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vrcp2_270, Variable vrp_270) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("__memcpy")
		and not target_0.getTarget().hasName("__memset")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vrcp2_270
		and target_0.getArgument(1).(VariableAccess).getTarget()=vrp_270
		and target_0.getArgument(2).(SizeofExprOperator).getValue()="32"
		and target_0.getArgument(2).(SizeofExprOperator).getExprOperand().(VariableAccess).getTarget()=vrcp2_270)
}

predicate func_2(Variable vrcp2_270, Variable vrp_270) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="ip"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vrcp2_270
		and target_2.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="ip"
		and target_2.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrp_270
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vrp_270)
}

predicate func_3(Variable vrcp2_270, Variable vrp_270) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="at"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vrcp2_270
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="at"
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrp_270
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vrp_270)
}

predicate func_4(Variable vrcp2_270, Variable vrp_270) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="flags"
		and target_4.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vrcp2_270
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="flags"
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrp_270
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vrp_270)
}

predicate func_6(Variable vrp_270) {
	exists(IfStmt target_6 |
		target_6.getCondition().(VariableAccess).getTarget()=vrp_270
		and target_6.getThen().(ExprStmt).getExpr() instanceof FunctionCall)
}

from Function func, Variable vrcp2_270, Variable vrp_270
where
func_0(vrcp2_270, vrp_270)
and not func_2(vrcp2_270, vrp_270)
and not func_3(vrcp2_270, vrp_270)
and not func_4(vrcp2_270, vrp_270)
and vrcp2_270.getType().hasName("ipddp_route")
and vrp_270.getType().hasName("ipddp_route *")
and func_6(vrp_270)
and vrcp2_270.getParentScope+() = func
and vrp_270.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
