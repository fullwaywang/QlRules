/**
 * @name linux-83c6f2390040f188cc25b270b4befeb5628c1aee-sg_write
 * @id cpp/linux/83c6f2390040f188cc25b270b4befeb5628c1aee/sg_write
 * @description linux-83c6f2390040f188cc25b270b4befeb5628c1aee-sg_write 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_599, Variable vcmd_size_601, Variable vsfp_605, Variable vsrp_606, Variable vcmnd_609) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("sg_remove_request")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsfp_605
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsrp_606
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("copy_from_user")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcmnd_609
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuf_599
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcmd_size_601)
}

predicate func_1(Parameter vbuf_599, Variable vcmd_size_601, Variable vcmnd_609) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(UnaryMinusExpr).getValue()="-14"
		and target_1.getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="14"
		and target_1.getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("copy_from_user")
		and target_1.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcmnd_609
		and target_1.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuf_599
		and target_1.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcmd_size_601)
}

predicate func_2(Variable vsfp_605, Variable vsrp_606) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("sg_remove_request")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vsfp_605
		and target_2.getArgument(1).(VariableAccess).getTarget()=vsrp_606)
}

predicate func_3(Variable vsrp_606) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="header"
		and target_3.getQualifier().(VariableAccess).getTarget()=vsrp_606)
}

from Function func, Parameter vbuf_599, Variable vcmd_size_601, Variable vsfp_605, Variable vsrp_606, Variable vcmnd_609
where
not func_0(vbuf_599, vcmd_size_601, vsfp_605, vsrp_606, vcmnd_609)
and func_1(vbuf_599, vcmd_size_601, vcmnd_609)
and vbuf_599.getType().hasName("const char *")
and vcmd_size_601.getType().hasName("int")
and vsfp_605.getType().hasName("Sg_fd *")
and func_2(vsfp_605, vsrp_606)
and vsrp_606.getType().hasName("Sg_request *")
and func_3(vsrp_606)
and vcmnd_609.getType().hasName("unsigned char[252]")
and vbuf_599.getParentScope+() = func
and vcmd_size_601.getParentScope+() = func
and vsfp_605.getParentScope+() = func
and vsrp_606.getParentScope+() = func
and vcmnd_609.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
