/**
 * @name linux-28d76df18f0ad5bcf5fa48510b225f0ed262a99b-mptctl_hp_targetinfo
 * @id cpp/linux/28d76df18f0ad5bcf5fa48510b225f0ed262a99b/mptctl_hp_targetinfo
 * @description linux-28d76df18f0ad5bcf5fa48510b225f0ed262a99b-mptctl_hp_targetinfo 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vuarg_2664) {
	exists(Literal target_0 |
		target_0.getValue()="2680"
		and not target_0.getValue()="2573"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="3mptctl%s@%d::mptctl_hp_targetinfo - Unable to read in hp_host_targetinfo struct @ %p\n"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="drivers/message/fusion/mptctl.c"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vuarg_2664)
}

predicate func_1(Variable vuarg_2664, Variable vioc_2667) {
	exists(Literal target_1 |
		target_1.getValue()="2795"
		and not target_1.getValue()="2682"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="3mptctl: %s: ERROR - %s@%d::mptctl_hp_target_info - Unable to write out mpt_ioctl_targetinfo struct @ %p\n"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vioc_2667
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="drivers/message/fusion/mptctl.c"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vuarg_2664)
}

predicate func_2(Variable vkarg_2669) {
	exists(ValueFieldAccess target_2 |
		target_2.getTarget().getName()="hdr"
		and target_2.getQualifier().(VariableAccess).getTarget()=vkarg_2669)
}

predicate func_3(Function func) {
	exists(ReturnStmt target_3 |
		target_3.getExpr().(UnaryMinusExpr).getValue()="-19"
		and target_3.getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="19"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof LogicalOrExpr
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(DeclStmt target_4 |
		target_4.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof PointerType
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

predicate func_5(Function func) {
	exists(DeclStmt target_5 |
		func.getEntryPoint().(BlockStmt).getAStmt()=target_5)
}

predicate func_6(Variable vioc_2667, Variable viocnum_2670, Function func) {
	exists(IfStmt target_6 |
		target_6.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=viocnum_2670
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("mpt_verify_adapter")
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="iocnum"
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier() instanceof ValueFieldAccess
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vioc_2667
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vioc_2667
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="7mptctl%s::mptctl_hp_targetinfo() @%d - ioc%d not found!\n"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="drivers/message/fusion/mptctl.c"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="2687"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=viocnum_2670
		and target_6.getThen().(BlockStmt).getStmt(1) instanceof ReturnStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6)
}

from Function func, Variable vuarg_2664, Variable vioc_2667, Variable vkarg_2669, Variable viocnum_2670
where
func_0(vuarg_2664)
and func_1(vuarg_2664, vioc_2667)
and func_2(vkarg_2669)
and func_3(func)
and func_4(func)
and func_5(func)
and func_6(vioc_2667, viocnum_2670, func)
and vuarg_2664.getType().hasName("hp_target_info_t *")
and vioc_2667.getType().hasName("MPT_ADAPTER *")
and vkarg_2669.getType().hasName("hp_target_info_t")
and viocnum_2670.getType().hasName("int")
and vuarg_2664.getParentScope+() = func
and vioc_2667.getParentScope+() = func
and vkarg_2669.getParentScope+() = func
and viocnum_2670.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
