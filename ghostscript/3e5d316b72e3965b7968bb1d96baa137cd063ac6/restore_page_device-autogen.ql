/**
 * @name ghostscript-3e5d316b72e3965b7968bb1d96baa137cd063ac6-restore_page_device
 * @id cpp/ghostscript/3e5d316b72e3965b7968bb1d96baa137cd063ac6/restore-page-device
 * @description ghostscript-3e5d316b72e3965b7968bb1d96baa137cd063ac6-psi/zdevice2.c-restore_page_device CVE-2018-16802
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsamepagedevice_261, EqualityOperation target_9, NotExpr target_10) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsamepagedevice_261
		and target_0.getExpr().(AssignExpr).getRValue() instanceof Literal
		and target_0.getParent().(IfStmt).getCondition()=target_9
		and target_10.getOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_1(Variable vsamepagedevice_261, EqualityOperation target_11) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsamepagedevice_261
		and target_1.getExpr().(AssignExpr).getRValue() instanceof Literal
		and target_1.getParent().(IfStmt).getCondition()=target_11)
}

predicate func_2(Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getType().hasName("bool")
		and target_2.getCondition().(LogicalAndExpr).getAnOperand() instanceof NotExpr
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getType().hasName("os_ptr")
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(ValueFieldAccess).getTarget().getName()="bot"
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="stack"
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("ref_stack_count")
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_2))
}

predicate func_4(Variable vsamepagedevice_261, NotExpr target_5) {
	exists(ConditionalExpr target_4 |
		target_4.getCondition().(VariableAccess).getTarget()=vsamepagedevice_261
		and target_4.getThen().(Literal).getValue()="0"
		and target_4.getElse().(Literal).getValue()="1"
		and target_4.getCondition().(VariableAccess).getLocation().isBefore(target_5.getOperand().(VariableAccess).getLocation()))
}

predicate func_5(Variable vsamepagedevice_261, NotExpr target_5) {
		target_5.getOperand().(VariableAccess).getTarget()=vsamepagedevice_261
}

predicate func_8(Function func, ReturnStmt target_8) {
		target_8.getExpr() instanceof NotExpr
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8
}

predicate func_9(EqualityOperation target_9) {
		target_9.getAnOperand().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("gx_device *")
		and target_9.getAnOperand().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getTarget().getName()="get_page_device"
		and target_9.getAnOperand().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_9.getAnOperand().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("gx_device *")
		and target_9.getAnOperand().(AssignExpr).getRValue().(ExprCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("gx_device *")
		and target_9.getAnOperand().(Literal).getValue()="0"
}

predicate func_10(Variable vsamepagedevice_261, NotExpr target_10) {
		target_10.getOperand().(VariableAccess).getTarget()=vsamepagedevice_261
}

predicate func_11(EqualityOperation target_11) {
		target_11.getAnOperand().(VariableAccess).getTarget().getType().hasName("gx_device *")
		and target_11.getAnOperand().(VariableAccess).getTarget().getType().hasName("gx_device *")
}

from Function func, Variable vsamepagedevice_261, NotExpr target_5, ReturnStmt target_8, EqualityOperation target_9, NotExpr target_10, EqualityOperation target_11
where
not func_0(vsamepagedevice_261, target_9, target_10)
and not func_1(vsamepagedevice_261, target_11)
and not func_2(func)
and not func_4(vsamepagedevice_261, target_5)
and func_5(vsamepagedevice_261, target_5)
and func_8(func, target_8)
and func_9(target_9)
and func_10(vsamepagedevice_261, target_10)
and func_11(target_11)
and vsamepagedevice_261.getType().hasName("bool")
and vsamepagedevice_261.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
