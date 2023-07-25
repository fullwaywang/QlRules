/**
 * @name imagemagick-dd84447b63a71fa8c3f47071b09454efc667767b-Get8BIMProperty
 * @id cpp/imagemagick/dd84447b63a71fa8c3f47071b09454efc667767b/Get8BIMProperty
 * @description imagemagick-dd84447b63a71fa8c3f47071b09454efc667767b-MagickCore/property.c-Get8BIMProperty CVE-2016-6491
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlength_605, Variable vcount_608, AddressOfExpr target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcount_608
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcount_608
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlength_605
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlength_605
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(ContinueStmt).toString() = "continue;"
		and target_1.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_1(Variable vlength_605, AddressOfExpr target_1) {
		target_1.getOperand().(VariableAccess).getTarget()=vlength_605
}

predicate func_2(Variable vlength_605, Variable vcount_608, ExprStmt target_2) {
		target_2.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vlength_605
		and target_2.getExpr().(AssignSubExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcount_608
		and target_2.getExpr().(AssignSubExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlength_605
		and target_2.getExpr().(AssignSubExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vcount_608
		and target_2.getExpr().(AssignSubExpr).getRValue().(ConditionalExpr).getElse().(VariableAccess).getTarget()=vlength_605
}

predicate func_3(Variable vlength_605, Variable vcount_608, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcount_608
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ReadPropertyMSBLong")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vlength_605
}

predicate func_4(Variable vcount_608, ExprStmt target_4) {
		target_4.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vcount_608
}

from Function func, Variable vlength_605, Variable vcount_608, AddressOfExpr target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vlength_605, vcount_608, target_1, target_2, target_3, target_4)
and func_1(vlength_605, target_1)
and func_2(vlength_605, vcount_608, target_2)
and func_3(vlength_605, vcount_608, target_3)
and func_4(vcount_608, target_4)
and vlength_605.getType().hasName("size_t")
and vcount_608.getType().hasName("ssize_t")
and vlength_605.getParentScope+() = func
and vcount_608.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
