/**
 * @name freerdp-e7bffa64ef5ed70bac94f823e2b95262642f5296-update_recv_secondary_order
 * @id cpp/freerdp/e7bffa64ef5ed70bac94f823e2b95262642f5296/update-recv-secondary-order
 * @description freerdp-e7bffa64ef5ed70bac94f823e2b95262642f5296-libfreerdp/core/orders.c-update_recv_secondary_order CVE-2020-4032
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vstart_3608, SubExpr target_6, VariableAccess target_0) {
		target_0.getTarget()=vstart_3608
		and target_6.getRightOperand().(VariableAccess).getLocation().isBefore(target_0.getLocation())
}

predicate func_1(Variable vend_3608, SubExpr target_6, VariableAccess target_1) {
		target_1.getTarget()=vend_3608
		and target_6.getLeftOperand().(VariableAccess).getLocation().isBefore(target_1.getLocation())
}

predicate func_2(Variable vdiff_3608, Parameter vs_3605, RelationalOperation target_7, ExprStmt target_8, ExprStmt target_9) {
	exists(IfStmt target_2 |
		target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("Stream_SafeSeek")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_3605
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdiff_3608
		and target_2.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_8.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getLocation().isBefore(target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(Parameter vs_3605, VariableAccess target_3) {
		target_3.getTarget()=vs_3605
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_4(Variable vdiff_3608, VariableAccess target_4) {
		target_4.getTarget()=vdiff_3608
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_5(Variable vdiff_3608, Parameter vs_3605, RelationalOperation target_7, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_3605
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdiff_3608
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
}

predicate func_6(Variable vstart_3608, Variable vend_3608, SubExpr target_6) {
		target_6.getLeftOperand().(VariableAccess).getTarget()=vend_3608
		and target_6.getRightOperand().(VariableAccess).getTarget()=vstart_3608
}

predicate func_7(Variable vdiff_3608, RelationalOperation target_7) {
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getGreaterOperand().(VariableAccess).getTarget()=vdiff_3608
		and target_7.getLesserOperand().(Literal).getValue()="0"
}

predicate func_8(Variable vdiff_3608, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("WLog_PrintMessage")
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_8.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_8.getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_8.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_8.getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_8.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="SECONDARY_ORDER %s: read %zubytes short, skipping"
		and target_8.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vdiff_3608
}

predicate func_9(Parameter vs_3605, Variable vend_3608, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vend_3608
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Stream_GetPosition")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_3605
}

from Function func, Variable vdiff_3608, Parameter vs_3605, Variable vstart_3608, Variable vend_3608, VariableAccess target_0, VariableAccess target_1, VariableAccess target_3, VariableAccess target_4, ExprStmt target_5, SubExpr target_6, RelationalOperation target_7, ExprStmt target_8, ExprStmt target_9
where
func_0(vstart_3608, target_6, target_0)
and func_1(vend_3608, target_6, target_1)
and not func_2(vdiff_3608, vs_3605, target_7, target_8, target_9)
and func_3(vs_3605, target_3)
and func_4(vdiff_3608, target_4)
and func_5(vdiff_3608, vs_3605, target_7, target_5)
and func_6(vstart_3608, vend_3608, target_6)
and func_7(vdiff_3608, target_7)
and func_8(vdiff_3608, target_8)
and func_9(vs_3605, vend_3608, target_9)
and vdiff_3608.getType().hasName("size_t")
and vs_3605.getType().hasName("wStream *")
and vstart_3608.getType().hasName("size_t")
and vend_3608.getType().hasName("size_t")
and vdiff_3608.getParentScope+() = func
and vs_3605.getParentScope+() = func
and vstart_3608.getParentScope+() = func
and vend_3608.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
