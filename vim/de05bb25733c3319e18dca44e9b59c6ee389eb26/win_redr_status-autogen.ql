/**
 * @name vim-de05bb25733c3319e18dca44e9b59c6ee389eb26-win_redr_status
 * @id cpp/vim/de05bb25733c3319e18dca44e9b59c6ee389eb26/win-redr-status
 * @description vim-de05bb25733c3319e18dca44e9b59c6ee389eb26-src/drawscreen.c-win_redr_status CVE-2022-0213
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlen_422, ExprStmt target_2, ExprStmt target_3) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof LogicalOrExpr
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlen_422
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getValue()="4095"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vwp_418, ExprStmt target_2, LogicalOrExpr target_1) {
		target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("bt_help")
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="w_buffer"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwp_418
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="wo_pvw"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_onebuf_opt"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwp_418
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("bufIsChanged")
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="w_buffer"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwp_418
		and target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="b_p_ro"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_buffer"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwp_418
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vlen_422, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vlen_422
		and target_2.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="32"
}

predicate func_3(Variable vlen_422, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_422
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strlen")
}

from Function func, Variable vlen_422, Parameter vwp_418, LogicalOrExpr target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vlen_422, target_2, target_3)
and func_1(vwp_418, target_2, target_1)
and func_2(vlen_422, target_2)
and func_3(vlen_422, target_3)
and vlen_422.getType().hasName("int")
and vwp_418.getType().hasName("win_T *")
and vlen_422.getParentScope+() = func
and vwp_418.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
