/**
 * @name vim-c32949b0779106ed5710ae3bffc5053e49083ab4-msg_puts_printf
 * @id cpp/vim/c32949b0779106ed5710ae3bffc5053e49083ab4/msg-puts-printf
 * @description vim-c32949b0779106ed5710ae3bffc5053e49083ab4-src/message.c-msg_puts_printf CVE-2023-0051
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vp_3001, FunctionCall target_0) {
		target_0.getTarget().hasName("strlen")
		and not target_0.getTarget().hasName("vim_strlen_maxlen")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vp_3001
}

predicate func_1(Parameter vmaxlen_2997, Variable vp_3001, BlockStmt target_5, LogicalAndExpr target_6, ExprStmt target_7, LogicalAndExpr target_8) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GEExpr or target_1 instanceof LEExpr)
		and target_1.getGreaterOperand().(FunctionCall).getTarget().hasName("vim_strlen_maxlen")
		and target_1.getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_3001
		and target_1.getGreaterOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmaxlen_2997
		and target_1.getLesserOperand().(VariableAccess).getTarget()=vmaxlen_2997
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vmaxlen_2997
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_1.getParent().(LogicalAndExpr).getAnOperand() instanceof RelationalOperation
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_5
		and target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getGreaterOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_1.getGreaterOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_1.getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(Parameter vmaxlen_2997, VariableAccess target_3) {
		target_3.getTarget()=vmaxlen_2997
}

predicate func_4(Parameter vmaxlen_2997, BlockStmt target_5, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getGreaterOperand() instanceof FunctionCall
		and target_4.getLesserOperand().(VariableAccess).getTarget()=vmaxlen_2997
		and target_4.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vmaxlen_2997
		and target_4.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_4.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_5
}

predicate func_5(Parameter vmaxlen_2997, Variable vp_3001, BlockStmt target_5) {
		target_5.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("vim_strnsave")
		and target_5.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_3001
		and target_5.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmaxlen_2997
		and target_5.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_3001
}

predicate func_6(Parameter vmaxlen_2997, LogicalAndExpr target_6) {
		target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vmaxlen_2997
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_6.getAnOperand() instanceof RelationalOperation
}

predicate func_7(Parameter vmaxlen_2997, Variable vp_3001, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("vim_strnsave")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_3001
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmaxlen_2997
}

predicate func_8(Variable vp_3001, LogicalAndExpr target_8) {
		target_8.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_3001
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getAnOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vmaxlen_2997, Variable vp_3001, FunctionCall target_0, VariableAccess target_3, RelationalOperation target_4, BlockStmt target_5, LogicalAndExpr target_6, ExprStmt target_7, LogicalAndExpr target_8
where
func_0(vp_3001, target_0)
and not func_1(vmaxlen_2997, vp_3001, target_5, target_6, target_7, target_8)
and func_3(vmaxlen_2997, target_3)
and func_4(vmaxlen_2997, target_5, target_4)
and func_5(vmaxlen_2997, vp_3001, target_5)
and func_6(vmaxlen_2997, target_6)
and func_7(vmaxlen_2997, vp_3001, target_7)
and func_8(vp_3001, target_8)
and vmaxlen_2997.getType().hasName("int")
and vp_3001.getType().hasName("char_u *")
and vmaxlen_2997.getParentScope+() = func
and vp_3001.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
