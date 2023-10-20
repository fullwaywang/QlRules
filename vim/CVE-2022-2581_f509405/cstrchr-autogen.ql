/**
 * @name vim-f50940531dd57135fe60aa393ac9d3281f352d88-cstrchr
 * @id cpp/vim/f50940531dd57135fe60aa393ac9d3281f352d88/cstrchr
 * @description vim-f50940531dd57135fe60aa393ac9d3281f352d88-src/regexp.c-cstrchr CVE-2022-2581
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vp_1619, Variable vcc_1620, ReturnStmt target_3, AssignPointerAddExpr target_4, FunctionCall target_2, ExprStmt target_5, LogicalOrExpr target_6) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(HexLiteral).getValue()="128"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_1619
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("utf_fold")
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("int")
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcc_1620
		and target_0.getParent().(IfStmt).getThen()=target_3
		and target_4.getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_2.getArgument(0).(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vp_1619, FunctionCall target_2) {
		target_2.getTarget().hasName("utf_ptr2char")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vp_1619
}

predicate func_3(Variable vp_1619, ReturnStmt target_3) {
		target_3.getExpr().(VariableAccess).getTarget()=vp_1619
}

predicate func_4(Variable vp_1619, AssignPointerAddExpr target_4) {
		target_4.getLValue().(VariableAccess).getTarget()=vp_1619
		and target_4.getRValue().(ExprCall).getArgument(0).(VariableAccess).getTarget()=vp_1619
}

predicate func_5(Variable vcc_1620, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcc_1620
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("vim_toupper")
}

predicate func_6(Variable vp_1619, Variable vcc_1620, LogicalOrExpr target_6) {
		target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_1619
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_1619
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcc_1620
}

from Function func, Variable vp_1619, Variable vcc_1620, FunctionCall target_2, ReturnStmt target_3, AssignPointerAddExpr target_4, ExprStmt target_5, LogicalOrExpr target_6
where
not func_0(vp_1619, vcc_1620, target_3, target_4, target_2, target_5, target_6)
and func_2(vp_1619, target_2)
and func_3(vp_1619, target_3)
and func_4(vp_1619, target_4)
and func_5(vcc_1620, target_5)
and func_6(vp_1619, vcc_1620, target_6)
and vp_1619.getType().hasName("char_u *")
and vcc_1620.getType().hasName("int")
and vp_1619.getParentScope+() = func
and vcc_1620.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
