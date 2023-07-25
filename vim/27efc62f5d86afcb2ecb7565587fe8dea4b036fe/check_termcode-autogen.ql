/**
 * @name vim-27efc62f5d86afcb2ecb7565587fe8dea4b036fe-check_termcode
 * @id cpp/vim/27efc62f5d86afcb2ecb7565587fe8dea4b036fe/check-termcode
 * @description vim-27efc62f5d86afcb2ecb7565587fe8dea4b036fe-src/term.c-check_termcode CVE-2022-2285
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtp_5318, Variable vlen_5322, LogicalAndExpr target_1, EqualityOperation target_2, ExprStmt target_3, RelationalOperation target_4) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vtp_5318
		and target_0.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vlen_5322
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_4.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vtp_5318, LogicalAndExpr target_1) {
		target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtp_5318
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="27"
		and target_1.getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="16"
}

predicate func_2(Variable vtp_5318, EqualityOperation target_2) {
		target_2.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtp_5318
		and target_2.getAnOperand().(Literal).getValue()="155"
}

predicate func_3(Variable vlen_5322, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_5322
}

predicate func_4(Variable vlen_5322, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getLesserOperand().(VariableAccess).getTarget()=vlen_5322
		and target_4.getGreaterOperand().(Literal).getValue()="3"
}

from Function func, Variable vtp_5318, Variable vlen_5322, LogicalAndExpr target_1, EqualityOperation target_2, ExprStmt target_3, RelationalOperation target_4
where
not func_0(vtp_5318, vlen_5322, target_1, target_2, target_3, target_4)
and func_1(vtp_5318, target_1)
and func_2(vtp_5318, target_2)
and func_3(vlen_5322, target_3)
and func_4(vlen_5322, target_4)
and vtp_5318.getType().hasName("char_u *")
and vlen_5322.getType().hasName("int")
and vtp_5318.getParentScope+() = func
and vlen_5322.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
