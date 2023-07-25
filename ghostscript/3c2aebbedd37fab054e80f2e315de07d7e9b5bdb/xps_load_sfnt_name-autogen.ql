/**
 * @name ghostscript-3c2aebbedd37fab054e80f2e315de07d7e9b5bdb-xps_load_sfnt_name
 * @id cpp/ghostscript/3c2aebbedd37fab054e80f2e315de07d7e9b5bdb/xps-load-sfnt-name
 * @description ghostscript-3c2aebbedd37fab054e80f2e315de07d7e9b5bdb-xps/xpsfont.c-xps_load_sfnt_name CVE-2017-9618
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlength_169, ExprStmt target_1, ExprStmt target_2) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlength_169
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlength_169
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getType().hasName("int")
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(SubExpr).getLeftOperand().(VariableAccess).getType().hasName("int")
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(VariableAccess).getTarget()=vlength_169
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_1(Variable vlength_169, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlength_169
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("u16")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("byte *")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="8"
}

predicate func_2(Variable vlength_169, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("char *")
		and target_2.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("byte *")
		and target_2.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlength_169
}

from Function func, Variable vlength_169, ExprStmt target_1, ExprStmt target_2
where
not func_0(vlength_169, target_1, target_2)
and func_1(vlength_169, target_1)
and func_2(vlength_169, target_2)
and vlength_169.getType().hasName("int")
and vlength_169.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
