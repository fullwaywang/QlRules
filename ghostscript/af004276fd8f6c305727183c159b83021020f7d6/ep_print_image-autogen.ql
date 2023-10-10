/**
 * @name ghostscript-af004276fd8f6c305727183c159b83021020f7d6-ep_print_image
 * @id cpp/ghostscript/af004276fd8f6c305727183c159b83021020f7d6/ep-print-image
 * @description ghostscript-af004276fd8f6c305727183c159b83021020f7d6-devices/gdevcdj.c-ep_print_image CVE-2020-16308
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vp3_1931, Variable voutp_1932, ExprStmt target_2, FunctionCall target_1, RelationalOperation target_3, LogicalAndExpr target_4) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vp3_1931
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=voutp_1932
		and target_0.getAnOperand() instanceof FunctionCall
		and target_0.getParent().(ForStmt).getStmt() instanceof EmptyStmt
		and target_2.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(VariableAccess).getLocation())
		and target_3.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vimg_rows_1930, Variable vp3_1931, Variable vzeros_1963, FunctionCall target_1) {
		target_1.getTarget().hasName("memcmp")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vp3_1931
		and target_1.getArgument(1).(VariableAccess).getTarget()=vzeros_1963
		and target_1.getArgument(2).(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vimg_rows_1930
		and target_1.getArgument(2).(DivExpr).getRightOperand().(Literal).getValue()="8"
		and target_1.getParent().(ForStmt).getStmt() instanceof EmptyStmt
}

predicate func_2(Variable vimg_rows_1930, Variable vp3_1931, ExprStmt target_2) {
		target_2.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vp3_1931
		and target_2.getExpr().(AssignPointerAddExpr).getRValue().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vimg_rows_1930
		and target_2.getExpr().(AssignPointerAddExpr).getRValue().(DivExpr).getRightOperand().(Literal).getValue()="8"
}

predicate func_3(Variable vp3_1931, Variable voutp_1932, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vp3_1931
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=voutp_1932
}

predicate func_4(Variable vimg_rows_1930, Variable vp3_1931, Variable voutp_1932, Variable vzeros_1963, LogicalAndExpr target_4) {
		target_4.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vp3_1931
		and target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=voutp_1932
		and target_4.getAnOperand().(FunctionCall).getTarget().hasName("memcmp")
		and target_4.getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp3_1931
		and target_4.getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vimg_rows_1930
		and target_4.getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(DivExpr).getRightOperand().(Literal).getValue()="8"
		and target_4.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vzeros_1963
		and target_4.getAnOperand().(FunctionCall).getArgument(2).(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vimg_rows_1930
		and target_4.getAnOperand().(FunctionCall).getArgument(2).(DivExpr).getRightOperand().(Literal).getValue()="8"
}

from Function func, Variable vimg_rows_1930, Variable vp3_1931, Variable voutp_1932, Variable vzeros_1963, FunctionCall target_1, ExprStmt target_2, RelationalOperation target_3, LogicalAndExpr target_4
where
not func_0(vp3_1931, voutp_1932, target_2, target_1, target_3, target_4)
and func_1(vimg_rows_1930, vp3_1931, vzeros_1963, target_1)
and func_2(vimg_rows_1930, vp3_1931, target_2)
and func_3(vp3_1931, voutp_1932, target_3)
and func_4(vimg_rows_1930, vp3_1931, voutp_1932, vzeros_1963, target_4)
and vimg_rows_1930.getType().hasName("int")
and vp3_1931.getType().hasName("byte *")
and voutp_1932.getType().hasName("byte *")
and vzeros_1963.getType().hasName("const word[8]")
and vimg_rows_1930.(LocalVariable).getFunction() = func
and vp3_1931.(LocalVariable).getFunction() = func
and voutp_1932.(LocalVariable).getFunction() = func
and vzeros_1963.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
