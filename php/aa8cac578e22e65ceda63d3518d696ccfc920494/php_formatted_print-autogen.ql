/**
 * @name php-aa8cac578e22e65ceda63d3518d696ccfc920494-php_formatted_print
 * @id cpp/php/aa8cac578e22e65ceda63d3518d696ccfc920494/php-formatted-print
 * @description php-aa8cac578e22e65ceda63d3518d696ccfc920494-ext/standard/formatted_print.c-php_formatted_print CVE-2015-8880
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnewargs_388, RelationalOperation target_2, ExprStmt target_3, IfStmt target_4, IfStmt target_0) {
		target_0.getCondition().(VariableAccess).getTarget()=vnewargs_388
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_efree")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnewargs_388
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(VariableAccess).getLocation())
		and target_0.getCondition().(VariableAccess).getLocation().isBefore(target_4.getCondition().(VariableAccess).getLocation())
}

predicate func_1(Variable vnewargs_388, RelationalOperation target_5, ExprStmt target_6, IfStmt target_7, IfStmt target_1) {
		target_1.getCondition().(VariableAccess).getTarget()=vnewargs_388
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_efree")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnewargs_388
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getCondition().(VariableAccess).getLocation())
		and target_1.getCondition().(VariableAccess).getLocation().isBefore(target_7.getCondition().(VariableAccess).getLocation())
}

predicate func_2(RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("php_sprintf_getnumber")
		and target_2.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("char *")
		and target_2.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("size_t")
		and target_2.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_3(Variable vnewargs_388, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("_efree")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnewargs_388
}

predicate func_4(Variable vnewargs_388, IfStmt target_4) {
		target_4.getCondition().(VariableAccess).getTarget()=vnewargs_388
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_efree")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnewargs_388
}

predicate func_5(RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_5.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("php_sprintf_getnumber")
		and target_5.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("char *")
		and target_5.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("size_t")
		and target_5.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_6(Variable vnewargs_388, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("_efree")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnewargs_388
}

predicate func_7(Variable vnewargs_388, IfStmt target_7) {
		target_7.getCondition().(VariableAccess).getTarget()=vnewargs_388
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_efree")
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnewargs_388
}

from Function func, Variable vnewargs_388, IfStmt target_0, IfStmt target_1, RelationalOperation target_2, ExprStmt target_3, IfStmt target_4, RelationalOperation target_5, ExprStmt target_6, IfStmt target_7
where
func_0(vnewargs_388, target_2, target_3, target_4, target_0)
and func_1(vnewargs_388, target_5, target_6, target_7, target_1)
and func_2(target_2)
and func_3(vnewargs_388, target_3)
and func_4(vnewargs_388, target_4)
and func_5(target_5)
and func_6(vnewargs_388, target_6)
and func_7(vnewargs_388, target_7)
and vnewargs_388.getType().hasName("zval *")
and vnewargs_388.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
