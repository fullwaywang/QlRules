/**
 * @name varnish-0f0e51e9871ed1bd1236378f8b0dea0d33df4e9e-http_Proto
 * @id cpp/varnish/0f0e51e9871ed1bd1236378f8b0dea0d33df4e9e/http-Proto
 * @description varnish-0f0e51e9871ed1bd1236378f8b0dea0d33df4e9e-bin/varnishd/cache/cache_http.c-http_Proto CVE-2019-15892
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfm_231, ExprStmt target_2, LogicalAndExpr target_3) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vfm_231
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand() instanceof LogicalOrExpr
		and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_1(Variable vfm_231, LogicalOrExpr target_1) {
		target_1.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vfm_231
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="72"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vfm_231
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="104"
}

predicate func_2(Variable vfm_231, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfm_231
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="b"
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="hd"
}

predicate func_3(Variable vfm_231, LogicalAndExpr target_3) {
		target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="47"
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("vct_is")
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vfm_231
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="5"
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getValue()="32"
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vfm_231
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="6"
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="46"
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("vct_is")
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vfm_231
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="7"
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getValue()="32"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vfm_231
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="8"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
}

from Function func, Variable vfm_231, LogicalOrExpr target_1, ExprStmt target_2, LogicalAndExpr target_3
where
not func_0(vfm_231, target_2, target_3)
and func_1(vfm_231, target_1)
and func_2(vfm_231, target_2)
and func_3(vfm_231, target_3)
and vfm_231.getType().hasName("const char *")
and vfm_231.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
