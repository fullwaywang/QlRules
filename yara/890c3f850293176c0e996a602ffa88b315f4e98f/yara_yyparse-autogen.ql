/**
 * @name yara-890c3f850293176c0e996a602ffa88b315f4e98f-yara_yyparse
 * @id cpp/yara/890c3f850293176c0e996a602ffa88b315f4e98f/yara-yyparse
 * @description yara-890c3f850293176c0e996a602ffa88b315f4e98f-libyara/grammar.c-yara_yyparse CVE-2016-10211
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="408"
		and not target_0.getValue()="406"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="88"
		and not target_1.getValue()="87"
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, Literal target_2) {
		target_2.getValue()="91"
		and not target_2.getValue()="89"
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Function func, Literal target_3) {
		target_3.getValue()="94"
		and not target_3.getValue()="93"
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Function func, Literal target_4) {
		target_4.getValue()="408"
		and not target_4.getValue()="406"
		and target_4.getEnclosingFunction() = func
}

predicate func_5(Function func, Literal target_5) {
		target_5.getValue()="408"
		and not target_5.getValue()="406"
		and target_5.getEnclosingFunction() = func
}

predicate func_6(Parameter vcompiler_1404, ExprStmt target_10) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(PostfixDecrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="loop_depth"
		and target_6.getExpr().(PostfixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcompiler_1404
		and target_10.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_6.getExpr().(PostfixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_7(Parameter vcompiler_1404, EqualityOperation target_11) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="loop_identifier"
		and target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcompiler_1404
		and target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="loop_depth"
		and target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcompiler_1404
		and target_7.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_8(Function func) {
	exists(SwitchCase target_8 |
		target_8.getExpr().(Literal).getValue()="122"
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(VariableAccess target_12, Function func) {
	exists(BreakStmt target_9 |
		target_9.toString() = "break;"
		and target_9.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_12
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Parameter vcompiler_1404, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("yara_yyerror")
		and target_10.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcompiler_1404
		and target_10.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_11(Parameter vcompiler_1404, EqualityOperation target_11) {
		target_11.getAnOperand().(PointerFieldAccess).getTarget().getName()="loop_depth"
		and target_11.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcompiler_1404
		and target_11.getAnOperand().(Literal).getValue()="4"
}

predicate func_12(Variable vyyn_1442, VariableAccess target_12) {
		target_12.getTarget()=vyyn_1442
}

from Function func, Parameter vcompiler_1404, Variable vyyn_1442, Literal target_0, Literal target_1, Literal target_2, Literal target_3, Literal target_4, Literal target_5, ExprStmt target_10, EqualityOperation target_11, VariableAccess target_12
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
and func_3(func, target_3)
and func_4(func, target_4)
and func_5(func, target_5)
and not func_6(vcompiler_1404, target_10)
and not func_7(vcompiler_1404, target_11)
and not func_8(func)
and not func_9(target_12, func)
and func_10(vcompiler_1404, target_10)
and func_11(vcompiler_1404, target_11)
and func_12(vyyn_1442, target_12)
and vcompiler_1404.getType().hasName("YR_COMPILER *")
and vyyn_1442.getType().hasName("int")
and vcompiler_1404.getParentScope+() = func
and vyyn_1442.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
