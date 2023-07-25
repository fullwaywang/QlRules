/**
 * @name libyang-6cc51b1757dfbb7cff92de074ada65e8523289a6-yyparse
 * @id cpp/libyang/6cc51b1757dfbb7cff92de074ada65e8523289a6/yyparse
 * @description libyang-6cc51b1757dfbb7cff92de074ada65e8523289a6-src/parser_yang_bis.c-yyparse CVE-2019-20394
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="7092"
		and not target_0.getValue()="7093"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ly_log")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ctx"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Internal error (%s:%d)."
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="/opt/project/build/cloned/libyang/src/parser_yang_bis.c"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="7839"
		and not target_1.getValue()="7840"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ly_log")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ctx"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Internal error (%s:%d)."
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="/opt/project/build/cloned/libyang/src/parser_yang_bis.c"
		and target_1.getEnclosingFunction() = func
}

predicate func_3(Variable vs_2785, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vs_2785
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_4(Variable vs_2785, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vs_2785
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_5(Variable vs_2785, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vs_2785
		and target_5.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_6(Variable vs_2785, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vs_2785
		and target_6.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_7(Variable vs_2785, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vs_2785
		and target_7.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_8(Variable vs_2785, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vs_2785
		and target_8.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_9(Variable vs_2785, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vs_2785
		and target_9.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Variable vs_2785, Literal target_0, Literal target_1, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, ExprStmt target_9
where
func_0(func, target_0)
and func_1(func, target_1)
and func_3(vs_2785, target_3)
and func_4(vs_2785, target_4)
and func_5(vs_2785, target_5)
and func_6(vs_2785, target_6)
and func_7(vs_2785, target_7)
and func_8(vs_2785, target_8)
and func_9(vs_2785, target_9)
and vs_2785.getType().hasName("char *")
and vs_2785.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
