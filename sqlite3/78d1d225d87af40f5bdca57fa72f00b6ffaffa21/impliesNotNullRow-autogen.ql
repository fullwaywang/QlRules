/**
 * @name sqlite3-78d1d225d87af40f5bdca57fa72f00b6ffaffa21-impliesNotNullRow
 * @id cpp/sqlite3/78d1d225d87af40f5bdca57fa72f00b6ffaffa21/impliesNotNullRow
 * @description sqlite3-78d1d225d87af40f5bdca57fa72f00b6ffaffa21-src/expr.c-impliesNotNullRow CVE-2020-9327
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(BlockStmt target_12, Function func) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="op"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("Expr *")
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="164"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="pTab"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="y"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("Expr *")
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="nModuleArg"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="pTab"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="y"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("Expr *")
		and target_0.getParent().(LogicalOrExpr).getAnOperand() instanceof FunctionCall
		and target_0.getParent().(LogicalOrExpr).getAnOperand() instanceof FunctionCall
		and target_0.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_12
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(BlockStmt target_12, Function func) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="op"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("Expr *")
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="164"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="pTab"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="y"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("Expr *")
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="nModuleArg"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="pTab"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="y"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("Expr *")
		and target_1.getParent().(LogicalOrExpr).getAnOperand() instanceof FunctionCall
		and target_1.getParent().(LogicalOrExpr).getAnOperand() instanceof FunctionCall
		and target_1.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_12
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vpExpr_5426, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="pLeft"
		and target_2.getQualifier().(VariableAccess).getTarget()=vpExpr_5426
		and target_2.getParent().(FunctionCall).getParent().(LogicalOrExpr).getAnOperand() instanceof FunctionCall
}

predicate func_3(Parameter vpExpr_5426, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="pRight"
		and target_3.getQualifier().(VariableAccess).getTarget()=vpExpr_5426
		and target_3.getParent().(FunctionCall).getParent().(LogicalOrExpr).getAnOperand() instanceof FunctionCall
}

predicate func_4(PointerFieldAccess target_13, Function func, EmptyStmt target_4) {
		target_4.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_13
		and target_4.getEnclosingFunction() = func
}

predicate func_5(PointerFieldAccess target_13, Function func, EmptyStmt target_5) {
		target_5.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_13
		and target_5.getEnclosingFunction() = func
}

predicate func_6(PointerFieldAccess target_13, Function func, EmptyStmt target_6) {
		target_6.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_13
		and target_6.getEnclosingFunction() = func
}

predicate func_7(PointerFieldAccess target_13, Function func, EmptyStmt target_7) {
		target_7.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_13
		and target_7.getEnclosingFunction() = func
}

predicate func_8(PointerFieldAccess target_13, Function func, EmptyStmt target_8) {
		target_8.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_13
		and target_8.getEnclosingFunction() = func
}

predicate func_9(PointerFieldAccess target_13, Function func, EmptyStmt target_9) {
		target_9.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_13
		and target_9.getEnclosingFunction() = func
}

predicate func_10(Parameter vpExpr_5426, BlockStmt target_12, FunctionCall target_10) {
		target_10.getTarget().hasName("sqlite3ExprIsVtabRef")
		and target_10.getArgument(0).(PointerFieldAccess).getTarget().getName()="pLeft"
		and target_10.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpExpr_5426
		and target_10.getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("sqlite3ExprIsVtabRef")
		and target_10.getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pRight"
		and target_10.getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpExpr_5426
		and target_10.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_12
}

/*predicate func_11(Parameter vpExpr_5426, BlockStmt target_12, FunctionCall target_11) {
		target_11.getTarget().hasName("sqlite3ExprIsVtabRef")
		and target_11.getArgument(0).(PointerFieldAccess).getTarget().getName()="pRight"
		and target_11.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpExpr_5426
		and target_11.getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("sqlite3ExprIsVtabRef")
		and target_11.getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pLeft"
		and target_11.getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpExpr_5426
		and target_11.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_12
}

*/
predicate func_12(BlockStmt target_12) {
		target_12.getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="1"
}

predicate func_13(Parameter vpExpr_5426, PointerFieldAccess target_13) {
		target_13.getTarget().getName()="op"
		and target_13.getQualifier().(VariableAccess).getTarget()=vpExpr_5426
}

from Function func, Parameter vpExpr_5426, PointerFieldAccess target_2, PointerFieldAccess target_3, EmptyStmt target_4, EmptyStmt target_5, EmptyStmt target_6, EmptyStmt target_7, EmptyStmt target_8, EmptyStmt target_9, FunctionCall target_10, BlockStmt target_12, PointerFieldAccess target_13
where
not func_0(target_12, func)
and not func_1(target_12, func)
and func_2(vpExpr_5426, target_2)
and func_3(vpExpr_5426, target_3)
and func_4(target_13, func, target_4)
and func_5(target_13, func, target_5)
and func_6(target_13, func, target_6)
and func_7(target_13, func, target_7)
and func_8(target_13, func, target_8)
and func_9(target_13, func, target_9)
and func_10(vpExpr_5426, target_12, target_10)
and func_12(target_12)
and func_13(vpExpr_5426, target_13)
and vpExpr_5426.getType().hasName("Expr *")
and vpExpr_5426.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
