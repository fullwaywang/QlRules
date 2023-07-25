/**
 * @name sqlite3-bf48ce49f7c25e5d4524de9fdc5c0d505218d06d-impliesNotNullRow
 * @id cpp/sqlite3/bf48ce49f7c25e5d4524de9fdc5c0d505218d06d/impliesNotNullRow
 * @description sqlite3-bf48ce49f7c25e5d4524de9fdc5c0d505218d06d-src/expr.c-impliesNotNullRow CVE-2020-9327
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpExpr_5417, BlockStmt target_6, EqualityOperation target_7) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("sqlite3ExprIsVtabRef")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="pLeft"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpExpr_5417
		and target_0.getParent().(LogicalOrExpr).getAnOperand() instanceof LogicalAndExpr
		and target_0.getParent().(LogicalOrExpr).getAnOperand() instanceof LogicalAndExpr
		and target_0.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_6
		and target_7.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpExpr_5417, BlockStmt target_6, PointerFieldAccess target_8) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("sqlite3ExprIsVtabRef")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="pRight"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpExpr_5417
		and target_1.getParent().(LogicalOrExpr).getAnOperand() instanceof LogicalAndExpr
		and target_1.getParent().(LogicalOrExpr).getAnOperand() instanceof LogicalAndExpr
		and target_1.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_6
		and target_8.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vpExpr_5417, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="pLeft"
		and target_2.getQualifier().(VariableAccess).getTarget()=vpExpr_5417
}

predicate func_3(Parameter vpExpr_5417, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="pRight"
		and target_3.getQualifier().(VariableAccess).getTarget()=vpExpr_5417
}

predicate func_4(Parameter vpExpr_5417, BlockStmt target_6, LogicalAndExpr target_4) {
		target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="op"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pLeft"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpExpr_5417
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="164"
		and target_4.getAnOperand().(PointerFieldAccess).getTarget().getName()="nModuleArg"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="pTab"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="y"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pLeft"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpExpr_5417
		and target_4.getParent().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="op"
		and target_4.getParent().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pRight"
		and target_4.getParent().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpExpr_5417
		and target_4.getParent().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="164"
		and target_4.getParent().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="nModuleArg"
		and target_4.getParent().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="pTab"
		and target_4.getParent().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="y"
		and target_4.getParent().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pRight"
		and target_4.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_6
}

/*predicate func_5(Parameter vpExpr_5417, BlockStmt target_6, LogicalAndExpr target_5) {
		target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="op"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pRight"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpExpr_5417
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="164"
		and target_5.getAnOperand().(PointerFieldAccess).getTarget().getName()="nModuleArg"
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="pTab"
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="y"
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pRight"
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpExpr_5417
		and target_5.getParent().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="op"
		and target_5.getParent().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pLeft"
		and target_5.getParent().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpExpr_5417
		and target_5.getParent().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="164"
		and target_5.getParent().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="nModuleArg"
		and target_5.getParent().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="pTab"
		and target_5.getParent().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="y"
		and target_5.getParent().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pLeft"
		and target_5.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_6
}

*/
predicate func_6(BlockStmt target_6) {
		target_6.getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="1"
}

predicate func_7(Parameter vpExpr_5417, EqualityOperation target_7) {
		target_7.getAnOperand().(FunctionCall).getTarget().hasName("sqlite3WalkExpr")
		and target_7.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("Walker *")
		and target_7.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="pLeft"
		and target_7.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpExpr_5417
		and target_7.getAnOperand().(Literal).getValue()="2"
}

predicate func_8(Parameter vpExpr_5417, PointerFieldAccess target_8) {
		target_8.getTarget().getName()="y"
		and target_8.getQualifier().(PointerFieldAccess).getTarget().getName()="pLeft"
		and target_8.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpExpr_5417
}

from Function func, Parameter vpExpr_5417, PointerFieldAccess target_2, PointerFieldAccess target_3, LogicalAndExpr target_4, BlockStmt target_6, EqualityOperation target_7, PointerFieldAccess target_8
where
not func_0(vpExpr_5417, target_6, target_7)
and not func_1(vpExpr_5417, target_6, target_8)
and func_2(vpExpr_5417, target_2)
and func_3(vpExpr_5417, target_3)
and func_4(vpExpr_5417, target_6, target_4)
and func_6(target_6)
and func_7(vpExpr_5417, target_7)
and func_8(vpExpr_5417, target_8)
and vpExpr_5417.getType().hasName("Expr *")
and vpExpr_5417.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
