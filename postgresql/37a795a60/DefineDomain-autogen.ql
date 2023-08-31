/**
 * @name postgresql-37a795a60-DefineDomain
 * @id cpp/postgresql/37a795a60/DefineDomain
 * @description postgresql-37a795a60-src/backend/commands/typecmds.c-DefineDomain CVE-2017-15098
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="100"
		and not target_0.getValue()="99"
		and target_0.getParent().(NEExpr).getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="101"
		and not target_1.getValue()="100"
		and target_1.getParent().(NEExpr).getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, Literal target_2) {
		target_2.getValue()="114"
		and not target_2.getValue()="101"
		and target_2.getParent().(NEExpr).getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Variable vtyptype_746, DoStmt target_8, ExprStmt target_9, LogicalAndExpr target_10) {
	exists(LogicalAndExpr target_3 |
		target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtyptype_746
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="98"
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtyptype_746
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="99"
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_3.getAnOperand() instanceof EqualityOperation
		and target_3.getParent().(IfStmt).getThen()=target_8
		and target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_10.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

/*predicate func_4(Variable vtyptype_746, LogicalAndExpr target_10) {
	exists(EqualityOperation target_4 |
		target_4.getAnOperand().(VariableAccess).getTarget()=vtyptype_746
		and target_4.getAnOperand().(Literal).getValue()="99"
		and target_4.getAnOperand().(VariableAccess).getLocation().isBefore(target_10.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

*/
/*predicate func_5(Variable vtyptype_746, EqualityOperation target_5) {
		target_5.getAnOperand().(VariableAccess).getTarget()=vtyptype_746
		and target_5.getAnOperand() instanceof Literal
}

*/
/*predicate func_6(Variable vtyptype_746, EqualityOperation target_6) {
		target_6.getAnOperand().(VariableAccess).getTarget()=vtyptype_746
		and target_6.getAnOperand() instanceof Literal
}

*/
predicate func_7(Variable vtyptype_746, DoStmt target_8, EqualityOperation target_7) {
		target_7.getAnOperand().(VariableAccess).getTarget()=vtyptype_746
		and target_7.getAnOperand() instanceof Literal
		and target_7.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtyptype_746
		and target_7.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="98"
		and target_7.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtyptype_746
		and target_7.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_7.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtyptype_746
		and target_7.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_7.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_8
}

predicate func_8(DoStmt target_8) {
		target_8.getCondition() instanceof Literal
		and target_8.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_8.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0) instanceof Literal
		and target_8.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_8.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(2) instanceof Literal
		and target_8.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType() instanceof ArrayType
		and target_8.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(4) instanceof Literal
		and target_8.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("errfinish")
		and target_8.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("errcode")
		and target_8.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("errmsg")
		and target_8.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(StringLiteral).getValue()="\"%s\" is not a valid base type for a domain"
		and target_8.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("TypeNameToString")
}

predicate func_9(Variable vtyptype_746, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtyptype_746
		and target_9.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="typtype"
		and target_9.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Form_pg_type")
}

predicate func_10(Variable vtyptype_746, LogicalAndExpr target_10) {
		target_10.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtyptype_746
		and target_10.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="98"
		and target_10.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_10.getAnOperand().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_10.getAnOperand() instanceof EqualityOperation
}

from Function func, Variable vtyptype_746, Literal target_0, Literal target_1, Literal target_2, EqualityOperation target_7, DoStmt target_8, ExprStmt target_9, LogicalAndExpr target_10
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
and not func_3(vtyptype_746, target_8, target_9, target_10)
and func_7(vtyptype_746, target_8, target_7)
and func_8(target_8)
and func_9(vtyptype_746, target_9)
and func_10(vtyptype_746, target_10)
and vtyptype_746.getType().hasName("char")
and vtyptype_746.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
