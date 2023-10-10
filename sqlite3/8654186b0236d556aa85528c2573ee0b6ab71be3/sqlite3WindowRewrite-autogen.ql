/**
 * @name sqlite3-8654186b0236d556aa85528c2573ee0b6ab71be3-sqlite3WindowRewrite
 * @id cpp/sqlite3/8654186b0236d556aa85528c2573ee0b6ab71be3/sqlite3WindowRewrite
 * @description sqlite3-8654186b0236d556aa85528c2573ee0b6ab71be3-src/window.c-sqlite3WindowRewrite CVE-2019-19924
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdb_922, ExprStmt target_3, ExprStmt target_4) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("sqlite3ErrorToParser")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vdb_922
		and target_0.getArgument(1) instanceof Literal
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation())
		and target_0.getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vrc_919, Parameter vpParse_918, ExprStmt target_5, ReturnStmt target_6, ExprStmt target_7, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vrc_919
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="nErr"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpParse_918
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("sqlite3ErrorToParser")
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="db"
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpParse_918
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="7"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_1)
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_6.getExpr().(VariableAccess).getLocation())
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vdb_922, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("Table *")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sqlite3DbMallocZero")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdb_922
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="128"
}

predicate func_4(Variable vdb_922, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("ExprList *")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sqlite3ExprListDup")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdb_922
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="pPartition"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Window *")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_5(Variable vrc_919, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrc_919
		and target_5.getExpr().(AssignExpr).getRValue().(Literal).getValue()="7"
}

predicate func_6(Variable vrc_919, ReturnStmt target_6) {
		target_6.getExpr().(VariableAccess).getTarget()=vrc_919
}

predicate func_7(Parameter vpParse_918, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("Table *")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sqlite3ResultSetOfSelect")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpParse_918
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("Select *")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="64"
}

from Function func, Variable vrc_919, Variable vdb_922, Parameter vpParse_918, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, ReturnStmt target_6, ExprStmt target_7
where
not func_0(vdb_922, target_3, target_4)
and not func_1(vrc_919, vpParse_918, target_5, target_6, target_7, func)
and func_3(vdb_922, target_3)
and func_4(vdb_922, target_4)
and func_5(vrc_919, target_5)
and func_6(vrc_919, target_6)
and func_7(vpParse_918, target_7)
and vrc_919.getType().hasName("int")
and vdb_922.getType().hasName("sqlite3 *")
and vpParse_918.getType().hasName("Parse *")
and vrc_919.(LocalVariable).getFunction() = func
and vdb_922.(LocalVariable).getFunction() = func
and vpParse_918.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
