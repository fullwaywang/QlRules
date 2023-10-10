/**
 * @name postgresql-7eeb1d9861b0a3f453f8b31c7648396cdd7f1e59-findTypeInputFunction
 * @id cpp/postgresql/7eeb1d9861b0a3f453f8b31c7648396cdd7f1e59/findTypeInputFunction
 * @description postgresql-7eeb1d9861b0a3f453f8b31c7648396cdd7f1e59-src/backend/commands/typecmds.c-findTypeInputFunction CVE-2020-14350
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vargList_1628, Variable vprocOid_1629, VariableAccess target_0) {
		target_0.getTarget()=vprocOid_1629
		and target_0.getParent().(AssignExpr).getLValue() = target_0
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("LookupFuncName")
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("List *")
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="3"
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vargList_1628
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="1"
}

predicate func_1(Variable vprocOid_1629, BlockStmt target_8, ExprStmt target_9, NotExpr target_7) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vprocOid_1629
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_8
		and target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(NotExpr target_7, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("Oid")
		and target_2.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen().(DoStmt).getCondition() instanceof Literal
		and target_2.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_2.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0) instanceof Literal
		and target_2.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof Literal
		and target_2.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("errfinish")
		and target_2.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getValue()="1"
		and target_2.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vprocOid_1629, NotExpr target_7) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vprocOid_1629
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("Oid")
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7)
}

predicate func_4(Variable vprocOid_1629, BlockStmt target_8, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vprocOid_1629
		and target_4.getAnOperand().(Literal).getValue()="0"
		and target_4.getParent().(NotExpr).getParent().(IfStmt).getThen()=target_8
}

predicate func_5(Variable vargList_1628, NotExpr target_7, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vargList_1628
		and target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_5.getExpr().(AssignExpr).getRValue().(Literal).getValue()="26"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
}

predicate func_6(Variable vargList_1628, NotExpr target_7, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vargList_1628
		and target_6.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_6.getExpr().(AssignExpr).getRValue().(Literal).getValue()="23"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
}

predicate func_7(BlockStmt target_8, Function func, NotExpr target_7) {
		target_7.getOperand() instanceof EqualityOperation
		and target_7.getParent().(IfStmt).getThen()=target_8
		and target_7.getEnclosingFunction() = func
}

predicate func_8(Variable vargList_1628, Variable vprocOid_1629, BlockStmt target_8) {
		target_8.getStmt(0) instanceof ExprStmt
		and target_8.getStmt(1) instanceof ExprStmt
		and target_8.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vprocOid_1629
		and target_8.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("LookupFuncName")
		and target_8.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("List *")
		and target_8.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="3"
		and target_8.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vargList_1628
		and target_8.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="1"
}

predicate func_9(Variable vargList_1628, Variable vprocOid_1629, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vprocOid_1629
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("LookupFuncName")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("List *")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vargList_1628
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="1"
}

from Function func, Variable vargList_1628, Variable vprocOid_1629, VariableAccess target_0, EqualityOperation target_4, ExprStmt target_5, ExprStmt target_6, NotExpr target_7, BlockStmt target_8, ExprStmt target_9
where
func_0(vargList_1628, vprocOid_1629, target_0)
and not func_1(vprocOid_1629, target_8, target_9, target_7)
and not func_2(target_7, func)
and not func_3(vprocOid_1629, target_7)
and func_4(vprocOid_1629, target_8, target_4)
and func_5(vargList_1628, target_7, target_5)
and func_6(vargList_1628, target_7, target_6)
and func_7(target_8, func, target_7)
and func_8(vargList_1628, vprocOid_1629, target_8)
and func_9(vargList_1628, vprocOid_1629, target_9)
and vargList_1628.getType().hasName("Oid[3]")
and vprocOid_1629.getType().hasName("Oid")
and vargList_1628.(LocalVariable).getFunction() = func
and vprocOid_1629.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
