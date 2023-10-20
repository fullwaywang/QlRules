/**
 * @name postgresql-7eeb1d9861b0a3f453f8b31c7648396cdd7f1e59-ValidateJoinEstimator
 * @id cpp/postgresql/7eeb1d9861b0a3f453f8b31c7648396cdd7f1e59/ValidateJoinEstimator
 * @description postgresql-7eeb1d9861b0a3f453f8b31c7648396cdd7f1e59-src/backend/commands/operatorcmds.c-ValidateJoinEstimator CVE-2020-14350
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtypeId_298, Variable vjoinOid_299, Parameter vjoinName_296, VariableAccess target_0) {
		target_0.getTarget()=vjoinOid_299
		and target_0.getParent().(AssignExpr).getLValue() = target_0
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("LookupFuncName")
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vjoinName_296
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="4"
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtypeId_298
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="1"
}

predicate func_1(Variable vjoinOid_299, ExprStmt target_7, ExprStmt target_8) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vjoinOid_299
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_7
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(NotExpr target_6, Function func) {
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
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vjoinOid_299, NotExpr target_6) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vjoinOid_299
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("Oid")
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6)
}

predicate func_4(Variable vjoinOid_299, ExprStmt target_7, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vjoinOid_299
		and target_4.getAnOperand().(Literal).getValue()="0"
		and target_4.getParent().(NotExpr).getParent().(IfStmt).getThen()=target_7
}

predicate func_5(Variable vtypeId_298, Variable vjoinOid_299, Parameter vjoinName_296, Function func, IfStmt target_5) {
		target_5.getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vjoinOid_299
		and target_5.getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vjoinOid_299
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("LookupFuncName")
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vjoinName_296
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="5"
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtypeId_298
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

predicate func_6(ExprStmt target_7, Function func, NotExpr target_6) {
		target_6.getOperand() instanceof EqualityOperation
		and target_6.getParent().(IfStmt).getThen()=target_7
		and target_6.getEnclosingFunction() = func
}

predicate func_7(Variable vtypeId_298, Variable vjoinOid_299, Parameter vjoinName_296, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vjoinOid_299
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("LookupFuncName")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vjoinName_296
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="4"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtypeId_298
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="1"
}

predicate func_8(Variable vtypeId_298, Variable vjoinOid_299, Parameter vjoinName_296, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vjoinOid_299
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("LookupFuncName")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vjoinName_296
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="5"
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtypeId_298
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="1"
}

from Function func, Variable vtypeId_298, Variable vjoinOid_299, Parameter vjoinName_296, VariableAccess target_0, EqualityOperation target_4, IfStmt target_5, NotExpr target_6, ExprStmt target_7, ExprStmt target_8
where
func_0(vtypeId_298, vjoinOid_299, vjoinName_296, target_0)
and not func_1(vjoinOid_299, target_7, target_8)
and not func_2(target_6, func)
and not func_3(vjoinOid_299, target_6)
and func_4(vjoinOid_299, target_7, target_4)
and func_5(vtypeId_298, vjoinOid_299, vjoinName_296, func, target_5)
and func_6(target_7, func, target_6)
and func_7(vtypeId_298, vjoinOid_299, vjoinName_296, target_7)
and func_8(vtypeId_298, vjoinOid_299, vjoinName_296, target_8)
and vtypeId_298.getType().hasName("Oid[5]")
and vjoinOid_299.getType().hasName("Oid")
and vjoinName_296.getType().hasName("List *")
and vtypeId_298.(LocalVariable).getFunction() = func
and vjoinOid_299.(LocalVariable).getFunction() = func
and vjoinName_296.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
