/**
 * @name postgresql-06292bb949e555f34edde7603237194a7daac942-pg_get_triggerdef_worker
 * @id cpp/postgresql/06292bb949e555f34edde7603237194a7daac942/pg-get-triggerdef-worker
 * @description postgresql-06292bb949e555f34edde7603237194a7daac942-src/backend/utils/adt/ruleutils.c-pg_get_triggerdef_worker CVE-2018-16850
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtgoldtable_834, EqualityOperation target_4) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("quote_identifier")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vtgoldtable_834
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendStringInfo")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("StringInfoData")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="OLD TABLE AS %s "
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtgoldtable_834
		and target_4.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vtgnewtable_835, EqualityOperation target_5) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("quote_identifier")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vtgnewtable_835
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendStringInfo")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("StringInfoData")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="NEW TABLE AS %s "
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtgnewtable_835
		and target_5.getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Variable vtgoldtable_834, VariableAccess target_2) {
		target_2.getTarget()=vtgoldtable_834
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendStringInfo")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("StringInfoData")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="OLD TABLE AS %s "
}

predicate func_3(Variable vtgnewtable_835, VariableAccess target_3) {
		target_3.getTarget()=vtgnewtable_835
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendStringInfo")
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("StringInfoData")
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="NEW TABLE AS %s "
}

predicate func_4(Variable vtgoldtable_834, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vtgoldtable_834
		and target_4.getAnOperand().(Literal).getValue()="0"
}

predicate func_5(Variable vtgnewtable_835, EqualityOperation target_5) {
		target_5.getAnOperand().(VariableAccess).getTarget()=vtgnewtable_835
		and target_5.getAnOperand().(Literal).getValue()="0"
}

from Function func, Variable vtgoldtable_834, Variable vtgnewtable_835, VariableAccess target_2, VariableAccess target_3, EqualityOperation target_4, EqualityOperation target_5
where
not func_0(vtgoldtable_834, target_4)
and not func_1(vtgnewtable_835, target_5)
and func_2(vtgoldtable_834, target_2)
and func_3(vtgnewtable_835, target_3)
and func_4(vtgoldtable_834, target_4)
and func_5(vtgnewtable_835, target_5)
and vtgoldtable_834.getType().hasName("char *")
and vtgnewtable_835.getType().hasName("char *")
and vtgoldtable_834.(LocalVariable).getFunction() = func
and vtgnewtable_835.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
