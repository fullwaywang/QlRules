/**
 * @name postgresql-21f94c5-TypenameGetTypid
 * @id cpp/postgresql/21f94c5/TypenameGetTypid
 * @description postgresql-21f94c5-src/backend/catalog/namespace.c-TypenameGetTypid CVE-2019-10208
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="1"
		and target_0.getParent().(NEExpr).getParent().(ForStmt).getCondition() instanceof EqualityOperation
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vtypname_766, Variable vtypid_768, Variable vnamespaceId_775, FunctionCall target_1) {
		target_1.getTarget().hasName("GetSysCacheOid")
		and not target_1.getTarget().hasName("TypenameGetTypidExtended")
		and target_1.getArgument(1).(VariableAccess).getTarget()=vtypname_766
		and target_1.getArgument(2).(VariableAccess).getTarget()=vnamespaceId_775
		and target_1.getArgument(3).(Literal).getValue()="0"
		and target_1.getArgument(4).(Literal).getValue()="0"
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtypid_768
}

predicate func_2(Function func, DeclStmt target_2) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Function func, DeclStmt target_3) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

predicate func_4(Function func, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("recomputeNamespacePath")
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Variable vtypid_768, Variable vl_769, Variable vactiveSearchPath, Function func, ForStmt target_5) {
		target_5.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vl_769
		and target_5.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("list_head")
		and target_5.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vactiveSearchPath
		and target_5.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vl_769
		and target_5.getCondition().(EqualityOperation).getAnOperand() instanceof Literal
		and target_5.getUpdate().(AssignExpr).getLValue().(VariableAccess).getTarget()=vl_769
		and target_5.getUpdate().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="next"
		and target_5.getUpdate().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_769
		and target_5.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtypid_768
		and target_5.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and target_5.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtypid_768
		and target_5.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vtypid_768
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

/*predicate func_7(Variable vtypid_768, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtypid_768
		and target_7.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
}

*/
/*predicate func_8(Variable vtypid_768, IfStmt target_8) {
		target_8.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtypid_768
		and target_8.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vtypid_768
}

*/
/*predicate func_9(Variable vtypid_768, EqualityOperation target_11, VariableAccess target_9) {
		target_9.getTarget()=vtypid_768
		and target_11.getAnOperand().(VariableAccess).getLocation().isBefore(target_9.getLocation())
}

*/
predicate func_10(Function func, ReturnStmt target_10) {
		target_10.getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_10
}

predicate func_11(Variable vtypid_768, EqualityOperation target_11) {
		target_11.getAnOperand().(VariableAccess).getTarget()=vtypid_768
		and target_11.getAnOperand() instanceof Literal
}

from Function func, Parameter vtypname_766, Variable vtypid_768, Variable vl_769, Variable vactiveSearchPath, Variable vnamespaceId_775, Literal target_0, FunctionCall target_1, DeclStmt target_2, DeclStmt target_3, ExprStmt target_4, ForStmt target_5, ReturnStmt target_10, EqualityOperation target_11
where
func_0(func, target_0)
and func_1(vtypname_766, vtypid_768, vnamespaceId_775, target_1)
and func_2(func, target_2)
and func_3(func, target_3)
and func_4(func, target_4)
and func_5(vtypid_768, vl_769, vactiveSearchPath, func, target_5)
and func_10(func, target_10)
and func_11(vtypid_768, target_11)
and vtypname_766.getType().hasName("const char *")
and vtypid_768.getType().hasName("Oid")
and vl_769.getType().hasName("ListCell *")
and vactiveSearchPath.getType().hasName("List *")
and vnamespaceId_775.getType().hasName("Oid")
and vtypname_766.getFunction() = func
and vtypid_768.(LocalVariable).getFunction() = func
and vl_769.(LocalVariable).getFunction() = func
and not vactiveSearchPath.getParentScope+() = func
and vnamespaceId_775.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
