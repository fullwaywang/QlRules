/**
 * @name postgresql-7da4619-TypenameGetTypid
 * @id cpp/postgresql/7da4619/TypenameGetTypid
 * @description postgresql-7da4619-src/backend/catalog/namespace.c-TypenameGetTypid CVE-2019-10208
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

predicate func_1(Parameter vtypname_762, Variable vtypid_764, Variable vnamespaceId_771, FunctionCall target_1) {
		target_1.getTarget().hasName("GetSysCacheOid")
		and not target_1.getTarget().hasName("TypenameGetTypidExtended")
		and target_1.getArgument(1).(VariableAccess).getTarget()=vtypname_762
		and target_1.getArgument(2).(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vnamespaceId_771
		and target_1.getArgument(2).(BitwiseAndExpr).getRightOperand() instanceof Literal
		and target_1.getArgument(3).(Literal).getValue()="0"
		and target_1.getArgument(4).(Literal).getValue()="0"
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtypid_764
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

predicate func_5(Variable vtypid_764, Variable vl_765, Variable vactiveSearchPath, Function func, ForStmt target_5) {
		target_5.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vl_765
		and target_5.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("list_head")
		and target_5.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vactiveSearchPath
		and target_5.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vl_765
		and target_5.getCondition().(EqualityOperation).getAnOperand() instanceof Literal
		and target_5.getUpdate().(AssignExpr).getLValue().(VariableAccess).getTarget()=vl_765
		and target_5.getUpdate().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="next"
		and target_5.getUpdate().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_765
		and target_5.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtypid_764
		and target_5.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and target_5.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtypid_764
		and target_5.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vtypid_764
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

/*predicate func_7(Variable vtypid_764, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtypid_764
		and target_7.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
}

*/
predicate func_8(Variable vnamespaceId_771, VariableAccess target_8) {
		target_8.getTarget()=vnamespaceId_771
		and target_8.getParent().(BitwiseAndExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

/*predicate func_10(Variable vtypid_764, IfStmt target_10) {
		target_10.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtypid_764
		and target_10.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_10.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vtypid_764
}

*/
/*predicate func_11(Variable vtypid_764, EqualityOperation target_13, VariableAccess target_11) {
		target_11.getTarget()=vtypid_764
		and target_13.getAnOperand().(VariableAccess).getLocation().isBefore(target_11.getLocation())
}

*/
predicate func_12(Function func, ReturnStmt target_12) {
		target_12.getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_12
}

predicate func_13(Variable vtypid_764, EqualityOperation target_13) {
		target_13.getAnOperand().(VariableAccess).getTarget()=vtypid_764
		and target_13.getAnOperand() instanceof Literal
}

from Function func, Parameter vtypname_762, Variable vtypid_764, Variable vl_765, Variable vactiveSearchPath, Variable vnamespaceId_771, Literal target_0, FunctionCall target_1, DeclStmt target_2, DeclStmt target_3, ExprStmt target_4, ForStmt target_5, VariableAccess target_8, ReturnStmt target_12, EqualityOperation target_13
where
func_0(func, target_0)
and func_1(vtypname_762, vtypid_764, vnamespaceId_771, target_1)
and func_2(func, target_2)
and func_3(func, target_3)
and func_4(func, target_4)
and func_5(vtypid_764, vl_765, vactiveSearchPath, func, target_5)
and func_8(vnamespaceId_771, target_8)
and func_12(func, target_12)
and func_13(vtypid_764, target_13)
and vtypname_762.getType().hasName("const char *")
and vtypid_764.getType().hasName("Oid")
and vl_765.getType().hasName("ListCell *")
and vactiveSearchPath.getType().hasName("List *")
and vnamespaceId_771.getType().hasName("Oid")
and vtypname_762.getFunction() = func
and vtypid_764.(LocalVariable).getFunction() = func
and vl_765.(LocalVariable).getFunction() = func
and not vactiveSearchPath.getParentScope+() = func
and vnamespaceId_771.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
