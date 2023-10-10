/**
 * @name postgresql-8673743-TypenameGetTypid
 * @id cpp/postgresql/8673743/TypenameGetTypid
 * @description postgresql-8673743-src/backend/catalog/namespace.c-TypenameGetTypid CVE-2019-10208
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

predicate func_1(Parameter vtypname_760, Variable vtypid_762, Variable vnamespaceId_769, FunctionCall target_1) {
		target_1.getTarget().hasName("GetSysCacheOid")
		and not target_1.getTarget().hasName("TypenameGetTypidExtended")
		and target_1.getArgument(1).(VariableAccess).getTarget()=vtypname_760
		and target_1.getArgument(2).(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vnamespaceId_769
		and target_1.getArgument(2).(BitwiseAndExpr).getRightOperand() instanceof Literal
		and target_1.getArgument(3).(Literal).getValue()="0"
		and target_1.getArgument(4).(Literal).getValue()="0"
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtypid_762
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

predicate func_5(Variable vtypid_762, Variable vl_763, Variable vactiveSearchPath, Function func, ForStmt target_5) {
		target_5.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vl_763
		and target_5.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("list_head")
		and target_5.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vactiveSearchPath
		and target_5.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vl_763
		and target_5.getCondition().(EqualityOperation).getAnOperand() instanceof Literal
		and target_5.getUpdate().(AssignExpr).getLValue().(VariableAccess).getTarget()=vl_763
		and target_5.getUpdate().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="next"
		and target_5.getUpdate().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_763
		and target_5.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtypid_762
		and target_5.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and target_5.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtypid_762
		and target_5.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vtypid_762
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

/*predicate func_7(Variable vtypid_762, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtypid_762
		and target_7.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
}

*/
predicate func_8(Variable vnamespaceId_769, VariableAccess target_8) {
		target_8.getTarget()=vnamespaceId_769
		and target_8.getParent().(BitwiseAndExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

/*predicate func_10(Variable vtypid_762, IfStmt target_10) {
		target_10.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtypid_762
		and target_10.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_10.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vtypid_762
}

*/
/*predicate func_11(Variable vtypid_762, EqualityOperation target_13, VariableAccess target_11) {
		target_11.getTarget()=vtypid_762
		and target_13.getAnOperand().(VariableAccess).getLocation().isBefore(target_11.getLocation())
}

*/
predicate func_12(Function func, ReturnStmt target_12) {
		target_12.getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_12
}

predicate func_13(Variable vtypid_762, EqualityOperation target_13) {
		target_13.getAnOperand().(VariableAccess).getTarget()=vtypid_762
		and target_13.getAnOperand() instanceof Literal
}

from Function func, Parameter vtypname_760, Variable vtypid_762, Variable vl_763, Variable vactiveSearchPath, Variable vnamespaceId_769, Literal target_0, FunctionCall target_1, DeclStmt target_2, DeclStmt target_3, ExprStmt target_4, ForStmt target_5, VariableAccess target_8, ReturnStmt target_12, EqualityOperation target_13
where
func_0(func, target_0)
and func_1(vtypname_760, vtypid_762, vnamespaceId_769, target_1)
and func_2(func, target_2)
and func_3(func, target_3)
and func_4(func, target_4)
and func_5(vtypid_762, vl_763, vactiveSearchPath, func, target_5)
and func_8(vnamespaceId_769, target_8)
and func_12(func, target_12)
and func_13(vtypid_762, target_13)
and vtypname_760.getType().hasName("const char *")
and vtypid_762.getType().hasName("Oid")
and vl_763.getType().hasName("ListCell *")
and vactiveSearchPath.getType().hasName("List *")
and vnamespaceId_769.getType().hasName("Oid")
and vtypname_760.getFunction() = func
and vtypid_762.(LocalVariable).getFunction() = func
and vl_763.(LocalVariable).getFunction() = func
and not vactiveSearchPath.getParentScope+() = func
and vnamespaceId_769.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
