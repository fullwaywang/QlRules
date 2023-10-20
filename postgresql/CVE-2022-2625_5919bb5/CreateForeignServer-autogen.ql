/**
 * @name postgresql-5919bb5a5989cda232ac3d1f8b9d90f337be2077-CreateForeignServer
 * @id cpp/postgresql/5919bb5a5989cda232ac3d1f8b9d90f337be2077/CreateForeignServer
 * @description postgresql-5919bb5a5989cda232ac3d1f8b9d90f337be2077-src/backend/commands/foreigncmds.c-CreateForeignServer CVE-2022-2625
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vstmt_861, Variable vsrvId_868, IfStmt target_11, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsrvId_868
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_foreign_server_oid")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="servername"
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstmt_861
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof Literal
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_0)
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vmyself_871, PointerFieldAccess target_13) {
	exists(DoStmt target_2 |
		target_2.getCondition().(Literal).getValue()="0"
		and target_2.getStmt().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_2.getStmt().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_2.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="objectSubId"
		and target_2.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vmyself_871
		and target_2.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13)
}

predicate func_3(Variable vmyself_871, PointerFieldAccess target_13) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("checkMembershipInCurrentExtension")
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmyself_871
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13)
}

predicate func_5(Variable vsrvId_868, Variable vmyself_871, ExprStmt target_15, ExprStmt target_8, ExprStmt target_7, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="objectId"
		and target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vmyself_871
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vsrvId_868
		and (func.getEntryPoint().(BlockStmt).getStmt(32)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(32).getFollowingStmt()=target_5)
		and target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_6(Parameter vstmt_861, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="servername"
		and target_6.getQualifier().(VariableAccess).getTarget()=vstmt_861
		and target_6.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand() instanceof FunctionCall
}

predicate func_7(Variable vmyself_871, Function func, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="classId"
		and target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vmyself_871
		and target_7.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1417"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

predicate func_8(Variable vsrvId_868, Variable vmyself_871, Function func, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="objectId"
		and target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vmyself_871
		and target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vsrvId_868
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8
}

predicate func_10(Parameter vstmt_861, BlockStmt target_16, FunctionCall target_10) {
		target_10.getTarget().hasName("GetForeignServerByName")
		and target_10.getArgument(0).(PointerFieldAccess).getTarget().getName()="servername"
		and target_10.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstmt_861
		and target_10.getArgument(1) instanceof Literal
		and target_10.getParent().(NEExpr).getAnOperand().(Literal).getValue()="0"
		and target_10.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_16
}

predicate func_11(Parameter vstmt_861, IfStmt target_11) {
		target_11.getCondition().(PointerFieldAccess).getTarget().getName()="if_not_exists"
		and target_11.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstmt_861
		and target_11.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_11.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_11.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(Literal).getValue()="18"
		and target_11.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_11.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(2) instanceof Literal
		and target_11.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType() instanceof ArrayType
		and target_11.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(4) instanceof Literal
		and target_11.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("errfinish")
		and target_11.getElse().(DoStmt).getCondition() instanceof Literal
		and target_11.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_11.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0) instanceof Literal
		and target_11.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_11.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(2) instanceof Literal
		and target_11.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType() instanceof ArrayType
		and target_11.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(4) instanceof Literal
		and target_11.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("errfinish")
		and target_11.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("errcode")
		and target_11.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("errmsg")
}

predicate func_13(Parameter vstmt_861, PointerFieldAccess target_13) {
		target_13.getTarget().getName()="if_not_exists"
		and target_13.getQualifier().(VariableAccess).getTarget()=vstmt_861
}

predicate func_15(Variable vsrvId_868, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsrvId_868
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("CatalogTupleInsert")
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("Relation")
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("HeapTuple")
}

predicate func_16(Parameter vstmt_861, BlockStmt target_16) {
		target_16.getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="if_not_exists"
		and target_16.getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstmt_861
		and target_16.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_16.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_16.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("relation_close")
		and target_16.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("Relation")
		and target_16.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="3"
		and target_16.getStmt(0).(IfStmt).getElse().(DoStmt).getCondition() instanceof Literal
		and target_16.getStmt(0).(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_16.getStmt(0).(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0) instanceof Literal
		and target_16.getStmt(0).(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_16.getStmt(0).(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(2) instanceof Literal
		and target_16.getStmt(0).(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType() instanceof ArrayType
		and target_16.getStmt(0).(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(4) instanceof Literal
		and target_16.getStmt(0).(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("errfinish")
}

from Function func, Parameter vstmt_861, Variable vsrvId_868, Variable vmyself_871, PointerFieldAccess target_6, ExprStmt target_7, ExprStmt target_8, FunctionCall target_10, IfStmt target_11, PointerFieldAccess target_13, ExprStmt target_15, BlockStmt target_16
where
not func_0(vstmt_861, vsrvId_868, target_11, func)
and not func_2(vmyself_871, target_13)
and not func_3(vmyself_871, target_13)
and not func_5(vsrvId_868, vmyself_871, target_15, target_8, target_7, func)
and func_6(vstmt_861, target_6)
and func_7(vmyself_871, func, target_7)
and func_8(vsrvId_868, vmyself_871, func, target_8)
and func_10(vstmt_861, target_16, target_10)
and func_11(vstmt_861, target_11)
and func_13(vstmt_861, target_13)
and func_15(vsrvId_868, target_15)
and func_16(vstmt_861, target_16)
and vstmt_861.getType().hasName("CreateForeignServerStmt *")
and vsrvId_868.getType().hasName("Oid")
and vmyself_871.getType().hasName("ObjectAddress")
and vstmt_861.getFunction() = func
and vsrvId_868.(LocalVariable).getFunction() = func
and vmyself_871.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
