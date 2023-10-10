/**
 * @name postgresql-5919bb5a5989cda232ac3d1f8b9d90f337be2077-CreateSchemaCommand
 * @id cpp/postgresql/5919bb5a5989cda232ac3d1f8b9d90f337be2077/CreateSchemaCommand
 * @description postgresql-5919bb5a5989cda232ac3d1f8b9d90f337be2077-src/backend/commands/schemacmds.c-CreateSchemaCommand CVE-2022-2625
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vschemaName_54, Variable vnamespaceId_55, LogicalAndExpr target_8, FunctionCall target_9, FunctionCall target_10) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnamespaceId_55
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_namespace_oid")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vschemaName_54
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_9.getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_10.getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Variable vnamespaceId_55, Variable vaddress_63, Variable v__func__, LogicalAndExpr target_8, ExprStmt target_12, FunctionCall target_13) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnamespaceId_55
		and target_1.getCondition().(EqualityOperation).getAnOperand() instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="classId"
		and target_1.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="2615"
		and target_1.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="objectId"
		and target_1.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnamespaceId_55
		and target_1.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="objectSubId"
		and target_1.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("checkMembershipInCurrentExtension")
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vaddress_63
		and target_1.getThen().(BlockStmt).getStmt(2).(DoStmt).getCondition() instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_1.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(Literal).getValue()="18"
		and target_1.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_1.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(2) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__func__
		and target_1.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(4) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("errfinish")
		and target_1.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
		and target_1.getThen().(BlockStmt).getStmt(3) instanceof ReturnStmt
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_13.getArgument(3).(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_2(LogicalAndExpr target_8, Function func, ReturnStmt target_2) {
		target_2.getExpr().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Parameter vstmt_51, BlockStmt target_14, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="if_not_exists"
		and target_3.getQualifier().(VariableAccess).getTarget()=vstmt_51
		and target_3.getParent().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_14
}

predicate func_4(Variable vschemaName_54, VariableAccess target_4) {
		target_4.getTarget()=vschemaName_54
		and target_4.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
}

predicate func_8(Parameter vstmt_51, Variable vschemaName_54, BlockStmt target_14, LogicalAndExpr target_8) {
		target_8.getAnOperand().(PointerFieldAccess).getTarget().getName()="if_not_exists"
		and target_8.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstmt_51
		and target_8.getAnOperand().(FunctionCall).getTarget().hasName("SearchSysCacheExists")
		and target_8.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vschemaName_54
		and target_8.getAnOperand().(FunctionCall).getArgument(2) instanceof Literal
		and target_8.getAnOperand().(FunctionCall).getArgument(3) instanceof Literal
		and target_8.getAnOperand().(FunctionCall).getArgument(4) instanceof Literal
		and target_8.getParent().(IfStmt).getThen()=target_14
}

predicate func_9(Variable vschemaName_54, FunctionCall target_9) {
		target_9.getTarget().hasName("errmsg")
		and target_9.getArgument(0).(StringLiteral).getValue()="unacceptable schema name \"%s\""
		and target_9.getArgument(1).(VariableAccess).getTarget()=vschemaName_54
}

predicate func_10(Variable vschemaName_54, FunctionCall target_10) {
		target_10.getTarget().hasName("errmsg")
		and target_10.getArgument(0).(StringLiteral).getValue()="schema \"%s\" already exists, skipping"
		and target_10.getArgument(1).(VariableAccess).getTarget()=vschemaName_54
}

predicate func_12(Variable vaddress_63, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="classId"
		and target_12.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vaddress_63
		and target_12.getExpr().(AssignExpr).getRValue().(Literal).getValue()="2615"
}

predicate func_13(Variable v__func__, FunctionCall target_13) {
		target_13.getTarget().hasName("errstart")
		and target_13.getArgument(0) instanceof Literal
		and target_13.getArgument(1) instanceof StringLiteral
		and target_13.getArgument(2) instanceof Literal
		and target_13.getArgument(3).(VariableAccess).getTarget()=v__func__
		and target_13.getArgument(4) instanceof Literal
}

predicate func_14(Variable v__func__, BlockStmt target_14) {
		target_14.getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_14.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_14.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(Literal).getValue()="18"
		and target_14.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_14.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(2) instanceof Literal
		and target_14.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__func__
		and target_14.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(4) instanceof Literal
		and target_14.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("errfinish")
		and target_14.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("errcode")
		and target_14.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("errmsg")
}

from Function func, Parameter vstmt_51, Variable vschemaName_54, Variable vnamespaceId_55, Variable vaddress_63, Variable v__func__, ReturnStmt target_2, PointerFieldAccess target_3, VariableAccess target_4, LogicalAndExpr target_8, FunctionCall target_9, FunctionCall target_10, ExprStmt target_12, FunctionCall target_13, BlockStmt target_14
where
not func_0(vschemaName_54, vnamespaceId_55, target_8, target_9, target_10)
and not func_1(vnamespaceId_55, vaddress_63, v__func__, target_8, target_12, target_13)
and func_2(target_8, func, target_2)
and func_3(vstmt_51, target_14, target_3)
and func_4(vschemaName_54, target_4)
and func_8(vstmt_51, vschemaName_54, target_14, target_8)
and func_9(vschemaName_54, target_9)
and func_10(vschemaName_54, target_10)
and func_12(vaddress_63, target_12)
and func_13(v__func__, target_13)
and func_14(v__func__, target_14)
and vstmt_51.getType().hasName("CreateSchemaStmt *")
and vschemaName_54.getType().hasName("const char *")
and vnamespaceId_55.getType().hasName("Oid")
and vaddress_63.getType().hasName("ObjectAddress")
and v__func__.getType() instanceof ArrayType
and vstmt_51.getFunction() = func
and vschemaName_54.(LocalVariable).getFunction() = func
and vnamespaceId_55.(LocalVariable).getFunction() = func
and vaddress_63.(LocalVariable).getFunction() = func
and not v__func__.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
