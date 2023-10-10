/**
 * @name postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-dumpTableSecLabel
 * @id cpp/postgresql/3d2aed664ee8271fd6c721ed0aa10168cda112ea/dumpTableSecLabel
 * @description postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-src/bin/pg_dump/pg_dump.c-dumpTableSecLabel CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtbinfo_15055, FunctionCall target_0) {
		target_0.getTarget().hasName("fmtId")
		and not target_0.getTarget().hasName("fmtQualifiedId")
		and target_0.getArgument(0).(ValueFieldAccess).getTarget().getName()="name"
		and target_0.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_0.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtbinfo_15055
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("PQExpBuffer")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="COLUMN %s"
}

predicate func_1(Parameter vfout_15055, ExprStmt target_5) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="remoteVersion"
		and target_1.getQualifier().(VariableAccess).getTarget()=vfout_15055
		and target_1.getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vtbinfo_15055, ValueFieldAccess target_6) {
	exists(ValueFieldAccess target_2 |
		target_2.getTarget().getName()="name"
		and target_2.getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="namespace"
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtbinfo_15055
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vfout_15055, Parameter vtbinfo_15055, ExprStmt target_7, ExprStmt target_8) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("fmtQualifiedId")
		and target_3.getArgument(0).(PointerFieldAccess).getTarget().getName()="remoteVersion"
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfout_15055
		and target_3.getArgument(1).(ValueFieldAccess).getTarget().getName()="name"
		and target_3.getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_3.getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="namespace"
		and target_3.getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_3.getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtbinfo_15055
		and target_3.getArgument(2).(ValueFieldAccess).getTarget().getName()="name"
		and target_3.getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_3.getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtbinfo_15055
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("PQExpBuffer")
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="COLUMN %s"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof FunctionCall
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_3.getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vtbinfo_15055, FunctionCall target_4) {
		target_4.getTarget().hasName("fmtId")
		and target_4.getArgument(0).(ValueFieldAccess).getTarget().getName()="name"
		and target_4.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_4.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtbinfo_15055
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("PQExpBuffer")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s %s"
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("const char *")
}

predicate func_5(Parameter vfout_15055, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("appendStringLiteral")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("PQExpBuffer")
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_5.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="encoding"
		and target_5.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfout_15055
		and target_5.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="std_strings"
		and target_5.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfout_15055
}

predicate func_6(Parameter vtbinfo_15055, ValueFieldAccess target_6) {
		target_6.getTarget().getName()="name"
		and target_6.getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtbinfo_15055
}

predicate func_7(Parameter vfout_15055, Parameter vtbinfo_15055, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("findSecLabels")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfout_15055
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="tableoid"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="catId"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtbinfo_15055
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="oid"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="catId"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtbinfo_15055
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("SecLabelItem *")
}

predicate func_8(Parameter vtbinfo_15055, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("const char *")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("getAttrName")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("int")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtbinfo_15055
}

from Function func, Parameter vfout_15055, Parameter vtbinfo_15055, FunctionCall target_0, FunctionCall target_4, ExprStmt target_5, ValueFieldAccess target_6, ExprStmt target_7, ExprStmt target_8
where
func_0(vtbinfo_15055, target_0)
and not func_1(vfout_15055, target_5)
and not func_2(vtbinfo_15055, target_6)
and not func_3(vfout_15055, vtbinfo_15055, target_7, target_8)
and func_4(vtbinfo_15055, target_4)
and func_5(vfout_15055, target_5)
and func_6(vtbinfo_15055, target_6)
and func_7(vfout_15055, vtbinfo_15055, target_7)
and func_8(vtbinfo_15055, target_8)
and vfout_15055.getType().hasName("Archive *")
and vtbinfo_15055.getType().hasName("TableInfo *")
and vfout_15055.getFunction() = func
and vtbinfo_15055.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
