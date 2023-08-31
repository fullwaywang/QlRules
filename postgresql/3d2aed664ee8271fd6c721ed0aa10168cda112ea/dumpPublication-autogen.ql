/**
 * @name postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-dumpPublication
 * @id cpp/postgresql/3d2aed664ee8271fd6c721ed0aa10168cda112ea/dumpPublication
 * @description postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-src/bin/pg_dump/pg_dump.c-dumpPublication CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlabelq_3766, FunctionCall target_0) {
		target_0.getTarget().hasName("appendPQExpBuffer")
		and not target_0.getTarget().hasName("free")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vlabelq_3766
		and target_0.getArgument(1).(StringLiteral).getValue()="PUBLICATION %s"
		and target_0.getArgument(2).(FunctionCall).getTarget().hasName("fmtId")
		and target_0.getArgument(2).(FunctionCall).getArgument(0) instanceof ValueFieldAccess
}

predicate func_2(Function func) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getType().hasName("char *")
		and target_2.getRValue().(FunctionCall).getTarget().hasName("pg_strdup")
		and target_2.getRValue().(FunctionCall).getArgument(0) instanceof FunctionCall
		and target_2.getEnclosingFunction() = func)
}

predicate func_10(Parameter vpubinfo_3762, FunctionCall target_10) {
		target_10.getTarget().hasName("fmtId")
		and target_10.getArgument(0).(ValueFieldAccess).getTarget().getName()="name"
		and target_10.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_10.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpubinfo_3762
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("PQExpBuffer")
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="DROP PUBLICATION %s;\n"
}

predicate func_12(Variable vlabelq_3766, AssignExpr target_12) {
		target_12.getLValue().(VariableAccess).getTarget()=vlabelq_3766
		and target_12.getRValue().(FunctionCall).getTarget().hasName("createPQExpBuffer")
}

predicate func_13(Parameter vpubinfo_3762, ValueFieldAccess target_17, ValueFieldAccess target_14, FunctionCall target_13) {
		target_13.getTarget().hasName("fmtId")
		and target_13.getArgument(0).(ValueFieldAccess).getTarget().getName()="name"
		and target_13.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_13.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpubinfo_3762
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("PQExpBuffer")
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="CREATE PUBLICATION %s"
		and target_17.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_13.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_14(Parameter vpubinfo_3762, ValueFieldAccess target_18, IfStmt target_19, ValueFieldAccess target_14) {
		target_14.getTarget().getName()="name"
		and target_14.getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_14.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpubinfo_3762
		and target_14.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("fmtId")
		and target_18.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_14.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_19.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_15(Variable vlabelq_3766, ExprStmt target_21, PointerFieldAccess target_15) {
		target_15.getTarget().getName()="data"
		and target_15.getQualifier().(VariableAccess).getTarget()=vlabelq_3766
		and target_15.getQualifier().(VariableAccess).getLocation().isBefore(target_21.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_16(Variable vlabelq_3766, ExprStmt target_22, PointerFieldAccess target_16) {
		target_16.getTarget().getName()="data"
		and target_16.getQualifier().(VariableAccess).getTarget()=vlabelq_3766
		and target_22.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_16.getQualifier().(VariableAccess).getLocation())
}

predicate func_17(Parameter vpubinfo_3762, ValueFieldAccess target_17) {
		target_17.getTarget().getName()="name"
		and target_17.getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_17.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpubinfo_3762
}

predicate func_18(Parameter vpubinfo_3762, ValueFieldAccess target_18) {
		target_18.getTarget().getName()="name"
		and target_18.getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_18.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpubinfo_3762
}

predicate func_19(Parameter vpubinfo_3762, IfStmt target_19) {
		target_19.getCondition().(PointerFieldAccess).getTarget().getName()="puballtables"
		and target_19.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpubinfo_3762
		and target_19.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPQExpBufferStr")
		and target_19.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("PQExpBuffer")
		and target_19.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()=" FOR ALL TABLES"
}

predicate func_21(Parameter vpubinfo_3762, Variable vlabelq_3766, ExprStmt target_21) {
		target_21.getExpr().(FunctionCall).getTarget().hasName("dumpSecLabel")
		and target_21.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("Archive *")
		and target_21.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="data"
		and target_21.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlabelq_3766
		and target_21.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_21.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="rolname"
		and target_21.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpubinfo_3762
		and target_21.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getTarget().getName()="catId"
		and target_21.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_21.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpubinfo_3762
		and target_21.getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_21.getExpr().(FunctionCall).getArgument(6).(ValueFieldAccess).getTarget().getName()="dumpId"
		and target_21.getExpr().(FunctionCall).getArgument(6).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_21.getExpr().(FunctionCall).getArgument(6).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpubinfo_3762
}

predicate func_22(Parameter vpubinfo_3762, Variable vlabelq_3766, ExprStmt target_22) {
		target_22.getExpr().(FunctionCall).getTarget().hasName("dumpComment")
		and target_22.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("Archive *")
		and target_22.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="data"
		and target_22.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlabelq_3766
		and target_22.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_22.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="rolname"
		and target_22.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpubinfo_3762
		and target_22.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getTarget().getName()="catId"
		and target_22.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_22.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpubinfo_3762
		and target_22.getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_22.getExpr().(FunctionCall).getArgument(6).(ValueFieldAccess).getTarget().getName()="dumpId"
		and target_22.getExpr().(FunctionCall).getArgument(6).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_22.getExpr().(FunctionCall).getArgument(6).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpubinfo_3762
}

from Function func, Parameter vpubinfo_3762, Variable vlabelq_3766, FunctionCall target_0, FunctionCall target_10, AssignExpr target_12, FunctionCall target_13, ValueFieldAccess target_14, PointerFieldAccess target_15, PointerFieldAccess target_16, ValueFieldAccess target_17, ValueFieldAccess target_18, IfStmt target_19, ExprStmt target_21, ExprStmt target_22
where
func_0(vlabelq_3766, target_0)
and not func_2(func)
and func_10(vpubinfo_3762, target_10)
and func_12(vlabelq_3766, target_12)
and func_13(vpubinfo_3762, target_17, target_14, target_13)
and func_14(vpubinfo_3762, target_18, target_19, target_14)
and func_15(vlabelq_3766, target_21, target_15)
and func_16(vlabelq_3766, target_22, target_16)
and func_17(vpubinfo_3762, target_17)
and func_18(vpubinfo_3762, target_18)
and func_19(vpubinfo_3762, target_19)
and func_21(vpubinfo_3762, vlabelq_3766, target_21)
and func_22(vpubinfo_3762, vlabelq_3766, target_22)
and vpubinfo_3762.getType().hasName("PublicationInfo *")
and vlabelq_3766.getType().hasName("PQExpBuffer")
and vpubinfo_3762.getFunction() = func
and vlabelq_3766.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
