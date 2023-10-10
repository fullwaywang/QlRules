/**
 * @name postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-dumpStatisticsExt
 * @id cpp/postgresql/3d2aed664ee8271fd6c721ed0aa10168cda112ea/dumpStatisticsExt
 * @description postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-src/bin/pg_dump/pg_dump.c-dumpStatisticsExt CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vfout_16483, FunctionCall target_0) {
		target_0.getTarget().hasName("selectSourceSchema")
		and not target_0.getTarget().hasName("free")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vfout_16483
		and target_0.getArgument(1) instanceof ValueFieldAccess
}

predicate func_1(Function func, StringLiteral target_1) {
		target_1.getValue()="STATISTICS %s"
		and not target_1.getValue()="DROP STATISTICS %s;\n"
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, FunctionCall target_2) {
		target_2.getTarget().hasName("fmtId")
		and not target_2.getTarget().hasName("fmtQualifiedId")
		and target_2.getArgument(0).(ValueFieldAccess).getTarget().getName()="name"
		and target_2.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_2.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier() instanceof ValueFieldAccess
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
		and target_2.getEnclosingFunction() = func
}

predicate func_4(Function func) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(VariableAccess).getType().hasName("char *")
		and target_4.getRValue().(FunctionCall).getTarget().hasName("pg_strdup")
		and target_4.getRValue().(FunctionCall).getArgument(0) instanceof FunctionCall
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Parameter vfout_16483, ExprStmt target_24) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="remoteVersion"
		and target_5.getQualifier().(VariableAccess).getTarget()=vfout_16483
		and target_24.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getQualifier().(VariableAccess).getLocation()))
}

predicate func_9(Parameter vstatsextinfo_16483, ValueFieldAccess target_9) {
		target_9.getTarget().getName()="namespace"
		and target_9.getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_9.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstatsextinfo_16483
}

predicate func_10(Parameter vstatsextinfo_16483, ValueFieldAccess target_10) {
		target_10.getTarget().getName()="name"
		and target_10.getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_10.getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="namespace"
		and target_10.getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_10.getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstatsextinfo_16483
}

predicate func_11(Parameter vstatsextinfo_16483, Variable vlabelq_16488, FunctionCall target_11) {
		target_11.getTarget().hasName("fmtId")
		and target_11.getArgument(0).(ValueFieldAccess).getTarget().getName()="name"
		and target_11.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_11.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstatsextinfo_16483
		and target_11.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_11.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlabelq_16488
		and target_11.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
}

predicate func_12(Parameter vstatsextinfo_16483, ValueFieldAccess target_12) {
		target_12.getTarget().getName()="name"
		and target_12.getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_12.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstatsextinfo_16483
}

predicate func_13(Parameter vfout_16483, VariableAccess target_13) {
		target_13.getTarget()=vfout_16483
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_14(Variable vdelq_16487, VariableAccess target_14) {
		target_14.getTarget()=vdelq_16487
		and target_14.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_15(Parameter vstatsextinfo_16483, Variable vlabelq_16488, Parameter vfout_16483, VariableAccess target_15) {
		target_15.getTarget()=vfout_16483
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dumpComment")
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="data"
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlabelq_16488
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="name"
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="namespace"
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstatsextinfo_16483
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="rolname"
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstatsextinfo_16483
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getTarget().getName()="catId"
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstatsextinfo_16483
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ValueFieldAccess).getTarget().getName()="dumpId"
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstatsextinfo_16483
}

predicate func_17(Variable vlabelq_16488, AssignExpr target_17) {
		target_17.getLValue().(VariableAccess).getTarget()=vlabelq_16488
		and target_17.getRValue().(FunctionCall).getTarget().hasName("createPQExpBuffer")
}

predicate func_18(Variable vlabelq_16488, ExprStmt target_26, VariableAccess target_18) {
		target_18.getTarget()=vlabelq_16488
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof FunctionCall
		and target_18.getLocation().isBefore(target_26.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_19(Variable vdelq_16487, Function func, ExprStmt target_19) {
		target_19.getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_19.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdelq_16487
		and target_19.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="DROP STATISTICS %s."
		and target_19.getExpr().(FunctionCall).getArgument(2) instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_19
}

predicate func_20(Function func, PointerFieldAccess target_20) {
		target_20.getTarget().getName()="dobj"
		and target_20.getQualifier() instanceof ValueFieldAccess
		and target_20.getEnclosingFunction() = func
}

predicate func_21(Variable vdelq_16487, Function func, ExprStmt target_21) {
		target_21.getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_21.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdelq_16487
		and target_21.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s;\n"
		and target_21.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("fmtId")
		and target_21.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0) instanceof ValueFieldAccess
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_21
}

predicate func_22(Variable vlabelq_16488, PointerFieldAccess target_22) {
		target_22.getTarget().getName()="data"
		and target_22.getQualifier().(VariableAccess).getTarget()=vlabelq_16488
}

predicate func_23(Variable vlabelq_16488, Function func, ExprStmt target_23) {
		target_23.getExpr().(FunctionCall).getTarget().hasName("destroyPQExpBuffer")
		and target_23.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlabelq_16488
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_23
}

predicate func_24(Parameter vstatsextinfo_16483, Variable vdelq_16487, Parameter vfout_16483, ExprStmt target_24) {
		target_24.getExpr().(FunctionCall).getTarget().hasName("ArchiveEntry")
		and target_24.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfout_16483
		and target_24.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="catId"
		and target_24.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_24.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstatsextinfo_16483
		and target_24.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="dumpId"
		and target_24.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_24.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstatsextinfo_16483
		and target_24.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="name"
		and target_24.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_24.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstatsextinfo_16483
		and target_24.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getTarget().getName()="name"
		and target_24.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_24.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="namespace"
		and target_24.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_24.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstatsextinfo_16483
		and target_24.getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_24.getExpr().(FunctionCall).getArgument(6).(PointerFieldAccess).getTarget().getName()="rolname"
		and target_24.getExpr().(FunctionCall).getArgument(6).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstatsextinfo_16483
		and target_24.getExpr().(FunctionCall).getArgument(7).(Literal).getValue()="0"
		and target_24.getExpr().(FunctionCall).getArgument(8).(StringLiteral).getValue()="STATISTICS"
		and target_24.getExpr().(FunctionCall).getArgument(10).(PointerFieldAccess).getTarget().getName()="data"
		and target_24.getExpr().(FunctionCall).getArgument(10).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("PQExpBuffer")
		and target_24.getExpr().(FunctionCall).getArgument(11).(PointerFieldAccess).getTarget().getName()="data"
		and target_24.getExpr().(FunctionCall).getArgument(11).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdelq_16487
		and target_24.getExpr().(FunctionCall).getArgument(12).(Literal).getValue()="0"
		and target_24.getExpr().(FunctionCall).getArgument(13).(Literal).getValue()="0"
		and target_24.getExpr().(FunctionCall).getArgument(14).(Literal).getValue()="0"
		and target_24.getExpr().(FunctionCall).getArgument(15).(Literal).getValue()="0"
		and target_24.getExpr().(FunctionCall).getArgument(16).(Literal).getValue()="0"
}

predicate func_26(Parameter vstatsextinfo_16483, Variable vlabelq_16488, Parameter vfout_16483, ExprStmt target_26) {
		target_26.getExpr().(FunctionCall).getTarget().hasName("dumpComment")
		and target_26.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfout_16483
		and target_26.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="data"
		and target_26.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlabelq_16488
		and target_26.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="name"
		and target_26.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_26.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="namespace"
		and target_26.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_26.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstatsextinfo_16483
		and target_26.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="rolname"
		and target_26.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstatsextinfo_16483
		and target_26.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getTarget().getName()="catId"
		and target_26.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_26.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstatsextinfo_16483
		and target_26.getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_26.getExpr().(FunctionCall).getArgument(6).(ValueFieldAccess).getTarget().getName()="dumpId"
		and target_26.getExpr().(FunctionCall).getArgument(6).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_26.getExpr().(FunctionCall).getArgument(6).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstatsextinfo_16483
}

from Function func, Parameter vstatsextinfo_16483, Variable vdelq_16487, Variable vlabelq_16488, Parameter vfout_16483, FunctionCall target_0, StringLiteral target_1, FunctionCall target_2, ValueFieldAccess target_9, ValueFieldAccess target_10, FunctionCall target_11, ValueFieldAccess target_12, VariableAccess target_13, VariableAccess target_14, VariableAccess target_15, AssignExpr target_17, VariableAccess target_18, ExprStmt target_19, PointerFieldAccess target_20, ExprStmt target_21, PointerFieldAccess target_22, ExprStmt target_23, ExprStmt target_24, ExprStmt target_26
where
func_0(vfout_16483, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
and not func_4(func)
and not func_5(vfout_16483, target_24)
and func_9(vstatsextinfo_16483, target_9)
and func_10(vstatsextinfo_16483, target_10)
and func_11(vstatsextinfo_16483, vlabelq_16488, target_11)
and func_12(vstatsextinfo_16483, target_12)
and func_13(vfout_16483, target_13)
and func_14(vdelq_16487, target_14)
and func_15(vstatsextinfo_16483, vlabelq_16488, vfout_16483, target_15)
and func_17(vlabelq_16488, target_17)
and func_18(vlabelq_16488, target_26, target_18)
and func_19(vdelq_16487, func, target_19)
and func_20(func, target_20)
and func_21(vdelq_16487, func, target_21)
and func_22(vlabelq_16488, target_22)
and func_23(vlabelq_16488, func, target_23)
and func_24(vstatsextinfo_16483, vdelq_16487, vfout_16483, target_24)
and func_26(vstatsextinfo_16483, vlabelq_16488, vfout_16483, target_26)
and vstatsextinfo_16483.getType().hasName("StatsExtInfo *")
and vdelq_16487.getType().hasName("PQExpBuffer")
and vlabelq_16488.getType().hasName("PQExpBuffer")
and vfout_16483.getType().hasName("Archive *")
and vstatsextinfo_16483.getFunction() = func
and vdelq_16487.(LocalVariable).getFunction() = func
and vlabelq_16488.(LocalVariable).getFunction() = func
and vfout_16483.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
