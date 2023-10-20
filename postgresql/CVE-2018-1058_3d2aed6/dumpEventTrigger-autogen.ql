/**
 * @name postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-dumpEventTrigger
 * @id cpp/postgresql/3d2aed664ee8271fd6c721ed0aa10168cda112ea/dumpEventTrigger
 * @description postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-src/bin/pg_dump/pg_dump.c-dumpEventTrigger CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlabelq_17407, FunctionCall target_0) {
		target_0.getTarget().hasName("appendPQExpBuffer")
		and not target_0.getTarget().hasName("free")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vlabelq_17407
		and target_0.getArgument(1).(StringLiteral).getValue()="EVENT TRIGGER %s"
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

predicate func_9(Parameter vevtinfo_17402, FunctionCall target_9) {
		target_9.getTarget().hasName("fmtId")
		and target_9.getArgument(0).(ValueFieldAccess).getTarget().getName()="name"
		and target_9.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_9.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vevtinfo_17402
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPQExpBufferStr")
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("PQExpBuffer")
}

predicate func_11(Variable vlabelq_17407, AssignExpr target_11) {
		target_11.getLValue().(VariableAccess).getTarget()=vlabelq_17407
		and target_11.getRValue().(FunctionCall).getTarget().hasName("createPQExpBuffer")
}

predicate func_12(Parameter vevtinfo_17402, EqualityOperation target_18, SwitchStmt target_19, FunctionCall target_12) {
		target_12.getTarget().hasName("fmtId")
		and target_12.getArgument(0).(ValueFieldAccess).getTarget().getName()="name"
		and target_12.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_12.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vevtinfo_17402
		and target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("PQExpBuffer")
		and target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="\nALTER EVENT TRIGGER %s "
		and target_18.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_12.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_19.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_13(Parameter vevtinfo_17402, SwitchStmt target_19, ValueFieldAccess target_15, FunctionCall target_13) {
		target_13.getTarget().hasName("fmtId")
		and target_13.getArgument(0).(ValueFieldAccess).getTarget().getName()="name"
		and target_13.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_13.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vevtinfo_17402
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("PQExpBuffer")
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="DROP EVENT TRIGGER %s;\n"
		and target_19.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_13.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_15.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_14(Function func, ExprStmt target_14) {
		target_14.getExpr() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_14
}

predicate func_15(Parameter vevtinfo_17402, ValueFieldAccess target_20, BitwiseAndExpr target_21, ValueFieldAccess target_15) {
		target_15.getTarget().getName()="name"
		and target_15.getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_15.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vevtinfo_17402
		and target_15.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("fmtId")
		and target_20.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_15.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_15.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_21.getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_16(Variable vlabelq_17407, PointerFieldAccess target_16) {
		target_16.getTarget().getName()="data"
		and target_16.getQualifier().(VariableAccess).getTarget()=vlabelq_17407
}

predicate func_17(Variable vlabelq_17407, FunctionCall target_17) {
		target_17.getTarget().hasName("destroyPQExpBuffer")
		and target_17.getArgument(0).(VariableAccess).getTarget()=vlabelq_17407
}

predicate func_18(Parameter vevtinfo_17402, EqualityOperation target_18) {
		target_18.getAnOperand().(PointerFieldAccess).getTarget().getName()="evtenabled"
		and target_18.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vevtinfo_17402
		and target_18.getAnOperand().(CharLiteral).getValue()="79"
}

predicate func_19(Parameter vevtinfo_17402, SwitchStmt target_19) {
		target_19.getExpr().(PointerFieldAccess).getTarget().getName()="evtenabled"
		and target_19.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vevtinfo_17402
		and target_19.getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr().(CharLiteral).getValue()="68"
		and target_19.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPQExpBufferStr")
		and target_19.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("PQExpBuffer")
		and target_19.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="DISABLE"
		and target_19.getStmt().(BlockStmt).getStmt(3).(SwitchCase).getExpr().(CharLiteral).getValue()="65"
}

predicate func_20(Parameter vevtinfo_17402, ValueFieldAccess target_20) {
		target_20.getTarget().getName()="name"
		and target_20.getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_20.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vevtinfo_17402
}

predicate func_21(Parameter vevtinfo_17402, BitwiseAndExpr target_21) {
		target_21.getLeftOperand().(ValueFieldAccess).getTarget().getName()="dump"
		and target_21.getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_21.getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vevtinfo_17402
		and target_21.getRightOperand().(BinaryBitwiseOperation).getValue()="1"
}

from Function func, Parameter vevtinfo_17402, Variable vlabelq_17407, FunctionCall target_0, FunctionCall target_9, AssignExpr target_11, FunctionCall target_12, FunctionCall target_13, ExprStmt target_14, ValueFieldAccess target_15, PointerFieldAccess target_16, FunctionCall target_17, EqualityOperation target_18, SwitchStmt target_19, ValueFieldAccess target_20, BitwiseAndExpr target_21
where
func_0(vlabelq_17407, target_0)
and not func_2(func)
and func_9(vevtinfo_17402, target_9)
and func_11(vlabelq_17407, target_11)
and func_12(vevtinfo_17402, target_18, target_19, target_12)
and func_13(vevtinfo_17402, target_19, target_15, target_13)
and func_14(func, target_14)
and func_15(vevtinfo_17402, target_20, target_21, target_15)
and func_16(vlabelq_17407, target_16)
and func_17(vlabelq_17407, target_17)
and func_18(vevtinfo_17402, target_18)
and func_19(vevtinfo_17402, target_19)
and func_20(vevtinfo_17402, target_20)
and func_21(vevtinfo_17402, target_21)
and vevtinfo_17402.getType().hasName("EventTriggerInfo *")
and vlabelq_17407.getType().hasName("PQExpBuffer")
and vevtinfo_17402.getFunction() = func
and vlabelq_17407.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
