/**
 * @name postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-dumpAttrDef
 * @id cpp/postgresql/3d2aed664ee8271fd6c721ed0aa10168cda112ea/dumpAttrDef
 * @description postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-src/bin/pg_dump/pg_dump.c-dumpAttrDef CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtbinfo_16264, FunctionCall target_0) {
		target_0.getTarget().hasName("fmtId")
		and not target_0.getTarget().hasName("fmtQualifiedId")
		and target_0.getArgument(0).(ValueFieldAccess).getTarget().getName()="name"
		and target_0.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_0.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtbinfo_16264
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("PQExpBuffer")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ALTER TABLE ONLY %s "
}

predicate func_1(Function func, StringLiteral target_1) {
		target_1.getValue()="ALTER TABLE %s."
		and not target_1.getValue()="ALTER TABLE %s "
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable vdelq_16267, FunctionCall target_2) {
		target_2.getTarget().hasName("appendPQExpBuffer")
		and not target_2.getTarget().hasName("free")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vdelq_16267
		and target_2.getArgument(1).(StringLiteral).getValue()="%s "
		and target_2.getArgument(2).(FunctionCall).getTarget().hasName("fmtId")
		and target_2.getArgument(2).(FunctionCall).getArgument(0) instanceof ValueFieldAccess
}

predicate func_3(Parameter vfout_16261, Variable vtbinfo_16264, ExprStmt target_12, LogicalOrExpr target_13, ArrayExpr target_14) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(VariableAccess).getType().hasName("char *")
		and target_3.getRValue().(FunctionCall).getTarget().hasName("pg_strdup")
		and target_3.getRValue().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("fmtQualifiedId")
		and target_3.getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="remoteVersion"
		and target_3.getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfout_16261
		and target_3.getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1) instanceof ValueFieldAccess
		and target_3.getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="name"
		and target_3.getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_3.getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtbinfo_16264
		and target_3.getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_13.getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_4(Parameter vfout_16261, ExprStmt target_12) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="remoteVersion"
		and target_4.getQualifier().(VariableAccess).getTarget()=vfout_16261
		and target_4.getQualifier().(VariableAccess).getLocation().isBefore(target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

*/
predicate func_7(Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(FunctionCall).getTarget().hasName("free")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char *")
		and (func.getEntryPoint().(BlockStmt).getStmt(21)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(21).getFollowingStmt()=target_7))
}

predicate func_9(Variable vtbinfo_16264, ValueFieldAccess target_9) {
		target_9.getTarget().getName()="name"
		and target_9.getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_9.getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="namespace"
		and target_9.getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_9.getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtbinfo_16264
}

predicate func_10(Variable vdelq_16267, FunctionCall target_10) {
		target_10.getTarget().hasName("fmtId")
		and target_10.getArgument(0) instanceof ValueFieldAccess
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdelq_16267
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
}

predicate func_11(Variable vtbinfo_16264, ValueFieldAccess target_15, ArrayExpr target_16, ValueFieldAccess target_11) {
		target_11.getTarget().getName()="name"
		and target_11.getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_11.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtbinfo_16264
		and target_11.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("fmtId")
		and target_15.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_11.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_16.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_12(Parameter vfout_16261, Variable vtbinfo_16264, Variable vdelq_16267, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("ArchiveEntry")
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfout_16261
		and target_12.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="catId"
		and target_12.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_12.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("AttrDefInfo *")
		and target_12.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="dumpId"
		and target_12.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_12.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("AttrDefInfo *")
		and target_12.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("char *")
		and target_12.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getTarget().getName()="name"
		and target_12.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_12.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="namespace"
		and target_12.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_12.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtbinfo_16264
		and target_12.getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_12.getExpr().(FunctionCall).getArgument(6).(PointerFieldAccess).getTarget().getName()="rolname"
		and target_12.getExpr().(FunctionCall).getArgument(6).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtbinfo_16264
		and target_12.getExpr().(FunctionCall).getArgument(7).(Literal).getValue()="0"
		and target_12.getExpr().(FunctionCall).getArgument(8).(StringLiteral).getValue()="DEFAULT"
		and target_12.getExpr().(FunctionCall).getArgument(10).(PointerFieldAccess).getTarget().getName()="data"
		and target_12.getExpr().(FunctionCall).getArgument(10).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("PQExpBuffer")
		and target_12.getExpr().(FunctionCall).getArgument(11).(PointerFieldAccess).getTarget().getName()="data"
		and target_12.getExpr().(FunctionCall).getArgument(11).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdelq_16267
		and target_12.getExpr().(FunctionCall).getArgument(12).(Literal).getValue()="0"
		and target_12.getExpr().(FunctionCall).getArgument(13).(Literal).getValue()="0"
		and target_12.getExpr().(FunctionCall).getArgument(14).(Literal).getValue()="0"
		and target_12.getExpr().(FunctionCall).getArgument(15).(Literal).getValue()="0"
		and target_12.getExpr().(FunctionCall).getArgument(16).(Literal).getValue()="0"
}

predicate func_13(Variable vtbinfo_16264, LogicalOrExpr target_13) {
		target_13.getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="dump"
		and target_13.getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_13.getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtbinfo_16264
		and target_13.getAnOperand().(PointerFieldAccess).getTarget().getName()="dataOnly"
		and target_13.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("DumpOptions *")
}

predicate func_14(Variable vtbinfo_16264, ArrayExpr target_14) {
		target_14.getArrayBase().(PointerFieldAccess).getTarget().getName()="attnames"
		and target_14.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtbinfo_16264
		and target_14.getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_14.getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_15(Variable vtbinfo_16264, ValueFieldAccess target_15) {
		target_15.getTarget().getName()="namespace"
		and target_15.getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_15.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtbinfo_16264
}

predicate func_16(Variable vtbinfo_16264, ArrayExpr target_16) {
		target_16.getArrayBase().(PointerFieldAccess).getTarget().getName()="attnames"
		and target_16.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtbinfo_16264
		and target_16.getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_16.getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

from Function func, Parameter vfout_16261, Variable vtbinfo_16264, Variable vdelq_16267, FunctionCall target_0, StringLiteral target_1, FunctionCall target_2, ValueFieldAccess target_9, FunctionCall target_10, ValueFieldAccess target_11, ExprStmt target_12, LogicalOrExpr target_13, ArrayExpr target_14, ValueFieldAccess target_15, ArrayExpr target_16
where
func_0(vtbinfo_16264, target_0)
and func_1(func, target_1)
and func_2(vdelq_16267, target_2)
and not func_3(vfout_16261, vtbinfo_16264, target_12, target_13, target_14)
and not func_7(func)
and func_9(vtbinfo_16264, target_9)
and func_10(vdelq_16267, target_10)
and func_11(vtbinfo_16264, target_15, target_16, target_11)
and func_12(vfout_16261, vtbinfo_16264, vdelq_16267, target_12)
and func_13(vtbinfo_16264, target_13)
and func_14(vtbinfo_16264, target_14)
and func_15(vtbinfo_16264, target_15)
and func_16(vtbinfo_16264, target_16)
and vfout_16261.getType().hasName("Archive *")
and vtbinfo_16264.getType().hasName("TableInfo *")
and vdelq_16267.getType().hasName("PQExpBuffer")
and vfout_16261.getFunction() = func
and vtbinfo_16264.(LocalVariable).getFunction() = func
and vdelq_16267.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
