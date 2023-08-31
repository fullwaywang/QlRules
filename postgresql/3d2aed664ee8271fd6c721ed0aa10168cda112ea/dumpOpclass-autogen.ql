/**
 * @name postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-dumpOpclass
 * @id cpp/postgresql/3d2aed664ee8271fd6c721ed0aa10168cda112ea/dumpOpclass
 * @description postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-src/bin/pg_dump/pg_dump.c-dumpOpclass CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlabelq_12737, VariableAccess target_0) {
		target_0.getTarget()=vlabelq_12737
		and target_0.getParent().(AssignExpr).getLValue() = target_0
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("createPQExpBuffer")
}

predicate func_1(Variable vlabelq_12737, VariableAccess target_1) {
		target_1.getTarget()=vlabelq_12737
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()=" USING %s"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("fmtId")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("char *")
}

predicate func_2(Parameter vopcinfo_12731, Variable vq_12735, Variable vlabelq_12737, VariableAccess target_2) {
		target_2.getTarget()=vlabelq_12737
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("binary_upgrade_extension_member")
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vq_12735
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopcinfo_12731
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="data"
}

predicate func_3(Parameter vfout_12731, Parameter vopcinfo_12731, Variable vlabelq_12737, VariableAccess target_3) {
		target_3.getTarget()=vlabelq_12737
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dumpComment")
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfout_12731
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="data"
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="name"
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="namespace"
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="rolname"
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopcinfo_12731
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getTarget().getName()="catId"
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopcinfo_12731
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ValueFieldAccess).getTarget().getName()="dumpId"
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopcinfo_12731
}

predicate func_4(Variable vlabelq_12737, VariableAccess target_4) {
		target_4.getTarget()=vlabelq_12737
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("destroyPQExpBuffer")
}

predicate func_5(Parameter vfout_12731, FunctionCall target_5) {
		target_5.getTarget().hasName("selectSourceSchema")
		and not target_5.getTarget().hasName("appendPQExpBufferStr")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vfout_12731
		and target_5.getArgument(1) instanceof ValueFieldAccess
}

predicate func_6(Variable vdelq_12736, FunctionCall target_6) {
		target_6.getTarget().hasName("fmtId")
		and not target_6.getTarget().hasName("fmtQualifiedId")
		and target_6.getArgument(0) instanceof ValueFieldAccess
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdelq_12736
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="DROP OPERATOR CLASS %s"
}

predicate func_7(Variable vdelq_12736, VariableAccess target_7) {
		target_7.getTarget()=vdelq_12736
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof FunctionCall
}

predicate func_8(Function func, FunctionCall target_8) {
		target_8.getTarget().hasName("fmtId")
		and not target_8.getTarget().hasName("fmtQualifiedId")
		and target_8.getArgument(0) instanceof ValueFieldAccess
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
		and target_8.getEnclosingFunction() = func
}

predicate func_9(Parameter vfout_12731, ExprStmt target_33) {
	exists(PointerFieldAccess target_9 |
		target_9.getTarget().getName()="remoteVersion"
		and target_9.getQualifier().(VariableAccess).getTarget()=vfout_12731
		and target_33.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_9.getQualifier().(VariableAccess).getLocation()))
}

predicate func_10(Parameter vfout_12731, ExprStmt target_34, RelationalOperation target_35) {
	exists(PointerFieldAccess target_10 |
		target_10.getTarget().getName()="remoteVersion"
		and target_10.getQualifier().(VariableAccess).getTarget()=vfout_12731
		and target_34.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_10.getQualifier().(VariableAccess).getLocation())
		and target_10.getQualifier().(VariableAccess).getLocation().isBefore(target_35.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_13(Parameter vopcinfo_12731, PointerFieldAccess target_13) {
		target_13.getTarget().getName()="dobj"
		and target_13.getQualifier().(ValueFieldAccess).getTarget().getName()="namespace"
		and target_13.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_13.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopcinfo_12731
		and target_13.getParent().(ValueFieldAccess).getParent().(FunctionCall).getParent().(NEExpr).getAnOperand() instanceof FunctionCall
}

*/
predicate func_14(Parameter vopcinfo_12731, ValueFieldAccess target_14) {
		target_14.getTarget().getName()="name"
		and target_14.getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_14.getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="namespace"
		and target_14.getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_14.getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopcinfo_12731
}

predicate func_15(Parameter vopcinfo_12731, ValueFieldAccess target_15) {
		target_15.getTarget().getName()="name"
		and target_15.getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_15.getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="namespace"
		and target_15.getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_15.getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopcinfo_12731
}

predicate func_16(Parameter vopcinfo_12731, Variable vdelq_12736, FunctionCall target_16) {
		target_16.getTarget().hasName("fmtId")
		and target_16.getArgument(0).(ValueFieldAccess).getTarget().getName()="name"
		and target_16.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_16.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopcinfo_12731
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdelq_12736
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
}

predicate func_17(Parameter vopcinfo_12731, ValueFieldAccess target_17) {
		target_17.getTarget().getName()="name"
		and target_17.getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_17.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopcinfo_12731
}

predicate func_18(Parameter vopcinfo_12731, ValueFieldAccess target_18) {
		target_18.getTarget().getName()="name"
		and target_18.getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_18.getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="namespace"
		and target_18.getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_18.getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopcinfo_12731
}

predicate func_19(Variable vopcfamilynsp_12761, Variable vq_12735, EqualityOperation target_36, ExprStmt target_19) {
		target_19.getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_19.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vq_12735
		and target_19.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s."
		and target_19.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("fmtId")
		and target_19.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vopcfamilynsp_12761
		and target_19.getParent().(IfStmt).getCondition()=target_36
}

predicate func_20(Parameter vopcinfo_12731, PointerFieldAccess target_20) {
		target_20.getTarget().getName()="dobj"
		and target_20.getQualifier().(ValueFieldAccess).getTarget().getName()="namespace"
		and target_20.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_20.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopcinfo_12731
		and target_20.getParent().(ValueFieldAccess).getParent().(FunctionCall).getParent().(NEExpr).getAnOperand() instanceof FunctionCall
}

predicate func_21(Variable vsortfamilynsp_12767, Variable vq_12735, EqualityOperation target_37, ExprStmt target_21) {
		target_21.getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_21.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vq_12735
		and target_21.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s."
		and target_21.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("fmtId")
		and target_21.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsortfamilynsp_12767
		and target_21.getParent().(IfStmt).getCondition()=target_37
}

predicate func_22(Parameter vopcinfo_12731, ValueFieldAccess target_22) {
		target_22.getTarget().getName()="name"
		and target_22.getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_22.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopcinfo_12731
}

predicate func_23(Parameter vfout_12731, VariableAccess target_23) {
		target_23.getTarget()=vfout_12731
		and target_23.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_24(Variable vq_12735, VariableAccess target_24) {
		target_24.getTarget()=vq_12735
		and target_24.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_26(Parameter vfout_12731, Parameter vopcinfo_12731, Variable vlabelq_12737, VariableAccess target_26) {
		target_26.getTarget()=vfout_12731
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dumpComment")
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="data"
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlabelq_12737
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="name"
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="namespace"
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopcinfo_12731
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="rolname"
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopcinfo_12731
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getTarget().getName()="catId"
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopcinfo_12731
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ValueFieldAccess).getTarget().getName()="dumpId"
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopcinfo_12731
}

predicate func_27(Function func, ExprStmt target_27) {
		target_27.getExpr() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_27
}

predicate func_29(Variable vq_12735, Function func, ExprStmt target_29) {
		target_29.getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_29.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vq_12735
		and target_29.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_29.getExpr().(FunctionCall).getArgument(2) instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_29
}

predicate func_30(Variable vopcfamilynsp_12761, RelationalOperation target_38, IfStmt target_30) {
		target_30.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_30.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vopcfamilynsp_12761
		and target_30.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1) instanceof ValueFieldAccess
		and target_30.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_30.getThen() instanceof ExprStmt
		and target_30.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_38
}

predicate func_31(Variable vsortfamilynsp_12767, RelationalOperation target_39, IfStmt target_31) {
		target_31.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_31.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsortfamilynsp_12767
		and target_31.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="name"
		and target_31.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_31.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="namespace"
		and target_31.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_31.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_31.getThen() instanceof ExprStmt
		and target_31.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_39
}

predicate func_32(Variable vlabelq_12737, FunctionCall target_32) {
		target_32.getTarget().hasName("appendPQExpBuffer")
		and target_32.getArgument(0).(VariableAccess).getTarget()=vlabelq_12737
		and target_32.getArgument(1).(StringLiteral).getValue()="OPERATOR CLASS %s"
		and target_32.getArgument(2).(FunctionCall).getTarget().hasName("fmtId")
		and target_32.getArgument(2).(FunctionCall).getArgument(0) instanceof ValueFieldAccess
}

predicate func_33(Parameter vfout_12731, Parameter vopcinfo_12731, Variable vq_12735, Variable vdelq_12736, ExprStmt target_33) {
		target_33.getExpr().(FunctionCall).getTarget().hasName("ArchiveEntry")
		and target_33.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfout_12731
		and target_33.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="catId"
		and target_33.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_33.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopcinfo_12731
		and target_33.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="dumpId"
		and target_33.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_33.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopcinfo_12731
		and target_33.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="name"
		and target_33.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_33.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopcinfo_12731
		and target_33.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getTarget().getName()="name"
		and target_33.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_33.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="namespace"
		and target_33.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_33.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopcinfo_12731
		and target_33.getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_33.getExpr().(FunctionCall).getArgument(6).(PointerFieldAccess).getTarget().getName()="rolname"
		and target_33.getExpr().(FunctionCall).getArgument(6).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopcinfo_12731
		and target_33.getExpr().(FunctionCall).getArgument(7).(Literal).getValue()="0"
		and target_33.getExpr().(FunctionCall).getArgument(8).(StringLiteral).getValue()="OPERATOR CLASS"
		and target_33.getExpr().(FunctionCall).getArgument(10).(PointerFieldAccess).getTarget().getName()="data"
		and target_33.getExpr().(FunctionCall).getArgument(10).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_12735
		and target_33.getExpr().(FunctionCall).getArgument(11).(PointerFieldAccess).getTarget().getName()="data"
		and target_33.getExpr().(FunctionCall).getArgument(11).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdelq_12736
		and target_33.getExpr().(FunctionCall).getArgument(12).(Literal).getValue()="0"
		and target_33.getExpr().(FunctionCall).getArgument(13).(Literal).getValue()="0"
		and target_33.getExpr().(FunctionCall).getArgument(14).(Literal).getValue()="0"
		and target_33.getExpr().(FunctionCall).getArgument(15).(Literal).getValue()="0"
		and target_33.getExpr().(FunctionCall).getArgument(16).(Literal).getValue()="0"
}

predicate func_34(Parameter vfout_12731, ExprStmt target_34) {
		target_34.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("PGresult *")
		and target_34.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecuteSqlQueryForSingleRow")
		and target_34.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfout_12731
		and target_34.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="data"
		and target_34.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("PQExpBuffer")
}

predicate func_35(Parameter vfout_12731, RelationalOperation target_35) {
		 (target_35 instanceof GEExpr or target_35 instanceof LEExpr)
		and target_35.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="remoteVersion"
		and target_35.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfout_12731
		and target_35.getLesserOperand().(Literal).getValue()="90100"
}

predicate func_36(EqualityOperation target_36) {
		target_36.getAnOperand() instanceof FunctionCall
		and target_36.getAnOperand() instanceof Literal
}

predicate func_37(EqualityOperation target_37) {
		target_37.getAnOperand() instanceof FunctionCall
		and target_37.getAnOperand() instanceof Literal
}

predicate func_38(RelationalOperation target_38) {
		 (target_38 instanceof GTExpr or target_38 instanceof LTExpr)
		and target_38.getGreaterOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_38.getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("char *")
		and target_38.getLesserOperand().(Literal).getValue()="0"
}

predicate func_39(RelationalOperation target_39) {
		 (target_39 instanceof GTExpr or target_39 instanceof LTExpr)
		and target_39.getGreaterOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_39.getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("char *")
		and target_39.getLesserOperand().(Literal).getValue()="0"
}

from Function func, Variable vopcfamilynsp_12761, Variable vsortfamilynsp_12767, Parameter vfout_12731, Parameter vopcinfo_12731, Variable vq_12735, Variable vdelq_12736, Variable vlabelq_12737, VariableAccess target_0, VariableAccess target_1, VariableAccess target_2, VariableAccess target_3, VariableAccess target_4, FunctionCall target_5, FunctionCall target_6, VariableAccess target_7, FunctionCall target_8, ValueFieldAccess target_14, ValueFieldAccess target_15, FunctionCall target_16, ValueFieldAccess target_17, ValueFieldAccess target_18, ExprStmt target_19, PointerFieldAccess target_20, ExprStmt target_21, ValueFieldAccess target_22, VariableAccess target_23, VariableAccess target_24, VariableAccess target_26, ExprStmt target_27, ExprStmt target_29, IfStmt target_30, IfStmt target_31, FunctionCall target_32, ExprStmt target_33, ExprStmt target_34, RelationalOperation target_35, EqualityOperation target_36, EqualityOperation target_37, RelationalOperation target_38, RelationalOperation target_39
where
func_0(vlabelq_12737, target_0)
and func_1(vlabelq_12737, target_1)
and func_2(vopcinfo_12731, vq_12735, vlabelq_12737, target_2)
and func_3(vfout_12731, vopcinfo_12731, vlabelq_12737, target_3)
and func_4(vlabelq_12737, target_4)
and func_5(vfout_12731, target_5)
and func_6(vdelq_12736, target_6)
and func_7(vdelq_12736, target_7)
and func_8(func, target_8)
and not func_9(vfout_12731, target_33)
and not func_10(vfout_12731, target_34, target_35)
and func_14(vopcinfo_12731, target_14)
and func_15(vopcinfo_12731, target_15)
and func_16(vopcinfo_12731, vdelq_12736, target_16)
and func_17(vopcinfo_12731, target_17)
and func_18(vopcinfo_12731, target_18)
and func_19(vopcfamilynsp_12761, vq_12735, target_36, target_19)
and func_20(vopcinfo_12731, target_20)
and func_21(vsortfamilynsp_12767, vq_12735, target_37, target_21)
and func_22(vopcinfo_12731, target_22)
and func_23(vfout_12731, target_23)
and func_24(vq_12735, target_24)
and func_26(vfout_12731, vopcinfo_12731, vlabelq_12737, target_26)
and func_27(func, target_27)
and func_29(vq_12735, func, target_29)
and func_30(vopcfamilynsp_12761, target_38, target_30)
and func_31(vsortfamilynsp_12767, target_39, target_31)
and func_32(vlabelq_12737, target_32)
and func_33(vfout_12731, vopcinfo_12731, vq_12735, vdelq_12736, target_33)
and func_34(vfout_12731, target_34)
and func_35(vfout_12731, target_35)
and func_36(target_36)
and func_37(target_37)
and func_38(target_38)
and func_39(target_39)
and vopcfamilynsp_12761.getType().hasName("char *")
and vsortfamilynsp_12767.getType().hasName("char *")
and vfout_12731.getType().hasName("Archive *")
and vopcinfo_12731.getType().hasName("OpclassInfo *")
and vq_12735.getType().hasName("PQExpBuffer")
and vdelq_12736.getType().hasName("PQExpBuffer")
and vlabelq_12737.getType().hasName("PQExpBuffer")
and vopcfamilynsp_12761.(LocalVariable).getFunction() = func
and vsortfamilynsp_12767.(LocalVariable).getFunction() = func
and vfout_12731.getFunction() = func
and vopcinfo_12731.getFunction() = func
and vq_12735.(LocalVariable).getFunction() = func
and vdelq_12736.(LocalVariable).getFunction() = func
and vlabelq_12737.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
