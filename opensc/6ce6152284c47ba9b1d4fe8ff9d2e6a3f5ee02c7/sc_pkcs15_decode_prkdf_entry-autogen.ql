/**
 * @name opensc-6ce6152284c47ba9b1d4fe8ff9d2e6a3f5ee02c7-sc_pkcs15_decode_prkdf_entry
 * @id cpp/opensc/6ce6152284c47ba9b1d4fe8ff9d2e6a3f5ee02c7/sc-pkcs15-decode-prkdf-entry
 * @description opensc-6ce6152284c47ba9b1d4fe8ff9d2e6a3f5ee02c7-src/libopensc/pkcs15-prkey.c-sc_pkcs15_decode_prkdf_entry CVE-2019-19480
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vinfo_175, ExprStmt target_3, ValueFieldAccess target_4) {
	exists(ValueFieldAccess target_0 |
		target_0.getTarget().getName()="value"
		and target_0.getQualifier().(ValueFieldAccess).getTarget().getName()="subject"
		and target_0.getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfo_175
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vasn1_com_prkey_attr_181, RelationalOperation target_5, IfStmt target_1) {
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vasn1_com_prkey_attr_181
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="flags"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vasn1_com_prkey_attr_181
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="parm"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vasn1_com_prkey_attr_181
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

/*predicate func_2(Variable vasn1_com_prkey_attr_181, ValueFieldAccess target_2) {
		target_2.getTarget().getName()="parm"
		and target_2.getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vasn1_com_prkey_attr_181
		and target_2.getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

*/
predicate func_3(Variable vinfo_175, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="native"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfo_175
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_4(Variable vinfo_175, ValueFieldAccess target_4) {
		target_4.getTarget().getName()="path"
		and target_4.getQualifier().(VariableAccess).getTarget()=vinfo_175
}

predicate func_5(RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getGreaterOperand().(Literal).getValue()="0"
}

from Function func, Variable vinfo_175, Variable vasn1_com_prkey_attr_181, IfStmt target_1, ExprStmt target_3, ValueFieldAccess target_4, RelationalOperation target_5
where
not func_0(vinfo_175, target_3, target_4)
and func_1(vasn1_com_prkey_attr_181, target_5, target_1)
and func_3(vinfo_175, target_3)
and func_4(vinfo_175, target_4)
and func_5(target_5)
and vinfo_175.getType().hasName("sc_pkcs15_prkey_info")
and vasn1_com_prkey_attr_181.getType().hasName("sc_asn1_entry[2]")
and vinfo_175.getParentScope+() = func
and vasn1_com_prkey_attr_181.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
