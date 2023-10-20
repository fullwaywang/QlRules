/**
 * @name curl-7214288898f5625a6cc196e22a74232eada7861c-Curl_follow
 * @id cpp/curl/7214288898f5625a6cc196e22a74232eada7861c/Curl-follow
 * @description curl-7214288898f5625a6cc196e22a74232eada7861c-lib/transfer.c-Curl_follow CVE-2021-22876
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(VariableAccess).getType().hasName("CURLU *")
		and target_0.getRValue().(FunctionCall).getTarget().hasName("curl_url")
		and target_0.getEnclosingFunction() = func)
}

predicate func_2(Variable vuc_1566, ValueFieldAccess target_16) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vuc_1566
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("curl_url_set")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("CURLU *")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2) instanceof ValueFieldAccess
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(5)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16)
}

predicate func_3(Variable vuc_1566, ValueFieldAccess target_16) {
	exists(IfStmt target_3 |
		target_3.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vuc_1566
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vuc_1566
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("curl_url_set")
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("CURLU *")
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(6)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16)
}

predicate func_4(Variable vuc_1566, ValueFieldAccess target_16) {
	exists(IfStmt target_4 |
		target_4.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vuc_1566
		and target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vuc_1566
		and target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("curl_url_set")
		and target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("CURLU *")
		and target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(7)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16)
}

predicate func_5(Variable vuc_1566, ValueFieldAccess target_16) {
	exists(IfStmt target_5 |
		target_5.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vuc_1566
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vuc_1566
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("curl_url_set")
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("CURLU *")
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(8)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16)
}

predicate func_6(Variable vuc_1566, ValueFieldAccess target_16) {
	exists(IfStmt target_6 |
		target_6.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vuc_1566
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vuc_1566
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("curl_url_get")
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("CURLU *")
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("char *")
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(9)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16)
}

predicate func_7(ValueFieldAccess target_16, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(FunctionCall).getTarget().hasName("curl_url_cleanup")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("CURLU *")
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(10)=target_7
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Variable vuc_1566, ValueFieldAccess target_16) {
	exists(IfStmt target_8 |
		target_8.getCondition().(LogicalOrExpr).getAnOperand().(VariableAccess).getTarget()=vuc_1566
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("char *")
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(11)=target_8
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16)
}

predicate func_9(Parameter vdata_1551, ValueFieldAccess target_16, ExprStmt target_17) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="referer"
		and target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1551
		and target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("char *")
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(12)=target_9
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
		and target_17.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_11(Parameter vdata_1551, PointerFieldAccess target_11) {
		target_11.getTarget().getName()="state"
		and target_11.getQualifier().(VariableAccess).getTarget()=vdata_1551
}

*/
predicate func_12(Parameter vdata_1551, ValueFieldAccess target_12) {
		target_12.getTarget().getName()="url"
		and target_12.getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_12.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1551
}

predicate func_13(Parameter vdata_1551, PointerFieldAccess target_13) {
		target_13.getTarget().getName()="state"
		and target_13.getQualifier().(VariableAccess).getTarget()=vdata_1551
}

predicate func_14(Variable vCurl_cstrdup, VariableCall target_14) {
		target_14.getExpr().(VariableAccess).getTarget()=vCurl_cstrdup
		and target_14.getArgument(0) instanceof ValueFieldAccess
}

predicate func_15(Parameter vdata_1551, ValueFieldAccess target_12, ExprStmt target_18, ValueFieldAccess target_15) {
		target_15.getTarget().getName()="referer"
		and target_15.getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_15.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1551
		and target_12.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_15.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_15.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_18.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_16(Parameter vdata_1551, ValueFieldAccess target_16) {
		target_16.getTarget().getName()="http_auto_referer"
		and target_16.getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_16.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1551
}

predicate func_17(Parameter vdata_1551, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="referer_alloc"
		and target_17.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_17.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1551
		and target_17.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_18(Parameter vdata_1551, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="referer_alloc"
		and target_18.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_18.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1551
		and target_18.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

from Function func, Parameter vdata_1551, Variable vuc_1566, Variable vCurl_cstrdup, ValueFieldAccess target_12, PointerFieldAccess target_13, VariableCall target_14, ValueFieldAccess target_15, ValueFieldAccess target_16, ExprStmt target_17, ExprStmt target_18
where
not func_0(func)
and not func_2(vuc_1566, target_16)
and not func_3(vuc_1566, target_16)
and not func_4(vuc_1566, target_16)
and not func_5(vuc_1566, target_16)
and not func_6(vuc_1566, target_16)
and not func_7(target_16, func)
and not func_8(vuc_1566, target_16)
and not func_9(vdata_1551, target_16, target_17)
and func_12(vdata_1551, target_12)
and func_13(vdata_1551, target_13)
and func_14(vCurl_cstrdup, target_14)
and func_15(vdata_1551, target_12, target_18, target_15)
and func_16(vdata_1551, target_16)
and func_17(vdata_1551, target_17)
and func_18(vdata_1551, target_18)
and vdata_1551.getType().hasName("Curl_easy *")
and vuc_1566.getType().hasName("CURLUcode")
and vCurl_cstrdup.getType().hasName("curl_strdup_callback")
and vdata_1551.getParentScope+() = func
and vuc_1566.getParentScope+() = func
and not vCurl_cstrdup.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
