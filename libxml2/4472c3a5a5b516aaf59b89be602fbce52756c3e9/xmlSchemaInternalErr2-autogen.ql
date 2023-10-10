/**
 * @name libxml2-4472c3a5a5b516aaf59b89be602fbce52756c3e9-xmlSchemaInternalErr2
 * @id cpp/libxml2/4472c3a5a5b516aaf59b89be602fbce52756c3e9/xmlSchemaInternalErr2
 * @description libxml2-4472c3a5a5b516aaf59b89be602fbce52756c3e9-xmlschemas.c-xmlSchemaInternalErr2 CVE-2016-4448
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="Internal error: "
		and not target_0.getValue()="Internal error: %s, "
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vactxt_2266, Parameter vstr1_2269, Parameter vstr2_2270, Variable vmsg_2272, FunctionCall target_1) {
		target_1.getTarget().hasName("xmlSchemaErr")
		and not target_1.getTarget().hasName("xmlSchemaErr3")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vactxt_2266
		and target_1.getArgument(2).(Literal).getValue()="0"
		and target_1.getArgument(3).(VariableAccess).getTarget()=vmsg_2272
		and target_1.getArgument(4).(VariableAccess).getTarget()=vstr1_2269
		and target_1.getArgument(5).(VariableAccess).getTarget()=vstr2_2270
}

predicate func_2(Parameter vactxt_2266, Parameter vstr1_2269, Parameter vstr2_2270, Variable vmsg_2272, FunctionCall target_2) {
		target_2.getTarget().hasName("xmlSchemaErr")
		and not target_2.getTarget().hasName("xmlSchemaErr3")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vactxt_2266
		and target_2.getArgument(2).(Literal).getValue()="0"
		and target_2.getArgument(3).(VariableAccess).getTarget()=vmsg_2272
		and target_2.getArgument(4).(VariableAccess).getTarget()=vstr1_2269
		and target_2.getArgument(5).(VariableAccess).getTarget()=vstr2_2270
}

predicate func_4(Variable vmsg_2272, VariableAccess target_4) {
		target_4.getTarget()=vmsg_2272
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_5(Parameter vfuncName_2267, VariableAccess target_5) {
		target_5.getTarget()=vfuncName_2267
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_6(Variable vmsg_2272, VariableAccess target_6) {
		target_6.getTarget()=vmsg_2272
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_7(Parameter vfuncName_2267, Variable vmsg_2272, Function func, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmsg_2272
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStrcat")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmsg_2272
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vfuncName_2267
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

predicate func_8(Variable vmsg_2272, Function func, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmsg_2272
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStrcat")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmsg_2272
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()=", "
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8
}

from Function func, Parameter vactxt_2266, Parameter vfuncName_2267, Parameter vstr1_2269, Parameter vstr2_2270, Variable vmsg_2272, StringLiteral target_0, FunctionCall target_1, FunctionCall target_2, VariableAccess target_4, VariableAccess target_5, VariableAccess target_6, ExprStmt target_7, ExprStmt target_8
where
func_0(func, target_0)
and func_1(vactxt_2266, vstr1_2269, vstr2_2270, vmsg_2272, target_1)
and func_2(vactxt_2266, vstr1_2269, vstr2_2270, vmsg_2272, target_2)
and func_4(vmsg_2272, target_4)
and func_5(vfuncName_2267, target_5)
and func_6(vmsg_2272, target_6)
and func_7(vfuncName_2267, vmsg_2272, func, target_7)
and func_8(vmsg_2272, func, target_8)
and vactxt_2266.getType().hasName("xmlSchemaAbstractCtxtPtr")
and vfuncName_2267.getType().hasName("const char *")
and vstr1_2269.getType().hasName("const xmlChar *")
and vstr2_2270.getType().hasName("const xmlChar *")
and vmsg_2272.getType().hasName("xmlChar *")
and vactxt_2266.getFunction() = func
and vfuncName_2267.getFunction() = func
and vstr1_2269.getFunction() = func
and vstr2_2270.getFunction() = func
and vmsg_2272.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
