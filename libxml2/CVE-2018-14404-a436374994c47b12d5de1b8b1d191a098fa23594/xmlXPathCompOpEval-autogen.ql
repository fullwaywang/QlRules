/**
 * @name libxml2-a436374994c47b12d5de1b8b1d191a098fa23594-xmlXPathCompOpEval
 * @id cpp/libxml2/a436374994c47b12d5de1b8b1d191a098fa23594/xmlXPathCompOpEval
 * @description libxml2-a436374994c47b12d5de1b8b1d191a098fa23594-xmlXPathCompOpEval CVE-2018-14404
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable varg2_13217, Parameter vctxt_13212) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="value"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_13212
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ExprStmt).getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getTarget().getName()="boolval"
		and target_0.getThen().(ExprStmt).getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="value"
		and target_0.getThen().(ExprStmt).getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_13212
		and target_0.getThen().(ExprStmt).getExpr().(AssignAndExpr).getRValue().(PointerFieldAccess).getTarget().getName()="boolval"
		and target_0.getThen().(ExprStmt).getExpr().(AssignAndExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=varg2_13217)
}

predicate func_2(Variable varg2_13217, Parameter vctxt_13212) {
	exists(IfStmt target_2 |
		target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="value"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_13212
		and target_2.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="boolval"
		and target_2.getThen().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="value"
		and target_2.getThen().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_13212
		and target_2.getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(PointerFieldAccess).getTarget().getName()="boolval"
		and target_2.getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=varg2_13217)
}

predicate func_4(Parameter vctxt_13212) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("valuePop")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vctxt_13212)
}

predicate func_8(Variable varg1_13217) {
	exists(VariableAccess target_8 |
		target_8.getTarget()=varg1_13217)
}

predicate func_9(Variable varg1_13217) {
	exists(AssignExpr target_9 |
		target_9.getLValue().(VariableAccess).getTarget()=varg1_13217
		and target_9.getRValue() instanceof FunctionCall)
}

predicate func_10(Variable varg1_13217, Variable varg2_13217) {
	exists(ExprStmt target_10 |
		target_10.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="boolval"
		and target_10.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=varg1_13217
		and target_10.getExpr().(AssignOrExpr).getRValue().(PointerFieldAccess).getTarget().getName()="boolval"
		and target_10.getExpr().(AssignOrExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=varg2_13217)
}

predicate func_12(Variable varg1_13217, Parameter vctxt_13212) {
	exists(ExprStmt target_12 |
		target_12.getExpr().(FunctionCall).getTarget().hasName("valuePush")
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_13212
		and target_12.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=varg1_13217)
}

predicate func_13(Variable varg1_13217) {
	exists(ExprStmt target_13 |
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=varg1_13217
		and target_13.getExpr().(AssignExpr).getRValue() instanceof FunctionCall)
}

from Function func, Variable varg1_13217, Variable varg2_13217, Parameter vctxt_13212
where
not func_0(varg2_13217, vctxt_13212)
and not func_2(varg2_13217, vctxt_13212)
and func_4(vctxt_13212)
and func_8(varg1_13217)
and func_9(varg1_13217)
and func_10(varg1_13217, varg2_13217)
and func_12(varg1_13217, vctxt_13212)
and func_13(varg1_13217)
and varg1_13217.getType().hasName("xmlXPathObjectPtr")
and varg2_13217.getType().hasName("xmlXPathObjectPtr")
and vctxt_13212.getType().hasName("xmlXPathParserContextPtr")
and varg1_13217.getParentScope+() = func
and varg2_13217.getParentScope+() = func
and vctxt_13212.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
