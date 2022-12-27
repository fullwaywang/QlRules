/**
 * @name libxml2-652dd12a858989b14eed4e84e453059cd3ba340e-xmlAddRef
 * @id cpp/libxml2/652dd12a858989b14eed4e84e453059cd3ba340e/xmlAddRef
 * @description libxml2-652dd12a858989b14eed4e84e453059cd3ba340e-xmlAddRef CVE-2022-23308
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_2973) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("xmlIsStreaming")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vctxt_2973)
}

predicate func_2(Parameter vattr_2974, Variable vret_2975, Parameter vctxt_2973) {
	exists(LogicalAndExpr target_2 |
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vctxt_2973
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="vstateNr"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_2973
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="name"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_2975
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStrdup")
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattr_2974
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="attr"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_2975
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0")
}

from Function func, Parameter vattr_2974, Variable vret_2975, Parameter vctxt_2973
where
not func_0(vctxt_2973)
and func_2(vattr_2974, vret_2975, vctxt_2973)
and vattr_2974.getType().hasName("xmlAttrPtr")
and vret_2975.getType().hasName("xmlRefPtr")
and vctxt_2973.getType().hasName("xmlValidCtxtPtr")
and vattr_2974.getParentScope+() = func
and vret_2975.getParentScope+() = func
and vctxt_2973.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
