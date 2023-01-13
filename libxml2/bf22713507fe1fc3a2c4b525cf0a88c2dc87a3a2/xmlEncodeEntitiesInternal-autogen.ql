/**
 * @name libxml2-bf22713507fe1fc3a2c4b525cf0a88c2dc87a3a2-xmlEncodeEntitiesInternal
 * @id cpp/libxml2/bf22713507fe1fc3a2c4b525cf0a88c2dc87a3a2/xmlEncodeEntitiesInternal
 * @description libxml2-bf22713507fe1fc3a2c4b525cf0a88c2dc87a3a2-xmlEncodeEntitiesInternal CVE-2021-3517
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdoc_599, Variable vcur_600, Variable vbuf_708) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vcur_600
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="192"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlEntitiesErr")
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdoc_599
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStrdup")
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("snprintf")
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_708
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof PointerDereferenceExpr)
}

predicate func_1(Parameter vdoc_599, Variable vcur_600, Variable vbuf_708) {
	exists(PointerDereferenceExpr target_1 |
		target_1.getOperand().(VariableAccess).getTarget()=vcur_600
		and target_1.getParent().(LTExpr).getGreaterOperand().(HexLiteral).getValue()="192"
		and target_1.getParent().(LTExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlEntitiesErr")
		and target_1.getParent().(LTExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdoc_599
		and target_1.getParent().(LTExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdoc_599
		and target_1.getParent().(LTExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_708
		and target_1.getParent().(LTExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vcur_600)
}

predicate func_3(Parameter vdoc_599, Variable vcur_600, Variable vbuf_708) {
	exists(RelationalOperation target_3 |
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlEntitiesErr")
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdoc_599
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdoc_599
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStrdup")
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_708
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vcur_600)
}

from Function func, Parameter vdoc_599, Variable vcur_600, Variable vout_602, Variable vbuf_708
where
not func_0(vdoc_599, vcur_600, vbuf_708)
and func_1(vdoc_599, vcur_600, vbuf_708)
and func_3(vdoc_599, vcur_600, vbuf_708)
and vdoc_599.getType().hasName("xmlDocPtr")
and vcur_600.getType().hasName("const xmlChar *")
and vout_602.getType().hasName("xmlChar *")
and vbuf_708.getType().hasName("char[11]")
and vdoc_599.getParentScope+() = func
and vcur_600.getParentScope+() = func
and vout_602.getParentScope+() = func
and vbuf_708.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
