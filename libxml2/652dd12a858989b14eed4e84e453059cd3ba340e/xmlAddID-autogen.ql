/**
 * @name libxml2-652dd12a858989b14eed4e84e453059cd3ba340e-xmlAddID
 * @id cpp/libxml2/652dd12a858989b14eed4e84e453059cd3ba340e/xmlAddID
 * @description libxml2-652dd12a858989b14eed4e84e453059cd3ba340e-xmlAddID CVE-2022-23308
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vvalue_2645) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalue_2645
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_1(Parameter vctxt_2645) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("xmlIsStreaming")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vctxt_2645)
}

predicate func_2(Parameter vvalue_2645) {
	exists(EqualityOperation target_2 |
		target_2.getAnOperand().(VariableAccess).getTarget()=vvalue_2645
		and target_2.getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_3(Parameter vdoc_2645, Parameter vattr_2646, Variable vret_2647, Parameter vctxt_2645) {
	exists(EqualityOperation target_3 |
		target_3.getAnOperand().(VariableAccess).getTarget()=vctxt_2645
		and target_3.getAnOperand().(Literal).getValue()="0"
		and target_3.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="dict"
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdoc_2645
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="name"
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_2647
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlDictLookup")
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="dict"
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdoc_2645
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattr_2646
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="name"
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_2647
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStrdup")
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattr_2646)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="0"
		and target_4.getEnclosingFunction() = func)
}

predicate func_6(Parameter vdoc_2645, Parameter vattr_2646, Variable vret_2647, Parameter vctxt_2645) {
	exists(LogicalAndExpr target_6 |
		target_6.getAnOperand() instanceof EqualityOperation
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="vstateNr"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_2645
		and target_6.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="dict"
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdoc_2645
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="name"
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_2647
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlDictLookup")
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="dict"
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdoc_2645
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattr_2646
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="name"
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_2647
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStrdup")
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattr_2646)
}

from Function func, Parameter vdoc_2645, Parameter vvalue_2645, Parameter vattr_2646, Variable vret_2647, Parameter vctxt_2645
where
not func_0(vvalue_2645)
and not func_1(vctxt_2645)
and func_2(vvalue_2645)
and func_3(vdoc_2645, vattr_2646, vret_2647, vctxt_2645)
and func_4(func)
and func_6(vdoc_2645, vattr_2646, vret_2647, vctxt_2645)
and vdoc_2645.getType().hasName("xmlDocPtr")
and vvalue_2645.getType().hasName("const xmlChar *")
and vattr_2646.getType().hasName("xmlAttrPtr")
and vret_2647.getType().hasName("xmlIDPtr")
and vctxt_2645.getType().hasName("xmlValidCtxtPtr")
and vdoc_2645.getParentScope+() = func
and vvalue_2645.getParentScope+() = func
and vattr_2646.getParentScope+() = func
and vret_2647.getParentScope+() = func
and vctxt_2645.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
