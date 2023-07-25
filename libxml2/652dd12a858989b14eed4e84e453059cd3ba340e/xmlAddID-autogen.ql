/**
 * @name libxml2-652dd12a858989b14eed4e84e453059cd3ba340e-xmlAddID
 * @id cpp/libxml2/652dd12a858989b14eed4e84e453059cd3ba340e/xmlAddID
 * @description libxml2-652dd12a858989b14eed4e84e453059cd3ba340e-valid.c-xmlAddID CVE-2022-23308
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vvalue_2645, EqualityOperation target_2) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalue_2645
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset() instanceof Literal
		and target_0.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ReturnStmt
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctxt_2645, BlockStmt target_7, ExprStmt target_8) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("xmlIsStreaming")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vctxt_2645
		and target_1.getParent().(IfStmt).getThen()=target_7
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vvalue_2645, EqualityOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=vvalue_2645
		and target_2.getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ReturnStmt
}

predicate func_4(Parameter vctxt_2645, VariableAccess target_4) {
		target_4.getTarget()=vctxt_2645
}

predicate func_6(Parameter vctxt_2645, BlockStmt target_7, LogicalAndExpr target_6) {
		target_6.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vctxt_2645
		and target_6.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="vstateNr"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_2645
		and target_6.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_6.getParent().(IfStmt).getThen()=target_7
}

predicate func_7(BlockStmt target_7) {
		target_7.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="dict"
		and target_7.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlDocPtr")
		and target_7.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_7.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="name"
		and target_7.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlIDPtr")
		and target_7.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlDictLookup")
		and target_7.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="dict"
		and target_7.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlDocPtr")
		and target_7.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_7.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlAttrPtr")
		and target_7.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(UnaryMinusExpr).getValue()="-1"
		and target_7.getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="name"
		and target_7.getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlIDPtr")
		and target_7.getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStrdup")
		and target_7.getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_7.getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlAttrPtr")
}

predicate func_8(Parameter vctxt_2645, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("xmlVErrMemory")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_2645
		and target_8.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="malloc failed"
}

from Function func, Parameter vvalue_2645, Parameter vctxt_2645, EqualityOperation target_2, VariableAccess target_4, LogicalAndExpr target_6, BlockStmt target_7, ExprStmt target_8
where
not func_0(vvalue_2645, target_2)
and not func_1(vctxt_2645, target_7, target_8)
and func_2(vvalue_2645, target_2)
and func_4(vctxt_2645, target_4)
and func_6(vctxt_2645, target_7, target_6)
and func_7(target_7)
and func_8(vctxt_2645, target_8)
and vvalue_2645.getType().hasName("const xmlChar *")
and vctxt_2645.getType().hasName("xmlValidCtxtPtr")
and vvalue_2645.getFunction() = func
and vctxt_2645.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
