/**
 * @name libxml2-4629ee02ac649c27f9c0cf98ba017c6b5526070f-xmlParseReference
 * @id cpp/libxml2/4629ee02ac649c27f9c0cf98ba017c6b5526070f/xmlParseReference
 * @description libxml2-4629ee02ac649c27f9c0cf98ba017c6b5526070f-parser.c-xmlParseReference CVE-2013-0339
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vent_6848, Parameter vctxt_6847, BlockStmt target_2, ExprStmt target_3, EqualityOperation target_1, ExprStmt target_4) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="etype"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_6848
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6847
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getValue()="18"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vent_6848, BlockStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="checked"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_6848
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Parameter vctxt_6847, BlockStmt target_2) {
		target_2.getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="userData"
		and target_2.getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6847
		and target_2.getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vctxt_6847
		and target_2.getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("void *")
		and target_2.getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getStmt(2).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("void *")
		and target_2.getStmt(2).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="userData"
		and target_2.getStmt(2).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6847
}

predicate func_3(Variable vent_6848, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("xmlChar *")
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="content"
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_6848
}

predicate func_4(Parameter vctxt_6847, ExprStmt target_4) {
		target_4.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="characters"
		and target_4.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sax"
		and target_4.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6847
		and target_4.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="userData"
		and target_4.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6847
		and target_4.getExpr().(VariableCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("xmlChar *")
		and target_4.getExpr().(VariableCall).getArgument(2).(FunctionCall).getTarget().hasName("xmlStrlen")
		and target_4.getExpr().(VariableCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("xmlChar *")
}

from Function func, Variable vent_6848, Parameter vctxt_6847, EqualityOperation target_1, BlockStmt target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vent_6848, vctxt_6847, target_2, target_3, target_1, target_4)
and func_1(vent_6848, target_2, target_1)
and func_2(vctxt_6847, target_2)
and func_3(vent_6848, target_3)
and func_4(vctxt_6847, target_4)
and vent_6848.getType().hasName("xmlEntityPtr")
and vctxt_6847.getType().hasName("xmlParserCtxtPtr")
and vent_6848.(LocalVariable).getFunction() = func
and vctxt_6847.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
