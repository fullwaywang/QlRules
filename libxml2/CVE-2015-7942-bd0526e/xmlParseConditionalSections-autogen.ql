/**
 * @name libxml2-bd0526e66a56e75a18da8c15c4750db8f801c52d-xmlParseConditionalSections
 * @id cpp/libxml2/bd0526e66a56e75a18da8c15c4750db8f801c52d/xmlParseConditionalSections
 * @description libxml2-bd0526e66a56e75a18da8c15c4750db8f801c52d-parser.c-xmlParseConditionalSections CVE-2015-7942
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_6774, EqualityOperation target_2, ExprStmt target_3, ExprStmt target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="instate"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6774
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6774
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="3"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="end"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6774
		and target_0.getThen() instanceof DoStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctxt_6774, EqualityOperation target_2, DoStmt target_1) {
		target_1.getCondition().(Literal).getValue()="0"
		and target_1.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nbChars"
		and target_1.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(AssignAddExpr).getRValue().(Literal).getValue()="3"
		and target_1.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="cur"
		and target_1.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="3"
		and target_1.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="col"
		and target_1.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_1.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignAddExpr).getRValue().(Literal).getValue()="3"
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="37"
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlParserHandlePEReference")
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_6774
		and target_1.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_1.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("xmlParserInputGrow")
		and target_1.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="input"
		and target_1.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(Literal).getValue()="250"
		and target_1.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlPopInput")
		and target_1.getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_6774
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Parameter vctxt_6774, EqualityOperation target_2) {
		target_2.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_2.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_2.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6774
		and target_2.getAnOperand().(Literal).getValue()="0"
}

predicate func_3(Parameter vctxt_6774, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("xmlValidityError")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_6774
		and target_3.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="All markup of the conditional section is not in the same entity\n"
		and target_3.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_3.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
}

predicate func_4(Parameter vctxt_6774, ExprStmt target_4) {
		target_4.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nbChars"
		and target_4.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6774
		and target_4.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(AssignAddExpr).getRValue().(Literal).getValue()="3"
		and target_4.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="cur"
		and target_4.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_4.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6774
		and target_4.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="3"
		and target_4.getExpr().(CommaExpr).getRightOperand().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="col"
		and target_4.getExpr().(CommaExpr).getRightOperand().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_4.getExpr().(CommaExpr).getRightOperand().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6774
		and target_4.getExpr().(CommaExpr).getRightOperand().(AssignAddExpr).getRValue().(Literal).getValue()="3"
}

from Function func, Parameter vctxt_6774, DoStmt target_1, EqualityOperation target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vctxt_6774, target_2, target_3, target_4)
and func_1(vctxt_6774, target_2, target_1)
and func_2(vctxt_6774, target_2)
and func_3(vctxt_6774, target_3)
and func_4(vctxt_6774, target_4)
and vctxt_6774.getType().hasName("xmlParserCtxtPtr")
and vctxt_6774.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
