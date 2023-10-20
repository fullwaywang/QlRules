/**
 * @name libxml2-41ac9049a27f52e7a1f3b341f8714149fc88d450-xmlParseConditionalSections
 * @id cpp/libxml2/41ac9049a27f52e7a1f3b341f8714149fc88d450/xmlParseConditionalSections
 * @description libxml2-41ac9049a27f52e7a1f3b341f8714149fc88d450-parser.c-xmlParseConditionalSections CVE-2015-7942
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_6774, DoStmt target_4, LogicalAndExpr target_5, ExprStmt target_6) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GEExpr or target_0 instanceof LEExpr)
		and target_0.getLesserOperand() instanceof PointerArithmeticOperation
		and target_0.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="end"
		and target_0.getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_0.getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6774
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="instate"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6774
		and target_0.getParent().(LogicalAndExpr).getAnOperand() instanceof RelationalOperation
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_4
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctxt_6774, PointerArithmeticOperation target_1) {
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6774
		and target_1.getAnOperand().(Literal).getValue()="3"
}

predicate func_2(Parameter vctxt_6774, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="end"
		and target_2.getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6774
}

predicate func_3(Parameter vctxt_6774, DoStmt target_4, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand() instanceof PointerArithmeticOperation
		and target_3.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="end"
		and target_3.getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_3.getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6774
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="instate"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6774
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_4
}

predicate func_4(DoStmt target_4) {
		target_4.getCondition().(Literal).getValue()="0"
		and target_4.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nbChars"
		and target_4.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(AssignAddExpr).getRValue().(Literal).getValue()="3"
		and target_4.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="cur"
		and target_4.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="3"
		and target_4.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="col"
		and target_4.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_4.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignAddExpr).getRValue().(Literal).getValue()="3"
}

predicate func_5(Parameter vctxt_6774, LogicalAndExpr target_5) {
		target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="instate"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6774
		and target_5.getAnOperand() instanceof RelationalOperation
}

predicate func_6(Parameter vctxt_6774, ExprStmt target_6) {
		target_6.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nbChars"
		and target_6.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6774
		and target_6.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(AssignAddExpr).getRValue().(Literal).getValue()="3"
		and target_6.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="cur"
		and target_6.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_6.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6774
		and target_6.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="3"
		and target_6.getExpr().(CommaExpr).getRightOperand().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="col"
		and target_6.getExpr().(CommaExpr).getRightOperand().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_6.getExpr().(CommaExpr).getRightOperand().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6774
		and target_6.getExpr().(CommaExpr).getRightOperand().(AssignAddExpr).getRValue().(Literal).getValue()="3"
}

from Function func, Parameter vctxt_6774, PointerArithmeticOperation target_1, PointerFieldAccess target_2, RelationalOperation target_3, DoStmt target_4, LogicalAndExpr target_5, ExprStmt target_6
where
not func_0(vctxt_6774, target_4, target_5, target_6)
and func_1(vctxt_6774, target_1)
and func_2(vctxt_6774, target_2)
and func_3(vctxt_6774, target_4, target_3)
and func_4(target_4)
and func_5(vctxt_6774, target_5)
and func_6(vctxt_6774, target_6)
and vctxt_6774.getType().hasName("xmlParserCtxtPtr")
and vctxt_6774.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
